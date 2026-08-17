//! Loopback HTTP/1.1 transport and reference server for ADR 0015.
//!
//! The reference service refuses non-loopback bind addresses. TLS 1.2+ via
//! rustls is the supported mode; plaintext is only available when the caller
//! explicitly allows it for tests. This is still not a remote WORM or
//! hardware monotonic sink.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    crypto::sha256,
    vault::{
        VaultError,
        anchor_protocol::{
            AnchorMethod, AnchorTransport, TransportFailure, TransportResponse,
            encode_cas_decision, encode_error_body, encode_get_body, parse_path_vault,
        },
        anchor_store::{
            AnchorAccessRecord, FileBackedAnchorStore, issue_anchor_token_file, load_anchor_token,
            split_host_port, token_digest, validate_loopback_listen,
        },
    },
};

const DEFAULT_LISTEN: &str = "127.0.0.1:7432";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Reference loopback CAS server.
pub(crate) struct AnchorHttpServer {
    listener: TcpListener,
    store: FileBackedAnchorStore,
    token_hash: [u8; 32],
    tls: Option<Arc<ServerConfig>>,
}

impl AnchorHttpServer {
    /// Bind a plaintext loopback listener. Tests and `--allow-plaintext` only.
    pub(crate) fn bind(
        data_dir: &Path,
        listen: &str,
        token_file: Option<&Path>,
    ) -> Result<BoundAnchorServer, VaultError> {
        Self::bind_internal(data_dir, listen, token_file, None)
    }

    /// Bind a loopback listener that requires rustls on every connection.
    pub(crate) fn bind_tls(
        data_dir: &Path,
        listen: &str,
        token_file: Option<&Path>,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<BoundAnchorServer, VaultError> {
        Self::bind_internal(
            data_dir,
            listen,
            token_file,
            Some(super::anchor_tls::server_config(cert_path, key_path)?),
        )
    }

    fn bind_internal(
        data_dir: &Path,
        listen: &str,
        token_file: Option<&Path>,
        tls: Option<Arc<ServerConfig>>,
    ) -> Result<BoundAnchorServer, VaultError> {
        let addr = parse_listen(listen)?;
        let listener = TcpListener::bind(addr).map_err(VaultError::from)?;
        listener.set_nonblocking(false).map_err(VaultError::from)?;
        let store = FileBackedAnchorStore::open(data_dir)?;
        let token_path = token_file.map_or_else(|| data_dir.join("token.json"), Path::to_path_buf);
        if !token_path.exists() {
            issue_anchor_token_file(&token_path)?;
        }
        let token = load_anchor_token(&token_path)?;
        let token_hash = token_digest(&token)?;
        Ok(BoundAnchorServer {
            server: Self {
                listener,
                store,
                token_hash,
                tls,
            },
            token_path,
        })
    }

    /// Bound socket address, including the ephemeral port when listen was `:0`.
    pub(crate) fn local_addr(&self) -> Result<SocketAddr, VaultError> {
        self.listener.local_addr().map_err(VaultError::from)
    }

    /// Serve requests until the process is terminated.
    pub(crate) fn serve_forever(&mut self) -> Result<(), VaultError> {
        loop {
            self.serve_one()?;
        }
    }

    /// Accept and handle a single connection. Used by tests.
    pub(crate) fn serve_one(&mut self) -> Result<(), VaultError> {
        let (stream, _) = self.listener.accept().map_err(VaultError::from)?;
        let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
        let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
        match &self.tls {
            Some(config) => {
                let Ok(connection) = ServerConnection::new(Arc::clone(config)) else {
                    return Ok(());
                };
                let mut tls = StreamOwned::new(connection, stream);
                handle_connection(&mut tls, &self.store, &self.token_hash);
            }
            None => handle_connection(stream, &self.store, &self.token_hash),
        }
        Ok(())
    }

    /// Whether this listener requires rustls.
    #[must_use]
    pub(crate) fn tls_enabled(&self) -> bool {
        self.tls.is_some()
    }
}

/// Newly bound server plus the token file it is using.
pub(crate) struct BoundAnchorServer {
    /// Listening server.
    pub(crate) server: AnchorHttpServer,
    /// Token file path. Never contains the token bytes.
    pub(crate) token_path: PathBuf,
}

/// Loopback HTTP client that implements [`AnchorTransport`].
pub(crate) struct HttpAnchorTransport {
    addr: SocketAddr,
    host: String,
    token: Zeroizing<String>,
    timeout: Duration,
    tls: Option<Arc<ClientConfig>>,
}

impl HttpAnchorTransport {
    /// Connect to a loopback endpoint with an optional rustls trust anchor.
    pub(crate) fn new(
        endpoint: &str,
        token: Zeroizing<String>,
        tls_ca: Option<&Path>,
    ) -> Result<Self, VaultError> {
        let (https, host, port) = super::anchor_store::split_loopback_endpoint(endpoint)?;
        if https {
            let Some(ca) = tls_ca else {
                return Err(VaultError::InvalidFormat);
            };
            if !ca.is_file() {
                return Err(VaultError::NotFound);
            }
        } else if tls_ca.is_some() {
            return Err(VaultError::InvalidFormat);
        }
        let addr: SocketAddr = match host {
            "127.0.0.1" | "localhost" => SocketAddr::from(([127, 0, 0, 1], port)),
            "[::1]" => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
            _ => return Err(VaultError::InvalidFormat),
        };
        let tls = match tls_ca {
            Some(path) => Some(super::anchor_tls::client_config(path)?),
            None => None,
        };
        Ok(Self {
            addr,
            host: format!("{host}:{port}"),
            token,
            timeout: REQUEST_TIMEOUT,
            tls,
        })
    }
}

impl AnchorTransport for HttpAnchorTransport {
    fn call(
        &mut self,
        method: AnchorMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<TransportResponse, TransportFailure> {
        let stream = TcpStream::connect_timeout(&self.addr, self.timeout)
            .map_err(|_| TransportFailure::ConnectionFailed)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|_| TransportFailure::ConnectionFailed)?;
        if let Some(config) = &self.tls {
            let name = super::anchor_tls::loopback_server_name()
                .map_err(|_| TransportFailure::ConnectionFailed)?;
            let connection = ClientConnection::new(Arc::clone(config), name)
                .map_err(|_| TransportFailure::ConnectionFailed)?;
            let mut tls = StreamOwned::new(connection, stream);
            exchange(&mut tls, method, path, &self.host, &self.token, body)
        } else {
            let mut stream = stream;
            exchange(&mut stream, method, path, &self.host, &self.token, body)
        }
    }
}

fn exchange<S: Read + Write>(
    stream: &mut S,
    method: AnchorMethod,
    path: &str,
    host: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<TransportResponse, TransportFailure> {
    write_request(stream, method, path, host, token, body)
        .map_err(|_| TransportFailure::ConnectionFailed)?;
    read_response(stream).map_err(|error| match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TransportFailure::Timeout,
        _ => TransportFailure::ConnectionFailed,
    })
}

/// Default listen address for the reference server.
#[must_use]
pub(crate) fn default_listen_addr() -> &'static str {
    DEFAULT_LISTEN
}

fn parse_listen(listen: &str) -> Result<SocketAddr, VaultError> {
    let endpoint = if listen.starts_with("http://") {
        listen.to_owned()
    } else {
        format!("http://{listen}")
    };
    validate_loopback_listen(&endpoint)?;
    let rest = endpoint
        .strip_prefix("http://")
        .ok_or(VaultError::InvalidFormat)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = split_host_port(rest)?;
    match host {
        "127.0.0.1" | "localhost" => Ok(SocketAddr::from(([127, 0, 0, 1], port))),
        "[::1]" => Ok(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port))),
        _ => Err(VaultError::InvalidFormat),
    }
}

fn handle_connection<S: Read + Write>(
    mut stream: S,
    store: &FileBackedAnchorStore,
    token_hash: &[u8; 32],
) {
    let Ok(request) = read_request(&mut stream) else {
        write_http(&mut stream, 400, &encode_error_body("invalid_anchor"));
        return;
    };
    let method = match request.method {
        AnchorMethod::Get => "GET",
        AnchorMethod::Post => "POST",
    };
    let parsed_vault = parse_path_vault(request.method, &request.path).ok();
    if !authorized(request.authorization.as_ref(), token_hash) {
        respond(
            &mut stream,
            store,
            record(method, parsed_vault, "unauthorized", None),
            401,
            &encode_error_body("unauthorized"),
        );
        return;
    }
    let Some(vault_id) = parsed_vault else {
        respond(
            &mut stream,
            store,
            record(method, None, "invalid", None),
            422,
            &encode_error_body("invalid_anchor"),
        );
        return;
    };
    match store.authorize(token_hash, vault_id) {
        Ok(true) => {}
        Ok(false) => {
            respond(
                &mut stream,
                store,
                record(method, Some(vault_id), "unauthorized", None),
                401,
                &encode_error_body("unauthorized"),
            );
            return;
        }
        Err(_) => {
            respond(
                &mut stream,
                store,
                record(method, Some(vault_id), "unavailable", None),
                503,
                &encode_error_body("unavailable"),
            );
            return;
        }
    }
    let (status, body, result, generation) = match request.method {
        AnchorMethod::Get => match store.load(vault_id) {
            Ok(Some(bytes)) => (
                200,
                encode_get_body(&bytes),
                "get_ok",
                parse_generation(&bytes),
            ),
            Ok(None) => (404, encode_error_body("not_found"), "not_found", None),
            Err(_) => (503, encode_error_body("unavailable"), "unavailable", None),
        },
        AnchorMethod::Post => {
            let Some(body) = request.body.as_deref() else {
                respond(
                    &mut stream,
                    store,
                    record(method, Some(vault_id), "invalid", None),
                    422,
                    &encode_error_body("invalid_anchor"),
                );
                return;
            };
            match decode_cas_request(body) {
                None => (422, encode_error_body("invalid_anchor"), "invalid", None),
                Some((request_id, expected, anchor)) => {
                    match store.compare_and_set(vault_id, &request_id, expected, &anchor) {
                        Ok(decision) => {
                            let (status, body) = encode_cas_decision(&decision);
                            let (result, generation) = decision_result(&decision);
                            (status, body, result, generation)
                        }
                        Err(_) => (503, encode_error_body("unavailable"), "unavailable", None),
                    }
                }
            }
        }
    };
    respond(
        &mut stream,
        store,
        record(method, Some(vault_id), result, generation),
        status,
        &body,
    );
}

fn respond<S: Write>(
    stream: &mut S,
    store: &FileBackedAnchorStore,
    access: AnchorAccessRecord,
    status: u16,
    body: &[u8],
) {
    if store.record_access(&access).is_err() {
        write_http(stream, 503, &encode_error_body("unavailable"));
        return;
    }
    write_http(stream, status, body);
}

fn record(
    method: &'static str,
    vault_id: Option<[u8; 16]>,
    result: &'static str,
    generation: Option<u64>,
) -> AnchorAccessRecord {
    AnchorAccessRecord {
        method,
        vault_id,
        result,
        generation,
    }
}

fn parse_generation(bytes: &[u8]) -> Option<u64> {
    crate::vault::audit_v2::parse_anchor(bytes)
        .ok()
        .map(|anchor| anchor.anchor_generation())
}

fn decision_result(
    decision: &crate::vault::anchor_cas::CasDecision,
) -> (&'static str, Option<u64>) {
    match decision {
        crate::vault::anchor_cas::CasDecision::Applied(bytes) => {
            ("applied", parse_generation(bytes))
        }
        crate::vault::anchor_cas::CasDecision::AlreadyApplied(bytes) => {
            ("already_applied", parse_generation(bytes))
        }
        crate::vault::anchor_cas::CasDecision::Conflict { generation, .. } => {
            ("conflict", Some(*generation))
        }
        crate::vault::anchor_cas::CasDecision::Invalid => ("invalid", None),
    }
}

struct ParsedRequest {
    method: AnchorMethod,
    path: String,
    authorization: Option<String>,
    body: Option<Vec<u8>>,
}

fn read_request<S: Read>(stream: &mut S) -> Result<ParsedRequest, std::io::Error> {
    let header_bytes = read_until_headers(stream)?;
    let header_text = std::str::from_utf8(&header_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "headers"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "request"))?;
    let mut parts = request_line.split(' ');
    let method = match parts.next() {
        Some("GET") => AnchorMethod::Get,
        Some("POST") => AnchorMethod::Post,
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "method",
            ));
        }
    };
    let path = parts
        .next()
        .filter(|value| value.starts_with('/'))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "path"))?
        .to_owned();
    if parts.next() != Some("HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "version",
        ));
    }
    let mut authorization = None;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "header"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("Authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "length"))?,
            );
        } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
            transfer_encoding = true;
        }
    }
    if transfer_encoding {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer-encoding",
        ));
    }
    let body = match (method, content_length) {
        (AnchorMethod::Get, _) => None,
        (AnchorMethod::Post, Some(length)) if length <= MAX_BODY_BYTES => {
            let mut body = vec![0_u8; length];
            stream.read_exact(&mut body)?;
            Some(body)
        }
        (AnchorMethod::Post, _) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "body"));
        }
    };
    Ok(ParsedRequest {
        method,
        path,
        authorization,
        body,
    })
}

fn read_until_headers<S: Read>(stream: &mut S) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while bytes.len() < MAX_HEADER_BYTES {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "headers too large",
    ))
}

fn authorized(header: Option<&String>, token_hash: &[u8; 32]) -> bool {
    let Some(header) = header.map(String::as_str) else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    let Ok(token) = STANDARD.decode(presented.as_bytes()) else {
        return false;
    };
    bool::from(sha256(&token).as_slice().ct_eq(token_hash.as_slice()))
}

fn decode_cas_request(body: &[u8]) -> Option<(Vec<u8>, u64, Vec<u8>)> {
    let request: CasRequest = serde_json::from_slice(body).ok()?;
    let request_id = STANDARD.decode(request.request_id).ok()?;
    let anchor = STANDARD.decode(request.anchor).ok()?;
    Some((request_id, request.expected_generation, anchor))
}

fn write_request<S: Write>(
    stream: &mut S,
    method: AnchorMethod,
    path: &str,
    host: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<(), std::io::Error> {
    let method = match method {
        AnchorMethod::Get => "GET",
        AnchorMethod::Post => "POST",
    };
    match body {
        Some(body) => write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?,
        None => write!(
            stream,
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        )?,
    }
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn read_response<S: Read>(stream: &mut S) -> Result<TransportResponse, std::io::Error> {
    let header_bytes = read_until_headers(stream)?;
    let header_text = std::str::from_utf8(&header_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "headers"))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "status"))?;
    let mut parts = status_line.split(' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "version",
        ));
    }
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "status"))?;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "length"))?,
            );
        }
    }
    let length = content_length
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "content-length"))?;
    if length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "body too large",
        ));
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    Ok(TransportResponse { status, body })
}

fn write_http<S: Write>(stream: &mut S, status: u16, body: &[u8]) {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Bad Request",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream
        .write_all(header.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
}

#[derive(Debug, serde::Deserialize)]
struct CasRequest {
    request_id: String,
    expected_generation: u64,
    anchor: String,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{AnchorHttpServer, HttpAnchorTransport};
    use crate::crypto::sha256;
    use crate::vault::{
        VaultError,
        anchor_protocol::ProtocolAnchorClient,
        anchor_store::load_anchor_token,
        audit_anchor::{AnchorCasResult, AnchorSink},
        audit_v2::{AuditAnchorV2, serialize_anchor},
    };

    const VAULT: [u8; 16] = [0x33; 16];

    fn anchor(generation: u64, previous: [u8; 32]) -> Result<Vec<u8>, VaultError> {
        serialize_anchor(&AuditAnchorV2::new(
            VAULT, generation, generation, generation, [0xab; 16], previous, 0,
        )?)
    }

    #[test]
    fn loopback_http_cas_round_trip_and_rejects_bad_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let bound = AnchorHttpServer::bind(root.path(), "127.0.0.1:0", None)?;
        let addr = bound.server.local_addr()?;
        let token_path = bound.token_path.clone();
        let mut server = bound.server;
        let _worker = std::thread::spawn(move || {
            let _ = server.serve_forever();
        });
        let token = load_anchor_token(&token_path)?;
        let transport = HttpAnchorTransport::new(&format!("http://{addr}"), token.clone(), None)?;
        let mut client = ProtocolAnchorClient::new(VAULT, transport, |_| Duration::ZERO);
        let first = anchor(1, [0_u8; 32])?;
        assert_eq!(client.compare_and_set(0, &first)?, AnchorCasResult::Applied);
        assert_eq!(
            client.compare_and_set(0, &first)?,
            AnchorCasResult::AlreadyApplied
        );
        let second = anchor(2, sha256(&first))?;
        assert_eq!(
            client.compare_and_set(1, &second)?,
            AnchorCasResult::Applied
        );
        let loaded = client.load()?.ok_or("missing anchor")?;
        assert_eq!(loaded, second);

        let bad = HttpAnchorTransport::new(
            &format!("http://{addr}"),
            zeroize::Zeroizing::new(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0x00; 32],
            )),
            None,
        )?;
        let mut denied = ProtocolAnchorClient::new(VAULT, bad, |_| Duration::ZERO);
        let error = denied.load().err().ok_or("expected auth failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        let log = String::from_utf8(
            crate::vault::anchor_store::FileBackedAnchorStore::open(root.path())?
                .access_log_bytes()?,
        )?;
        assert!(log.contains("applied"));
        assert!(log.contains("already_applied"));
        assert!(log.contains("unauthorized"));
        assert!(!log.contains(token.as_str()));
        Ok(())
    }

    #[test]
    fn token_bound_to_one_vault_cannot_read_another() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let bound = AnchorHttpServer::bind(root.path(), "127.0.0.1:0", None)?;
        let addr = bound.server.local_addr()?;
        let token_path = bound.token_path.clone();
        let mut server = bound.server;
        let _worker = std::thread::spawn(move || {
            let _ = server.serve_forever();
        });
        let token = load_anchor_token(&token_path)?;
        let mut owner = ProtocolAnchorClient::new(
            VAULT,
            HttpAnchorTransport::new(&format!("http://{addr}"), token.clone(), None)?,
            |_| Duration::ZERO,
        );
        let first = anchor(1, [0_u8; 32])?;
        assert_eq!(owner.compare_and_set(0, &first)?, AnchorCasResult::Applied);
        let mut other = ProtocolAnchorClient::new(
            [0x44; 16],
            HttpAnchorTransport::new(&format!("http://{addr}"), token, None)?,
            |_| Duration::ZERO,
        );
        let error = other.load().err().ok_or("expected cross-vault deny")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn server_rollback_writes_value_free_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let vault = root.path().join("test.vault");
        let bound = AnchorHttpServer::bind(root.path(), "127.0.0.1:0", None)?;
        let addr = bound.server.local_addr()?;
        let token_path = bound.token_path.clone();
        let mut server = bound.server;
        let _worker = std::thread::spawn(move || {
            let _ = server.serve_forever();
        });
        let token = load_anchor_token(&token_path)?;
        let confirmed = crate::vault::anchor_store::ConfirmedAnchorFile::for_vault(&vault, VAULT);
        let mut client = ProtocolAnchorClient::new(
            VAULT,
            HttpAnchorTransport::new(&format!("http://{addr}"), token, None)?,
            |_| Duration::ZERO,
        );
        client.set_persistence(Box::new(confirmed));
        let first = anchor(1, [0_u8; 32])?;
        assert_eq!(client.compare_and_set(0, &first)?, AnchorCasResult::Applied);
        let vaults = root.path().join("vaults");
        for entry in std::fs::read_dir(&vaults)? {
            let path = entry?.path().join("state.json");
            if path.exists() {
                let mut last_error = None;
                for _ in 0..10 {
                    match std::fs::remove_file(&path) {
                        Ok(()) => {
                            last_error = None;
                            break;
                        }
                        Err(error) => last_error = Some(error),
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if let Some(error) = last_error {
                    return Err(error.into());
                }
            }
        }
        let error = client.load().err().ok_or("expected rollback")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        let status = crate::vault::load_anchor_status(&vault, Some(VAULT))?;
        assert!(status.rollback_evidence);
        assert_eq!(status.rollback_expected_generation, Some(1));
        assert_eq!(status.last_confirmed_generation, Some(1));
        Ok(())
    }

    #[test]
    fn https_loopback_cas_requires_matching_trust_anchor() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempfile::tempdir()?;
        let cert = root.path().join("cert.pem");
        let key = root.path().join("key.pem");
        crate::vault::anchor_tls::write_loopback_self_signed(&cert, &key)?;
        let bound = AnchorHttpServer::bind_tls(root.path(), "127.0.0.1:0", None, &cert, &key)?;
        let addr = bound.server.local_addr()?;
        let token_path = bound.token_path.clone();
        assert!(bound.server.tls_enabled());
        let mut server = bound.server;
        let _worker = std::thread::spawn(move || {
            let _ = server.serve_forever();
        });
        let token = load_anchor_token(&token_path)?;
        assert!(HttpAnchorTransport::new(&format!("https://{addr}"), token.clone(), None).is_err());
        let mut client = ProtocolAnchorClient::new(
            VAULT,
            HttpAnchorTransport::new(&format!("https://{addr}"), token, Some(&cert))?,
            |_| Duration::ZERO,
        );
        let first = anchor(1, [0_u8; 32])?;
        assert_eq!(client.compare_and_set(0, &first)?, AnchorCasResult::Applied);
        assert_eq!(client.load()?.as_deref(), Some(first.as_slice()));
        Ok(())
    }

    #[test]
    fn bind_rejects_non_loopback_listen_address() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        assert!(AnchorHttpServer::bind(root.path(), "192.168.1.9:7432", None).is_err());
        assert!(
            HttpAnchorTransport::new(
                "http://8.8.8.8:80",
                zeroize::Zeroizing::new("dGVzdA==".to_owned()),
                None,
            )
            .is_err()
        );
        Ok(())
    }
}
