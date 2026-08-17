//! Durable, Vault-independent storage for the ADR 0015 reference CAS.
//!
//! The store directory is chosen by the operator and can live on a different
//! volume than the Vault file. It is still a local filesystem and is not a
//! remote WORM service or hardware monotonic counter.

use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use atomic_write_file::AtomicWriteFile;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{generate_array, sha256},
    secure_fs,
    vault::{
        VaultError,
        anchor_cas::{CasDecision, CasEngine, REQUEST_ID_LENGTH},
        audit_v2::{parse_anchor, serialize_anchor},
    },
};

const TOKEN_FORMAT: &str = "envvault-audit-anchor-token";
const TOKEN_VERSION: u32 = 1;
const TOKEN_LENGTH: usize = 32;
const CLIENT_FORMAT: &str = "envvault-audit-anchor-client";
const CLIENT_VERSION: u32 = 1;
const CONFIRMED_FORMAT: &str = "envvault-audit-anchor-confirmed";
const CONFIRMED_VERSION: u32 = 1;
const STORE_FORMAT: &str = "envvault-audit-anchor-store";
const STORE_VERSION: u32 = 1;
const BINDING_FORMAT: &str = "envvault-audit-anchor-binding";
const BINDING_VERSION: u32 = 1;
const ACCESS_FORMAT: &str = "envvault-audit-anchor-access";
const ACCESS_VERSION: u32 = 1;
const ROLLBACK_FORMAT: &str = "envvault-audit-anchor-rollback";
const ROLLBACK_VERSION: u32 = 1;
const MAX_SIDECAR_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 4 * 1024;
const MAX_ACCESS_LOG_BYTES: usize = 8 * 1024 * 1024;

/// Operator-facing client configuration written next to a Vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorClientConfig {
    /// Always `mandatory` in this implementation.
    pub(crate) mode: AnchorClientMode,
    /// Loopback HTTP endpoint, for example `http://127.0.0.1:7432`.
    pub(crate) endpoint: String,
    /// Private token file used as the Bearer secret.
    pub(crate) token_file: PathBuf,
    /// PEM trust anchor for `https://` endpoints.
    pub(crate) tls_ca: Option<PathBuf>,
    /// Set only when the endpoint is explicit loopback plaintext.
    pub(crate) allow_plaintext: bool,
}

/// Client operating mode. Only mandatory remote CAS is configurable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorClientMode {
    /// Fail closed when the remote CAS cannot be confirmed.
    Mandatory,
}

/// Value-free status for `audit anchor-status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorClientStatus {
    /// Whether a client sidecar exists.
    pub(crate) configured: bool,
    /// Configured mode, when present.
    pub(crate) mode: Option<AnchorClientMode>,
    /// Configured endpoint, when present.
    pub(crate) endpoint: Option<String>,
    /// Token file path, when present.
    pub(crate) token_file: Option<PathBuf>,
    /// PEM trust anchor path, when present.
    pub(crate) tls_ca: Option<PathBuf>,
    /// Whether the configured endpoint is explicit plaintext.
    pub(crate) allow_plaintext: bool,
    /// Last locally confirmed generation, when present.
    pub(crate) last_confirmed_generation: Option<u64>,
    /// SHA-256 of the last locally confirmed canonical bytes.
    pub(crate) last_confirmed_digest: Option<[u8; 32]>,
    /// Whether a rollback-evidence sidecar exists.
    pub(crate) rollback_evidence: bool,
    /// Expected generation recorded when rollback was detected.
    pub(crate) rollback_expected_generation: Option<u64>,
    /// Observed generation recorded when rollback was detected.
    pub(crate) rollback_observed_generation: Option<u64>,
}

/// File-backed CAS directory used by the reference HTTP server.
#[derive(Debug, Clone)]
pub(crate) struct FileBackedAnchorStore {
    root: PathBuf,
}

impl FileBackedAnchorStore {
    /// Open or create a private store directory.
    pub(crate) fn open(root: &Path) -> Result<Self, VaultError> {
        ensure_private_dir(root)?;
        let vaults = root.join("vaults");
        ensure_private_dir(&vaults)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Store root chosen by the operator.
    #[must_use]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Evaluate GET for one Vault id.
    pub(crate) fn load(&self, vault_id: [u8; 16]) -> Result<Option<Vec<u8>>, VaultError> {
        let engine = self.load_engine(vault_id)?;
        Ok(engine.current_bytes().map(Vec::from))
    }

    /// Evaluate compare-and-set for one Vault id.
    pub(crate) fn compare_and_set(
        &self,
        vault_id: [u8; 16],
        request_id: &[u8],
        expected_generation: u64,
        anchor_bytes: &[u8],
    ) -> Result<CasDecision, VaultError> {
        let paths = VaultStorePaths::for_root(&self.root, vault_id);
        ensure_private_dir(&paths.dir)?;
        let lock = secure_fs::open_lock(&paths.lock).map_err(map_secure_io)?;
        lock.lock()?;
        let mut engine = read_engine(&paths.state)?;
        let decision =
            engine.compare_and_set(vault_id, request_id, expected_generation, anchor_bytes);
        write_engine(&paths.state, &engine)?;
        Ok(decision)
    }

    /// Bind the issued token to `vault_id` on first use; reject any other Vault.
    pub(crate) fn authorize(
        &self,
        token_hash: &[u8; 32],
        vault_id: [u8; 16],
    ) -> Result<bool, VaultError> {
        let path = self.root.join("bindings.json");
        let mut lock_path = OsString::from(path.as_os_str());
        lock_path.push(".lock");
        let lock = secure_fs::open_lock(Path::new(&lock_path)).map_err(map_secure_io)?;
        lock.lock()?;
        match read_binding(&path)? {
            None => {
                write_json(
                    &path,
                    &BindingDocument {
                        format: BINDING_FORMAT.to_owned(),
                        version: BINDING_VERSION,
                        token_digest: hex_encode(token_hash),
                        vault_id: hex_encode(&vault_id),
                    },
                )?;
                Ok(true)
            }
            Some((bound_hash, bound_vault)) => {
                use subtle::ConstantTimeEq as _;
                let hash_ok = bool::from(bound_hash.as_slice().ct_eq(token_hash.as_slice()));
                let vault_ok = bool::from(bound_vault.as_slice().ct_eq(vault_id.as_slice()));
                Ok(hash_ok && vault_ok)
            }
        }
    }

    /// Append one value-free access record. Never includes a token.
    pub(crate) fn record_access(&self, record: &AnchorAccessRecord) -> Result<(), VaultError> {
        let path = self.root.join("access.jsonl");
        rotate_access_log_if_needed(&path)?;
        let document = AccessDocument {
            format: ACCESS_FORMAT,
            version: ACCESS_VERSION,
            unix_time_millis: current_unix_time_millis(),
            method: record.method,
            vault_id: record.vault_id.map(|id| hex_encode(&id)),
            result: record.result,
            generation: record.generation,
        };
        let mut line = serde_json::to_vec(&document).map_err(|_| VaultError::InvalidFormat)?;
        line.push(b'\n');
        append_private(&path, &line)
    }

    /// Read access-log bytes for tests. Never used by the CLI.
    #[cfg(test)]
    pub(crate) fn access_log_bytes(&self) -> Result<Vec<u8>, VaultError> {
        Ok(
            read_limited(&self.root.join("access.jsonl"), MAX_ACCESS_LOG_BYTES)?
                .unwrap_or_default(),
        )
    }

    fn load_engine(&self, vault_id: [u8; 16]) -> Result<CasEngine, VaultError> {
        let paths = VaultStorePaths::for_root(&self.root, vault_id);
        if !paths.state.exists() {
            return Ok(CasEngine::default());
        }
        let lock = secure_fs::open_lock(&paths.lock).map_err(map_secure_io)?;
        lock.lock()?;
        read_engine(&paths.state)
    }
}

/// Persist last-confirmed `(generation, canonical bytes)` next to a Vault.
pub(crate) struct ConfirmedAnchorFile {
    vault_path: PathBuf,
    path: PathBuf,
    vault_id: [u8; 16],
}

impl ConfirmedAnchorFile {
    /// Bind the sidecar to one Vault path and id.
    #[must_use]
    pub(crate) fn for_vault(vault_path: &Path, vault_id: [u8; 16]) -> Self {
        Self {
            vault_path: vault_path.to_path_buf(),
            path: sidecar_path(vault_path, ".audit-anchor-confirmed.json"),
            vault_id,
        }
    }

    /// Load the last locally confirmed anchor, if any.
    pub(crate) fn load(&self) -> Result<Option<(u64, Vec<u8>)>, VaultError> {
        let Some(bytes) = read_limited(&self.path, MAX_SIDECAR_BYTES)? else {
            return Ok(None);
        };
        let document: ConfirmedDocument =
            serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
        if document.format != CONFIRMED_FORMAT || document.version != CONFIRMED_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }
        let vault_id = decode_fixed::<16>(&document.vault_id)?;
        if vault_id != self.vault_id {
            return Err(VaultError::InvalidFormat);
        }
        let canonical = STANDARD
            .decode(document.canonical)
            .map_err(|_| VaultError::InvalidFormat)?;
        let observed = parse_anchor(&canonical)?;
        if serialize_anchor(&observed)? != canonical
            || observed.vault_id() != self.vault_id
            || observed.anchor_generation() != document.generation
            || sha256(&canonical) != decode_fixed::<32>(&document.digest)?
        {
            return Err(VaultError::InvalidFormat);
        }
        Ok(Some((document.generation, canonical)))
    }

    /// Replace the sidecar with the newly confirmed generation.
    pub(crate) fn persist(&self, generation: u64, bytes: &[u8]) -> Result<(), VaultError> {
        let observed = parse_anchor(bytes)?;
        if serialize_anchor(&observed)? != bytes
            || observed.vault_id() != self.vault_id
            || observed.anchor_generation() != generation
        {
            return Err(VaultError::InvalidFormat);
        }
        let document = ConfirmedDocument {
            format: CONFIRMED_FORMAT.to_owned(),
            version: CONFIRMED_VERSION,
            vault_id: URL_SAFE_NO_PAD.encode(self.vault_id),
            generation,
            digest: hex_encode(&sha256(bytes)),
            canonical: STANDARD.encode(bytes),
        };
        write_json(&self.path, &document)
    }

    /// Persist value-free rollback evidence next to the Vault.
    pub(crate) fn record_rollback(
        &self,
        expected_generation: u64,
        expected_bytes: &[u8],
        observed_generation: Option<u64>,
        observed_bytes: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        let document = RollbackDocument {
            format: ROLLBACK_FORMAT.to_owned(),
            version: ROLLBACK_VERSION,
            vault_id: URL_SAFE_NO_PAD.encode(self.vault_id),
            expected_generation,
            expected_digest: hex_encode(&sha256(expected_bytes)),
            observed_generation,
            observed_digest: observed_bytes
                .map(sha256)
                .as_ref()
                .map(|digest| hex_encode(digest)),
        };
        write_json(
            &sidecar_path(&self.vault_path, ".audit-anchor-rollback.json"),
            &document,
        )
    }
}

impl super::anchor_protocol::ConfirmedAnchorPersistence for ConfirmedAnchorFile {
    fn persist(&mut self, generation: u64, bytes: &[u8]) -> Result<(), VaultError> {
        Self::persist(self, generation, bytes)
    }

    fn record_rollback(
        &mut self,
        expected_generation: u64,
        expected_bytes: &[u8],
        observed_generation: Option<u64>,
        observed_bytes: Option<&[u8]>,
    ) -> Result<(), VaultError> {
        Self::record_rollback(
            self,
            expected_generation,
            expected_bytes,
            observed_generation,
            observed_bytes,
        )
    }
}

/// Value-free access record written by the reference CAS.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AnchorAccessRecord {
    /// `GET` or `POST`.
    pub(crate) method: &'static str,
    /// Vault id from the path, when it parsed.
    pub(crate) vault_id: Option<[u8; 16]>,
    /// Machine-readable result. Never a token or Secret.
    pub(crate) result: &'static str,
    /// Observed or applied generation, when known.
    pub(crate) generation: Option<u64>,
}

/// Issue a new token file, or refuse if the path already exists.
pub(crate) fn issue_anchor_token_file(path: &Path) -> Result<(), VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        ensure_private_dir(parent)?;
    }
    let token =
        generate_array::<TOKEN_LENGTH>().map_err(|_| VaultError::RandomSourceUnavailable)?;
    let document = TokenDocument {
        format: TOKEN_FORMAT.to_owned(),
        version: TOKEN_VERSION,
        token: STANDARD.encode(token),
    };
    let bytes = encode_json(&document)?;
    let mut file = secure_fs::create_new(path).map_err(map_secure_io)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Load the Bearer token from a private file. The caller must zeroize.
pub(crate) fn load_anchor_token(path: &Path) -> Result<Zeroizing<String>, VaultError> {
    let bytes = read_limited(path, MAX_TOKEN_BYTES)?.ok_or(VaultError::NotFound)?;
    let document: TokenDocument =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != TOKEN_FORMAT || document.version != TOKEN_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let token = STANDARD
        .decode(document.token.as_bytes())
        .map_err(|_| VaultError::InvalidFormat)?;
    if token.len() != TOKEN_LENGTH {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Zeroizing::new(document.token))
}

/// SHA-256 of the decoded token bytes, used by the server for comparison.
pub(crate) fn token_digest(token_b64: &str) -> Result<[u8; 32], VaultError> {
    let token = STANDARD
        .decode(token_b64.as_bytes())
        .map_err(|_| VaultError::InvalidFormat)?;
    if token.len() != TOKEN_LENGTH {
        return Err(VaultError::InvalidFormat);
    }
    Ok(sha256(&token))
}

/// Write the Vault-adjacent client sidecar after Owner authentication.
pub(crate) fn configure_anchor_client(
    vault_path: &Path,
    endpoint: &str,
    token_file: &Path,
    tls_ca: Option<&Path>,
    allow_plaintext: bool,
) -> Result<AnchorClientConfig, VaultError> {
    let (https, _, _) = split_loopback_endpoint(endpoint)?;
    if https {
        if allow_plaintext {
            return Err(VaultError::InvalidFormat);
        }
        let Some(ca) = tls_ca else {
            return Err(VaultError::InvalidFormat);
        };
        if !ca.is_file() {
            return Err(VaultError::NotFound);
        }
    } else if !allow_plaintext || tls_ca.is_some() {
        return Err(VaultError::InvalidFormat);
    }
    if !token_file.is_file() {
        return Err(VaultError::NotFound);
    }
    let _token = load_anchor_token(token_file)?;
    let config = AnchorClientConfig {
        mode: AnchorClientMode::Mandatory,
        endpoint: endpoint.to_owned(),
        token_file: token_file.to_path_buf(),
        tls_ca: tls_ca.map(Path::to_path_buf),
        allow_plaintext,
    };
    let tls_ca_display = config
        .tls_ca
        .as_ref()
        .map(|path| path.to_string_lossy().replace('\\', "/"));
    let document = ClientDocument {
        format: CLIENT_FORMAT,
        version: CLIENT_VERSION,
        mode: "mandatory",
        endpoint: config.endpoint.as_str(),
        token_file: &config.token_file.to_string_lossy().replace('\\', "/"),
        tls_ca: tls_ca_display.as_deref(),
        allow_plaintext: config.allow_plaintext,
    };
    write_json(&client_config_path(vault_path), &document)?;
    Ok(config)
}

/// Load a configured remote sink, if the sidecar exists.
pub(crate) fn load_anchor_client_config(
    vault_path: &Path,
) -> Result<Option<AnchorClientConfig>, VaultError> {
    let path = client_config_path(vault_path);
    let Some(bytes) = read_limited(&path, MAX_SIDECAR_BYTES)? else {
        return Ok(None);
    };
    let document: ClientDocumentOwned =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != CLIENT_FORMAT {
        return Err(VaultError::InvalidFormat);
    }
    if document.version != CLIENT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if document.mode != "mandatory" {
        return Err(VaultError::InvalidFormat);
    }
    let (https, _, _) = split_loopback_endpoint(&document.endpoint)?;
    let tls_ca = match document.tls_ca {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.as_os_str().is_empty()
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(VaultError::InvalidFormat);
            }
            Some(path)
        }
        None => None,
    };
    if https {
        if document.allow_plaintext || tls_ca.is_none() {
            return Err(VaultError::InvalidFormat);
        }
    } else if !document.allow_plaintext || tls_ca.is_some() {
        return Err(VaultError::InvalidFormat);
    }
    let token_file = PathBuf::from(document.token_file);
    if token_file.as_os_str().is_empty()
        || token_file
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Some(AnchorClientConfig {
        mode: AnchorClientMode::Mandatory,
        endpoint: document.endpoint,
        token_file,
        tls_ca,
        allow_plaintext: document.allow_plaintext,
    }))
}

/// Value-free inspection of the client sidecar and last-confirmed record.
pub(crate) fn load_anchor_status(
    vault_path: &Path,
    vault_id: Option<[u8; 16]>,
) -> Result<AnchorClientStatus, VaultError> {
    let config = load_anchor_client_config(vault_path)?;
    let confirmed = match vault_id {
        Some(id) => ConfirmedAnchorFile::for_vault(vault_path, id).load()?,
        None => inspect_confirmed(vault_path)?,
    };
    let rollback = inspect_rollback(vault_path)?;
    Ok(AnchorClientStatus {
        configured: config.is_some(),
        mode: config.as_ref().map(|value| value.mode),
        endpoint: config.as_ref().map(|value| value.endpoint.clone()),
        token_file: config.as_ref().map(|value| value.token_file.clone()),
        tls_ca: config.as_ref().and_then(|value| value.tls_ca.clone()),
        allow_plaintext: config.as_ref().is_some_and(|value| value.allow_plaintext),
        last_confirmed_generation: confirmed.as_ref().map(|(generation, _)| *generation),
        last_confirmed_digest: confirmed.as_ref().map(|(_, bytes)| sha256(bytes)),
        rollback_evidence: rollback.is_some(),
        rollback_expected_generation: rollback.as_ref().map(|value| value.0),
        rollback_observed_generation: rollback.and_then(|value| value.1),
    })
}

fn inspect_rollback(vault_path: &Path) -> Result<Option<(u64, Option<u64>)>, VaultError> {
    let path = sidecar_path(vault_path, ".audit-anchor-rollback.json");
    let Some(bytes) = read_limited(&path, MAX_SIDECAR_BYTES)? else {
        return Ok(None);
    };
    let document: RollbackDocument =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != ROLLBACK_FORMAT || document.version != ROLLBACK_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(Some((
        document.expected_generation,
        document.observed_generation,
    )))
}

fn inspect_confirmed(vault_path: &Path) -> Result<Option<(u64, Vec<u8>)>, VaultError> {
    let path = sidecar_path(vault_path, ".audit-anchor-confirmed.json");
    let Some(bytes) = read_limited(&path, MAX_SIDECAR_BYTES)? else {
        return Ok(None);
    };
    let document: ConfirmedDocument =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != CONFIRMED_FORMAT || document.version != CONFIRMED_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let canonical = STANDARD
        .decode(document.canonical)
        .map_err(|_| VaultError::InvalidFormat)?;
    if sha256(&canonical) != decode_fixed::<32>(&document.digest)? {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Some((document.generation, canonical)))
}

/// Accept only loopback HTTP or HTTPS endpoints.
pub(crate) fn validate_loopback_endpoint(endpoint: &str) -> Result<(), VaultError> {
    let (_, _, port) = split_loopback_endpoint(endpoint)?;
    if port == 0 {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

/// Split a loopback `http(s)://host:port` URL into scheme, host, and port.
pub(crate) fn split_loopback_endpoint(endpoint: &str) -> Result<(bool, &str, u16), VaultError> {
    let (https, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(VaultError::InvalidFormat);
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains('/') || rest.contains('@') || rest.contains('?') {
        return Err(VaultError::InvalidFormat);
    }
    let (host, port) = split_host_port(rest)?;
    if host != "127.0.0.1" && host != "[::1]" && host != "localhost" {
        return Err(VaultError::InvalidFormat);
    }
    Ok((https, host, port))
}

/// Like [`validate_loopback_endpoint`], but `port 0` is allowed so a server
/// can request an ephemeral listen port.
pub(crate) fn validate_loopback_listen(listen: &str) -> Result<(), VaultError> {
    let rest = listen
        .strip_prefix("http://")
        .ok_or(VaultError::InvalidFormat)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains('/') || rest.contains('@') || rest.contains('?') {
        return Err(VaultError::InvalidFormat);
    }
    let (host, _port) = split_host_port(rest)?;
    if host != "127.0.0.1" && host != "[::1]" && host != "localhost" {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

/// Parse `host:port` or `[::1]:port` from a validated endpoint body.
pub(crate) fn split_host_port(hostport: &str) -> Result<(&str, u16), VaultError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or(VaultError::InvalidFormat)?;
        if host != "::1" {
            return Err(VaultError::InvalidFormat);
        }
        let port = port.parse::<u16>().map_err(|_| VaultError::InvalidFormat)?;
        return Ok(("[::1]", port));
    }
    let (host, port) = hostport.split_once(':').ok_or(VaultError::InvalidFormat)?;
    let port = port.parse::<u16>().map_err(|_| VaultError::InvalidFormat)?;
    Ok((host, port))
}

fn client_config_path(vault_path: &Path) -> PathBuf {
    sidecar_path(vault_path, ".audit-anchor-client.json")
}

fn sidecar_path(vault_path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

struct VaultStorePaths {
    dir: PathBuf,
    state: PathBuf,
    lock: PathBuf,
}

impl VaultStorePaths {
    fn for_root(root: &Path, vault_id: [u8; 16]) -> Self {
        let dir = root.join("vaults").join(hex_encode(&vault_id));
        let state = dir.join("state.json");
        let mut lock = OsString::from(state.as_os_str());
        lock.push(".lock");
        Self {
            dir,
            state,
            lock: PathBuf::from(lock),
        }
    }
}

fn read_engine(path: &Path) -> Result<CasEngine, VaultError> {
    let Some(bytes) = read_limited(path, MAX_SIDECAR_BYTES)? else {
        return Ok(CasEngine::default());
    };
    let document: StoreDocument =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != STORE_FORMAT {
        return Err(VaultError::InvalidFormat);
    }
    if document.version != STORE_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let state = match document.canonical {
        Some(canonical) => {
            let bytes = STANDARD
                .decode(canonical)
                .map_err(|_| VaultError::InvalidFormat)?;
            let observed = parse_anchor(&bytes)?;
            if serialize_anchor(&observed)? != bytes
                || observed.anchor_generation() != document.generation
            {
                return Err(VaultError::InvalidFormat);
            }
            Some((document.generation, bytes))
        }
        None if document.generation == 0 => None,
        None => return Err(VaultError::InvalidFormat),
    };
    let mut ledger = Vec::new();
    for entry in document.ledger {
        let request_id = STANDARD
            .decode(entry.request_id)
            .map_err(|_| VaultError::InvalidFormat)?;
        if request_id.len() != REQUEST_ID_LENGTH {
            return Err(VaultError::InvalidFormat);
        }
        ledger.push((request_id, decode_decision(&entry.decision)?));
    }
    Ok(CasEngine::restore(state, ledger))
}

fn write_engine(path: &Path, engine: &CasEngine) -> Result<(), VaultError> {
    let (generation, canonical) = match engine.state() {
        Some((generation, bytes)) => (*generation, Some(STANDARD.encode(bytes))),
        None => (0, None),
    };
    let ledger = engine
        .ledger_entries()
        .into_iter()
        .map(|(request_id, decision)| {
            let encoded = encode_decision(&decision);
            StoreLedgerEntry {
                request_id: STANDARD.encode(request_id),
                decision: StoreDecisionOwned {
                    kind: encoded.kind.to_owned(),
                    generation: encoded.generation,
                    current: encoded.current,
                },
            }
        })
        .collect();
    let document = StoreDocument {
        format: STORE_FORMAT.to_owned(),
        version: STORE_VERSION,
        generation,
        canonical,
        ledger,
    };
    write_json(path, &document)
}

fn encode_decision(decision: &CasDecision) -> StoreDecision {
    match decision {
        CasDecision::Applied(bytes) => StoreDecision {
            kind: "applied",
            generation: None,
            current: Some(STANDARD.encode(bytes)),
        },
        CasDecision::AlreadyApplied(bytes) => StoreDecision {
            kind: "already_applied",
            generation: None,
            current: Some(STANDARD.encode(bytes)),
        },
        CasDecision::Conflict {
            generation,
            current,
        } => StoreDecision {
            kind: "conflict",
            generation: Some(*generation),
            current: current.as_ref().map(|bytes| STANDARD.encode(bytes)),
        },
        CasDecision::Invalid => StoreDecision {
            kind: "invalid",
            generation: None,
            current: None,
        },
    }
}

fn decode_decision(decision: &StoreDecisionOwned) -> Result<CasDecision, VaultError> {
    match decision.kind.as_str() {
        "applied" => Ok(CasDecision::Applied(decode_optional_anchor(
            decision.current.as_deref(),
        )?)),
        "already_applied" => Ok(CasDecision::AlreadyApplied(decode_optional_anchor(
            decision.current.as_deref(),
        )?)),
        "conflict" => Ok(CasDecision::Conflict {
            generation: decision.generation.ok_or(VaultError::InvalidFormat)?,
            current: match decision.current.as_deref() {
                None => None,
                Some(value) => Some(
                    STANDARD
                        .decode(value)
                        .map_err(|_| VaultError::InvalidFormat)?,
                ),
            },
        }),
        "invalid" => Ok(CasDecision::Invalid),
        _ => Err(VaultError::InvalidFormat),
    }
}

fn decode_optional_anchor(value: Option<&str>) -> Result<Vec<u8>, VaultError> {
    let encoded = value.ok_or(VaultError::InvalidFormat)?;
    STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidFormat)
}

fn write_json<T: Serialize>(path: &Path, document: &T) -> Result<(), VaultError> {
    let bytes = encode_json(document)?;
    if path.exists() {
        write_atomically(path, &bytes)?;
    } else {
        write_new(path, &bytes)?;
    }
    sync_parent_dir(path)
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), VaultError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let directory = fs::File::open(parent)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), VaultError> {
    Ok(())
}

fn encode_json<T: Serialize>(document: &T) -> Result<Vec<u8>, VaultError> {
    let mut bytes = serde_json::to_vec_pretty(document).map_err(|_| VaultError::InvalidFormat)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SIDECAR_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let mut file = secure_fs::create_new(path).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    let mut file = AtomicWriteFile::open(path)?;
    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(path).map_err(map_secure_io)
}

fn read_limited(path: &Path, max_bytes: usize) -> Result<Option<Vec<u8>>, VaultError> {
    let file = match secure_fs::open_existing(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_secure_io(error)),
    };
    let limit = u64::try_from(max_bytes).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(Some(bytes))
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], VaultError> {
    if value.len() == N * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut out = [0_u8; N];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| VaultError::InvalidFormat)?;
            out[index] = u8::from_str_radix(text, 16).map_err(|_| VaultError::InvalidFormat)?;
        }
        return Ok(out);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| VaultError::InvalidFormat)?;
    decoded.try_into().map_err(|_| VaultError::InvalidFormat)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn ensure_private_dir(dir: &Path) -> Result<(), VaultError> {
    if dir.exists() {
        if dir.is_dir() {
            return Ok(());
        }
        return Err(VaultError::UnsafePath);
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        ensure_private_dir(parent)?;
    }
    create_private_dir(dir).map_err(map_secure_io)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir(dir)
}

fn map_secure_io(error: std::io::Error) -> VaultError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        VaultError::UnsafePath
    } else {
        error.into()
    }
}

type TokenVaultBinding = ([u8; 32], [u8; 16]);

fn read_binding(path: &Path) -> Result<Option<TokenVaultBinding>, VaultError> {
    let Some(bytes) = read_limited(path, MAX_SIDECAR_BYTES)? else {
        return Ok(None);
    };
    let document: BindingDocument =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    if document.format != BINDING_FORMAT || document.version != BINDING_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    Ok(Some((
        decode_fixed::<32>(&document.token_digest)?,
        decode_fixed::<16>(&document.vault_id)?,
    )))
}

fn rotate_access_log_if_needed(path: &Path) -> Result<(), VaultError> {
    let Ok(metadata) = path.metadata() else {
        return Ok(());
    };
    if metadata.len() < MAX_ACCESS_LOG_BYTES as u64 {
        return Ok(());
    }
    let previous = path.with_extension("jsonl.prev");
    if previous.exists() {
        secure_fs::ensure_safe_path(&previous, false).map_err(map_secure_io)?;
        fs::remove_file(&previous)?;
    }
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    fs::rename(path, &previous)?;
    Ok(())
}

fn append_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if !path.exists() {
        return write_new(path, bytes);
    }
    let mut file = secure_fs::open_existing_read_write(path).map_err(map_secure_io)?;
    file.seek(SeekFrom::End(0))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn current_unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingDocument {
    format: String,
    version: u32,
    token_digest: String,
    vault_id: String,
}

#[derive(Debug, Serialize)]
struct AccessDocument {
    format: &'static str,
    version: u32,
    unix_time_millis: u64,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    vault_id: Option<String>,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackDocument {
    format: String,
    version: u32,
    vault_id: String,
    expected_generation: u64,
    expected_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observed_digest: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenDocument {
    format: String,
    version: u32,
    token: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientDocument<'a> {
    format: &'static str,
    version: u32,
    mode: &'static str,
    endpoint: &'a str,
    token_file: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_ca: Option<&'a str>,
    allow_plaintext: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientDocumentOwned {
    format: String,
    version: u32,
    mode: String,
    endpoint: String,
    token_file: String,
    #[serde(default)]
    tls_ca: Option<String>,
    #[serde(default)]
    allow_plaintext: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmedDocument {
    format: String,
    version: u32,
    vault_id: String,
    generation: u64,
    digest: String,
    canonical: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreDocument {
    format: String,
    version: u32,
    generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    canonical: Option<String>,
    ledger: Vec<StoreLedgerEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreLedgerEntry {
    request_id: String,
    decision: StoreDecisionOwned,
}

#[derive(Debug, Serialize)]
struct StoreDecision {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreDecisionOwned {
    kind: String,
    #[serde(default)]
    generation: Option<u64>,
    #[serde(default)]
    current: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        ConfirmedAnchorFile, FileBackedAnchorStore, configure_anchor_client,
        issue_anchor_token_file, load_anchor_client_config, load_anchor_status, load_anchor_token,
        validate_loopback_endpoint,
    };
    use crate::crypto::sha256;
    use crate::vault::VaultError;
    use crate::vault::anchor_cas::CasDecision;
    use crate::vault::audit_v2::{AuditAnchorV2, serialize_anchor};
    use tempfile::tempdir;

    const VAULT: [u8; 16] = [0x42; 16];

    fn anchor(generation: u64, previous: [u8; 32]) -> Result<Vec<u8>, VaultError> {
        serialize_anchor(&AuditAnchorV2::new(
            VAULT,
            generation,
            generation,
            generation,
            [u8::try_from(generation).unwrap_or(u8::MAX); 16],
            previous,
            0,
        )?)
    }

    #[test]
    fn file_store_survives_process_restart() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let store = FileBackedAnchorStore::open(root.path())?;
        let first = anchor(1, [0_u8; 32])?;
        assert!(matches!(
            store.compare_and_set(VAULT, &[0x01; 16], 0, &first)?,
            CasDecision::Applied(_)
        ));
        drop(store);
        let reopened = FileBackedAnchorStore::open(root.path())?;
        assert_eq!(reopened.load(VAULT)?.as_deref(), Some(first.as_slice()));
        assert!(matches!(
            reopened.compare_and_set(VAULT, &[0x01; 16], 0, &first)?,
            CasDecision::Applied(_)
        ));
        Ok(())
    }

    #[test]
    fn truncated_or_corrupt_store_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let store = FileBackedAnchorStore::open(root.path())?;
        let first = anchor(1, [0_u8; 32])?;
        assert!(matches!(
            store.compare_and_set(VAULT, &[0x01; 16], 0, &first)?,
            CasDecision::Applied(_)
        ));
        let Some(state) = std::fs::read_dir(root.path().join("vaults"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("state.json"))
            .find(|path| path.exists())
        else {
            return Err("missing state file".into());
        };
        overwrite_private(&state, b"{")?;
        assert!(matches!(store.load(VAULT), Err(VaultError::InvalidFormat)));
        overwrite_private(&state, b"{\"format\":\"envvault-audit-anchor-store\"}")?;
        assert!(matches!(store.load(VAULT), Err(VaultError::InvalidFormat)));
        Ok(())
    }

    fn overwrite_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        let mut file = crate::secure_fs::open_existing_read_write(path)?;
        file.set_len(0)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    #[test]
    fn last_confirmed_round_trips_and_binds_vault_id() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let vault = root.path().join("test.vault");
        let store = ConfirmedAnchorFile::for_vault(&vault, VAULT);
        let first = anchor(1, [0_u8; 32])?;
        store.persist(1, &first)?;
        assert_eq!(store.load()?.as_ref().map(|value| value.0), Some(1));
        let other = ConfirmedAnchorFile::for_vault(&vault, [0x00; 16]);
        assert!(other.load().is_err());
        Ok(())
    }

    #[test]
    fn configure_rejects_non_loopback_and_missing_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempdir()?;
        let vault = root.path().join("test.vault");
        let token = root.path().join("token.json");
        assert!(validate_loopback_endpoint("https://127.0.0.1:7432").is_ok());
        assert!(validate_loopback_endpoint("http://192.168.1.9:7432").is_err());
        assert!(matches!(
            configure_anchor_client(&vault, "http://127.0.0.1:7432", &token, None, true),
            Err(VaultError::NotFound)
        ));
        issue_anchor_token_file(&token)?;
        let loaded = load_anchor_token(&token)?;
        assert!(!loaded.is_empty());
        assert!(
            configure_anchor_client(&vault, "http://127.0.0.1:7432", &token, None, false).is_err()
        );
        configure_anchor_client(&vault, "http://127.0.0.1:7432", &token, None, true)?;
        let config = load_anchor_client_config(&vault)?.ok_or("missing config")?;
        assert_eq!(config.endpoint, "http://127.0.0.1:7432");
        let status = load_anchor_status(&vault, Some(VAULT))?;
        assert!(status.configured);
        assert!(status.last_confirmed_generation.is_none());
        assert_eq!(sha256(loaded.as_bytes()).len(), 32);
        Ok(())
    }
}
