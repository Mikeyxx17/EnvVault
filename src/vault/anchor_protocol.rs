//! Value-free wire-protocol reference implementation for external monotonic
//! audit anchors, following ADR 0015.
//!
//! This is an unverified prototype: it freezes the request/response shape,
//! the exact-generation compare-and-set semantics, bounded retries,
//! idempotency and service-side rollback detection, so a future real network
//! transport and a real deployment can reuse them. It performs no network
//! I/O and no Secret Value ever enters any of these types.

use std::collections::HashMap;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{CryptoError, sha256},
    vault::{
        VaultError,
        audit_anchor::{AnchorCasResult, AnchorSink},
        audit_v2::{parse_anchor, serialize_anchor},
    },
};

/// Number of random bytes in a client request id.
const REQUEST_ID_LENGTH: usize = 16;

/// Upper bound on accepted response bodies, well above the 4 KiB anchor cap.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Upper bound on accepted anchor bytes, matching the V2 format cap.
const MAX_ANCHOR_BYTES: usize = 4 * 1024;

/// Default number of transport attempts per logical CAS operation.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// ADR 0015 status codes used by the protocol.
mod status {
    pub(crate) const APPLIED: &str = "applied";
    pub(crate) const ALREADY_APPLIED: &str = "already_applied";
    pub(crate) const CONFLICT: &str = "conflict";
}

/// HTTP method subset used by ADR 0015.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorMethod {
    /// Read the current anchor.
    Get,
    /// Compare-and-set the anchor.
    Post,
}

/// A raw transport response: HTTP status plus body bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TransportResponse {
    /// HTTP status code.
    pub(super) status: u16,
    /// Response body.
    pub(super) body: Vec<u8>,
}

/// Transport-level failure: the request never produced an HTTP response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransportFailure {
    /// The attempt timed out.
    Timeout,
    /// The connection failed before a response arrived.
    ConnectionFailed,
}

/// Minimal transport boundary for one ADR 0015 call. A real deployment would
/// implement this over HTTPS with a vault-scoped bearer token.
pub(super) trait AnchorTransport: Send {
    /// Perform one call and return the raw response.
    fn call(
        &mut self,
        method: AnchorMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<TransportResponse, TransportFailure>;
}

/// ADR 0015 `compare-and-set` request body.
#[derive(Debug, Serialize, Deserialize)]
struct CasRequestBody {
    /// Base64 request id.
    request_id: String,
    /// Expected current generation.
    expected_generation: u64,
    /// Base64 canonical anchor bytes.
    anchor: String,
}

/// ADR 0015 `compare-and-set` response body.
#[derive(Debug, Serialize, Deserialize)]
struct CasResponseBody {
    /// One of `applied`, `already_applied`, `conflict`.
    status: String,
    /// Base64 stored canonical anchor bytes, when present.
    anchor: Option<String>,
    /// Stored generation, present on conflict.
    generation: Option<u64>,
}

/// ADR 0015 `GET anchor` response body.
#[derive(Debug, Serialize, Deserialize)]
struct AnchorBody {
    /// Base64 canonical anchor bytes.
    anchor: String,
}

/// ADR 0015 error body.
#[derive(Debug, Serialize, Deserialize)]
struct ErrorBody {
    /// Machine-readable error code.
    error: String,
}

/// Internal outcome of interpreting one CAS response.
enum CasOutcome {
    /// The operation reached a terminal CAS result with the verified bytes.
    Done(AnchorCasResult, Vec<u8>),
    /// The server reported a conflict.
    Conflict {
        /// Observed server generation.
        generation: Option<u64>,
    },
    /// The response is retryable.
    Retry,
    /// The response is fatal for this operation.
    Fatal(VaultError),
}

/// Reference client that speaks ADR 0015 over any [`AnchorTransport`] and
/// exposes the existing [`AnchorSink`] contract. Prototype only: the TLS
/// transport, token storage and deployment are deliberately out of scope.
pub(super) struct ProtocolAnchorClient<Transport: AnchorTransport> {
    vault_id: [u8; 16],
    transport: Transport,
    last_confirmed: Option<(u64, Vec<u8>)>,
    max_attempts: u32,
    sleep_before_retry: fn(u32) -> Duration,
}

impl<Transport: AnchorTransport> ProtocolAnchorClient<Transport> {
    /// Create a client for one Vault id. The backoff callback receives the
    /// zero-based attempt index and returns how long to wait before retrying.
    #[must_use]
    pub(super) fn new(
        vault_id: [u8; 16],
        transport: Transport,
        sleep_before_retry: fn(u32) -> Duration,
    ) -> Self {
        Self {
            vault_id,
            transport,
            last_confirmed: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            sleep_before_retry,
        }
    }
}

impl<Transport: AnchorTransport> AnchorSink for ProtocolAnchorClient<Transport> {
    fn load(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        let response = self
            .transport
            .call(AnchorMethod::Get, &anchor_path(&self.vault_id), None)
            .map_err(|_| VaultError::AuditAnchorDegraded)?;
        match response.status {
            200 => {
                let body: AnchorBody = serde_json::from_slice(&response.body)
                    .map_err(|_| VaultError::InvalidFormat)?;
                let bytes = decode_anchor_field(&body.anchor)?;
                let observed = parse_anchor(&bytes)?;
                let canonical = serialize_anchor(&observed)?;
                if canonical != bytes || observed.vault_id() != self.vault_id {
                    return Err(VaultError::InvalidFormat);
                }
                self.verify_no_rollback(observed.anchor_generation(), &bytes)?;
                self.last_confirmed = Some((observed.anchor_generation(), bytes.clone()));
                Ok(Some(bytes))
            }
            404 => {
                if self.last_confirmed.is_some() {
                    Err(VaultError::AuditAnchorDegraded)
                } else {
                    Ok(None)
                }
            }
            _ => Err(VaultError::AuditAnchorDegraded),
        }
    }

    fn compare_and_set(
        &mut self,
        expected_generation: u64,
        canonical_anchor: &[u8],
    ) -> Result<AnchorCasResult, VaultError> {
        let proposed = parse_anchor(canonical_anchor)?;
        let canonical = serialize_anchor(&proposed)?;
        if canonical != canonical_anchor
            || proposed.vault_id() != self.vault_id
            || proposed.anchor_generation()
                != expected_generation
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)?
        {
            return Err(VaultError::InvalidFormat);
        }
        let request_id = new_request_id()?;
        let body = serde_json::to_vec(&CasRequestBody {
            request_id: STANDARD.encode(&request_id),
            expected_generation,
            anchor: STANDARD.encode(canonical_anchor),
        })
        .map_err(|_| VaultError::InvalidFormat)?;

        let mut attempt: u32 = 0;
        loop {
            let outcome = match self.transport.call(
                AnchorMethod::Post,
                &cas_path(&self.vault_id),
                Some(&body),
            ) {
                Ok(response) => self.interpret_cas_response(&response, canonical_anchor),
                Err(TransportFailure::Timeout | TransportFailure::ConnectionFailed) => {
                    CasOutcome::Retry
                }
            };
            match outcome {
                CasOutcome::Done(result, bytes) => {
                    self.last_confirmed = Some((proposed.anchor_generation(), bytes));
                    return Ok(result);
                }
                CasOutcome::Conflict { generation } => {
                    if generation.is_some_and(|value| {
                        self.last_confirmed
                            .as_ref()
                            .is_some_and(|(confirmed, _)| value < *confirmed)
                    }) {
                        return Err(VaultError::AuditAnchorDegraded);
                    }
                    return Ok(AnchorCasResult::Conflict);
                }
                CasOutcome::Fatal(error) => return Err(error),
                CasOutcome::Retry => {}
            }
            if attempt + 1 >= self.max_attempts {
                return Err(VaultError::AuditAnchorDegraded);
            }
            (self.sleep_before_retry)(attempt);
            attempt += 1;
        }
    }
}

impl<Transport: AnchorTransport> ProtocolAnchorClient<Transport> {
    fn interpret_cas_response(
        &self,
        response: &TransportResponse,
        proposed_bytes: &[u8],
    ) -> CasOutcome {
        if response.body.len() > MAX_RESPONSE_BYTES {
            return CasOutcome::Fatal(VaultError::ResourceLimitExceeded);
        }
        match response.status {
            200 => {
                let Ok(body) = serde_json::from_slice::<CasResponseBody>(&response.body) else {
                    return CasOutcome::Fatal(VaultError::InvalidFormat);
                };
                let stored = match body.anchor {
                    Some(field) => match decode_anchor_field(&field) {
                        Ok(bytes) => bytes,
                        Err(error) => return CasOutcome::Fatal(error),
                    },
                    None => return CasOutcome::Fatal(VaultError::InvalidFormat),
                };
                let Ok(observed) = parse_anchor(&stored) else {
                    return CasOutcome::Fatal(VaultError::InvalidFormat);
                };
                let canonical = match serialize_anchor(&observed) {
                    Ok(bytes) => bytes,
                    Err(error) => return CasOutcome::Fatal(error),
                };
                if canonical != stored || observed.vault_id() != self.vault_id {
                    return CasOutcome::Fatal(VaultError::InvalidFormat);
                }
                if self
                    .last_confirmed
                    .as_ref()
                    .is_some_and(|(confirmed, _)| observed.anchor_generation() < *confirmed)
                {
                    return CasOutcome::Fatal(VaultError::AuditAnchorDegraded);
                }
                match body.status.as_str() {
                    status::APPLIED | status::ALREADY_APPLIED if stored == proposed_bytes => {
                        let result = if body.status == status::APPLIED {
                            AnchorCasResult::Applied
                        } else {
                            AnchorCasResult::AlreadyApplied
                        };
                        CasOutcome::Done(result, stored)
                    }
                    status::APPLIED | status::ALREADY_APPLIED => CasOutcome::Conflict {
                        generation: Some(observed.anchor_generation()),
                    },
                    status::CONFLICT => CasOutcome::Conflict {
                        generation: body.generation,
                    },
                    _ => CasOutcome::Fatal(VaultError::InvalidFormat),
                }
            }
            409 => {
                let Ok(body) = serde_json::from_slice::<CasResponseBody>(&response.body) else {
                    return CasOutcome::Fatal(VaultError::InvalidFormat);
                };
                let generation = match (&body.anchor, body.generation) {
                    (Some(field), Some(generation)) => {
                        let bytes = match decode_anchor_field(field) {
                            Ok(bytes) => bytes,
                            Err(error) => return CasOutcome::Fatal(error),
                        };
                        let Ok(observed) = parse_anchor(&bytes) else {
                            return CasOutcome::Fatal(VaultError::InvalidFormat);
                        };
                        let canonical = match serialize_anchor(&observed) {
                            Ok(bytes) => bytes,
                            Err(error) => return CasOutcome::Fatal(error),
                        };
                        if canonical != bytes
                            || observed.vault_id() != self.vault_id
                            || generation != observed.anchor_generation()
                        {
                            return CasOutcome::Fatal(VaultError::InvalidFormat);
                        }
                        Some(generation)
                    }
                    (None, None) => None,
                    (Some(_), None) | (None, Some(_)) => {
                        return CasOutcome::Fatal(VaultError::InvalidFormat);
                    }
                };
                CasOutcome::Conflict { generation }
            }
            422 => CasOutcome::Fatal(VaultError::InvalidFormat),
            429 | 503 => CasOutcome::Retry,
            _ => CasOutcome::Fatal(VaultError::AuditAnchorDegraded),
        }
    }

    fn verify_no_rollback(&self, generation: u64, bytes: &[u8]) -> Result<(), VaultError> {
        if let Some((confirmed, confirmed_bytes)) = &self.last_confirmed
            && (generation < *confirmed || (generation == *confirmed && confirmed_bytes != bytes))
        {
            return Err(VaultError::AuditAnchorDegraded);
        }
        Ok(())
    }
}

/// Deterministic response-fault knobs for the test double.
#[derive(Debug, Default)]
struct ResponseFaults {
    unavailable: bool,
    rate_limited: bool,
    corrupt_anchor: bool,
}

/// In-process test double for the ADR 0015 service side. It keeps the CAS
/// state, a bounded idempotency ledger and deterministic fault knobs so the
/// client can be exercised against the full protocol fault matrix without
/// any network or filesystem dependency.
#[derive(Debug, Default)]
pub(super) struct TestDoubleServer {
    state: Option<(u64, Vec<u8>)>,
    ledger: HashMap<Vec<u8>, (u16, Vec<u8>)>,
    forced: bool,
    forced_state: Option<(u64, Vec<u8>)>,
    faults: ResponseFaults,
}

impl TestDoubleServer {
    /// Answer every call with `503`.
    pub(super) fn set_respond_unavailable(&mut self, value: bool) {
        self.faults.unavailable = value;
    }

    /// Answer every call with `429`.
    pub(super) fn set_respond_rate_limited(&mut self, value: bool) {
        self.faults.rate_limited = value;
    }

    /// Corrupt the anchor bytes in `200` responses.
    pub(super) fn set_corrupt_anchor_response(&mut self, value: bool) {
        self.faults.corrupt_anchor = value;
    }

    /// Simulate service-side storage restored from an older snapshot: `None`
    /// means "no anchor ever existed", `Some(state)` restores that state.
    pub(super) fn set_forced_state(&mut self, state: Option<(u64, Vec<u8>)>) {
        self.forced = true;
        self.forced_state = state;
    }

    /// Handle one ADR 0015 call and return the raw HTTP response.
    pub(super) fn handle(
        &mut self,
        method: AnchorMethod,
        path: &str,
        body: Option<&[u8]>,
    ) -> (u16, Vec<u8>) {
        if self.faults.unavailable {
            return (503, error_body("unavailable"));
        }
        if self.faults.rate_limited {
            return (429, error_body("rate_limited"));
        }
        let Ok(path_vault) = parse_path_vault(method, path) else {
            return (422, error_body("invalid_anchor"));
        };
        match method {
            AnchorMethod::Get => self.handle_get(),
            AnchorMethod::Post => {
                let Some(body_bytes) = body else {
                    return (422, error_body("invalid_anchor"));
                };
                self.handle_cas(path_vault, body_bytes)
            }
        }
    }

    fn handle_get(&mut self) -> (u16, Vec<u8>) {
        match self.effective_state() {
            Some((_generation, bytes)) => {
                let mut stored = bytes.clone();
                if self.faults.corrupt_anchor {
                    stored.push(0);
                }
                let Ok(body) = serde_json::to_vec(&AnchorBody {
                    anchor: STANDARD.encode(&stored),
                }) else {
                    return (503, error_body("unavailable"));
                };
                (200, body)
            }
            None => (404, error_body("not_found")),
        }
    }

    fn handle_cas(&mut self, path_vault: [u8; 16], body_bytes: &[u8]) -> (u16, Vec<u8>) {
        let Ok(request) = serde_json::from_slice::<CasRequestBody>(body_bytes) else {
            return (422, error_body("invalid_anchor"));
        };
        let Ok(request_id) = STANDARD.decode(&request.request_id) else {
            return (422, error_body("invalid_anchor"));
        };
        if request_id.len() != REQUEST_ID_LENGTH {
            return (422, error_body("invalid_anchor"));
        }
        if let Some(previous) = self.ledger.get(&request_id) {
            return previous.clone();
        }
        let Ok(anchor_bytes) = STANDARD.decode(&request.anchor) else {
            return (422, error_body("invalid_anchor"));
        };
        let Ok(proposed) = parse_anchor(&anchor_bytes) else {
            return (422, error_body("invalid_anchor"));
        };
        let Ok(canonical) = serialize_anchor(&proposed) else {
            return (422, error_body("invalid_anchor"));
        };
        if canonical != anchor_bytes
            || proposed.vault_id() != path_vault
            || proposed.anchor_generation() != request.expected_generation.saturating_add(1)
        {
            return (422, error_body("invalid_anchor"));
        }
        let response = match self.effective_state() {
            None if request.expected_generation == 0
                && proposed.previous_anchor_digest() == [0_u8; 32] =>
            {
                self.state = Some((proposed.anchor_generation(), anchor_bytes.clone()));
                applied_body(&anchor_bytes)
            }
            None => conflict_body(0, None),
            Some((generation, current)) if anchor_bytes == *current => {
                already_applied_body(current)
            }
            Some((generation, current)) => {
                if *generation != request.expected_generation {
                    return self.record(&request_id, conflict_body(*generation, Some(current)));
                }
                let Ok(stored_anchor) = parse_anchor(current) else {
                    return self.record(&request_id, (422, error_body("invalid_anchor")));
                };
                if proposed.previous_anchor_digest() != sha256(current)
                    || proposed.segment_id() <= stored_anchor.segment_id()
                    || proposed.sequence() <= stored_anchor.sequence()
                {
                    return self.record(&request_id, (422, error_body("invalid_anchor")));
                }
                self.state = Some((proposed.anchor_generation(), anchor_bytes.clone()));
                applied_body(&anchor_bytes)
            }
        };
        let response = if self.faults.corrupt_anchor && response.0 == 200 {
            let mut body = response.1;
            body.push(0);
            (response.0, body)
        } else {
            response
        };
        self.record(&request_id, response)
    }

    fn effective_state(&self) -> Option<&(u64, Vec<u8>)> {
        if self.forced {
            self.forced_state.as_ref()
        } else {
            self.state.as_ref()
        }
    }

    fn record(&mut self, request_id: &[u8], response: (u16, Vec<u8>)) -> (u16, Vec<u8>) {
        self.ledger.insert(request_id.to_vec(), response.clone());
        response
    }
}

/// Produce an `applied` response body for stored canonical bytes.
fn applied_body(bytes: &[u8]) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(&CasResponseBody {
        status: status::APPLIED.to_owned(),
        anchor: Some(STANDARD.encode(bytes)),
        generation: None,
    })
    .unwrap_or_default();
    (200, body)
}

/// Produce an `already_applied` response body for stored canonical bytes.
fn already_applied_body(bytes: &[u8]) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(&CasResponseBody {
        status: status::ALREADY_APPLIED.to_owned(),
        anchor: Some(STANDARD.encode(bytes)),
        generation: None,
    })
    .unwrap_or_default();
    (200, body)
}

/// Produce a conflict response body.
fn conflict_body(generation: u64, anchor: Option<&[u8]>) -> (u16, Vec<u8>) {
    let body = serde_json::to_vec(&CasResponseBody {
        status: status::CONFLICT.to_owned(),
        anchor: anchor.map(|bytes| STANDARD.encode(bytes)),
        generation: Some(generation),
    })
    .unwrap_or_default();
    (409, body)
}

/// Produce an error body with the given code.
fn error_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&ErrorBody {
        error: code.to_owned(),
    })
    .unwrap_or_default()
}

/// Build the ADR 0015 GET path for a Vault id.
fn anchor_path(vault_id: &[u8; 16]) -> String {
    format!("/v1/vaults/{}/anchor", STANDARD.encode(vault_id))
}

/// Build the ADR 0015 CAS path for a Vault id.
fn cas_path(vault_id: &[u8; 16]) -> String {
    format!(
        "/v1/vaults/{}/anchor/compare-and-set",
        STANDARD.encode(vault_id)
    )
}

/// Decode and canonicalize a base64 anchor field from a response body.
fn decode_anchor_field(field: &str) -> Result<Vec<u8>, VaultError> {
    let bytes = STANDARD
        .decode(field)
        .map_err(|_| VaultError::InvalidFormat)?;
    if bytes.len() > MAX_ANCHOR_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

/// Generate a fresh CSPRNG request id.
fn new_request_id() -> Result<Vec<u8>, VaultError> {
    crate::crypto::generate_array::<REQUEST_ID_LENGTH>()
        .map(|bytes| bytes.to_vec())
        .map_err(map_crypto_error)
}

/// Map the reachable crypto failure to its Vault counterpart.
fn map_crypto_error(error: CryptoError) -> VaultError {
    match error {
        CryptoError::RandomSourceUnavailable => VaultError::RandomSourceUnavailable,
        CryptoError::InvalidKdfParameters
        | CryptoError::KeyDerivationFailed
        | CryptoError::EncryptionFailed
        | CryptoError::AuthenticationFailed => VaultError::InvalidFormat,
    }
}

/// Parse the Vault id and suffix out of an ADR 0015 path. Fails on any
/// deviation, including a suffix that does not match the method.
fn parse_path_vault(method: AnchorMethod, path: &str) -> Result<[u8; 16], ()> {
    const PREFIX: &str = "/v1/vaults/";
    let rest = path.strip_prefix(PREFIX).ok_or(())?;
    let (encoded, suffix) = rest.split_once('/').ok_or(())?;
    let expected_suffix = match method {
        AnchorMethod::Get => "anchor",
        AnchorMethod::Post => "anchor/compare-and-set",
    };
    if suffix != expected_suffix {
        return Err(());
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| ())?;
    if bytes.len() != 16 {
        return Err(());
    }
    let mut vault_id = [0_u8; 16];
    vault_id.copy_from_slice(&bytes);
    Ok(vault_id)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::time::Duration;

    use base64::Engine as _;

    use super::{
        AnchorMethod, AnchorTransport, ProtocolAnchorClient, TestDoubleServer, TransportFailure,
        TransportResponse,
    };
    use crate::{
        crypto::sha256,
        vault::{
            VaultError,
            audit_anchor::{AnchorCasResult, AnchorSink},
            audit_v2::{AuditAnchorV2, serialize_anchor},
        },
    };

    const VAULT: [u8; 16] = [0x11; 16];

    fn anchor(
        generation: u64,
        terminal: [u8; 16],
        previous: [u8; 32],
    ) -> Result<Vec<u8>, VaultError> {
        serialize_anchor(&AuditAnchorV2::new(
            VAULT, generation, generation, generation, terminal, previous, 0,
        )?)
    }

    /// Build a valid chain of anchors for generations `1..=N`.
    fn generations(count: u64) -> Result<Vec<Vec<u8>>, VaultError> {
        let mut out = Vec::new();
        let mut previous = [0_u8; 32];
        for generation in 1..=count {
            let bytes = anchor(
                generation,
                [u8::try_from(generation).unwrap_or(u8::MAX); 16],
                previous,
            )?;
            previous = sha256(&bytes);
            out.push(bytes);
        }
        Ok(out)
    }

    struct ScriptedTransport {
        server: TestDoubleServer,
        script: VecDeque<TransportFailure>,
    }

    impl AnchorTransport for ScriptedTransport {
        fn call(
            &mut self,
            method: AnchorMethod,
            path: &str,
            body: Option<&[u8]>,
        ) -> Result<TransportResponse, TransportFailure> {
            if let Some(failure) = self.script.pop_front() {
                return Err(failure);
            }
            let (status, body) = self.server.handle(method, path, body);
            Ok(TransportResponse { status, body })
        }
    }

    fn new_client(transport: ScriptedTransport) -> ProtocolAnchorClient<ScriptedTransport> {
        ProtocolAnchorClient::new(VAULT, transport, |_| Duration::ZERO)
    }

    #[test]
    fn response_loss_retries_with_the_same_request_id_and_applies_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut script = VecDeque::new();
        script.push_back(TransportFailure::Timeout);
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport { server, script };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        assert_eq!(sink.compare_and_set(0, first)?, AnchorCasResult::Applied);
        assert_eq!(sink.last_confirmed.as_ref().map(|value| value.0), Some(1));
        Ok(())
    }

    #[test]
    fn duplicate_request_returns_already_applied_without_generation_advance()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        assert_eq!(sink.compare_and_set(0, first)?, AnchorCasResult::Applied);
        assert_eq!(
            sink.compare_and_set(0, first)?,
            AnchorCasResult::AlreadyApplied
        );
        let loaded = sink.load()?.ok_or("expected stored anchor")?;
        assert_eq!(&loaded, first);
        Ok(())
    }

    #[test]
    fn same_generation_different_bytes_is_a_conflict() -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        assert_eq!(sink.compare_and_set(0, first)?, AnchorCasResult::Applied);
        let fork = anchor(1, [0x77; 16], [0_u8; 32])?;
        assert_eq!(sink.compare_and_set(0, &fork)?, AnchorCasResult::Conflict);
        Ok(())
    }

    #[test]
    fn persistent_unavailability_exhausts_the_retry_budget_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = TestDoubleServer::default();
        server.set_respond_unavailable(true);
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        let error = sink
            .compare_and_set(0, first)
            .err()
            .ok_or("expected failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn persistent_rate_limiting_exhausts_the_budget_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = TestDoubleServer::default();
        server.set_respond_rate_limited(true);
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        let error = sink
            .compare_and_set(0, first)
            .err()
            .ok_or("expected failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn service_rollback_to_an_older_generation_is_detected_on_load()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let gens = generations(2)?;
        assert_eq!(sink.compare_and_set(0, &gens[0])?, AnchorCasResult::Applied);
        assert_eq!(sink.compare_and_set(1, &gens[1])?, AnchorCasResult::Applied);
        sink.transport
            .server
            .set_forced_state(Some((1, gens[0].clone())));
        let error = sink.load().err().ok_or("expected rollback failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn service_rollback_with_equal_generation_but_different_bytes_is_detected()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let gens = generations(2)?;
        assert_eq!(sink.compare_and_set(0, &gens[0])?, AnchorCasResult::Applied);
        assert_eq!(sink.compare_and_set(1, &gens[1])?, AnchorCasResult::Applied);
        let fork = anchor(2, [0x66; 16], sha256(&gens[0]))?;
        sink.transport.server.set_forced_state(Some((2, fork)));
        let error = sink.load().err().ok_or("expected rollback failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn conflicting_response_that_rolls_back_is_degraded_not_conflict()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let gens = generations(2)?;
        assert_eq!(sink.compare_and_set(0, &gens[0])?, AnchorCasResult::Applied);
        assert_eq!(sink.compare_and_set(1, &gens[1])?, AnchorCasResult::Applied);
        sink.transport
            .server
            .set_forced_state(Some((1, gens[0].clone())));
        let third = anchor(3, [0x33; 16], sha256(&gens[1]))?;
        let error = sink
            .compare_and_set(2, &third)
            .err()
            .ok_or("expected failure")?;
        assert_eq!(error, VaultError::AuditAnchorDegraded);
        Ok(())
    }

    #[test]
    fn a_fresh_client_recovers_the_confirmed_chain_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let gens = generations(2)?;
        assert_eq!(sink.compare_and_set(0, &gens[0])?, AnchorCasResult::Applied);
        assert_eq!(sink.compare_and_set(1, &gens[1])?, AnchorCasResult::Applied);
        let revived_server = std::mem::take(&mut sink.transport.server);
        let mut revived = new_client(ScriptedTransport {
            server: revived_server,
            script: VecDeque::new(),
        });
        let loaded = revived.load()?.ok_or("expected stored anchor")?;
        assert_eq!(loaded, gens[1]);
        let third = anchor(3, [0x33; 16], sha256(&gens[1]))?;
        assert_eq!(
            revived.compare_and_set(2, &third)?,
            AnchorCasResult::Applied
        );
        Ok(())
    }

    #[test]
    fn server_enforces_generation_gap_prev_digest_and_vault_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = TestDoubleServer::default();
        let gens = generations(3)?;
        let mut request_counter = 0_u8;
        let mut apply = |server: &mut TestDoubleServer, expected: u64, bytes: &[u8]| {
            request_counter = request_counter.wrapping_add(1);
            server.handle(
                AnchorMethod::Post,
                &super::cas_path(&VAULT),
                Some(
                    &serde_json::to_vec(&super::CasRequestBody {
                        request_id: super::STANDARD.encode([request_counter; 16]),
                        expected_generation: expected,
                        anchor: super::STANDARD.encode(bytes),
                    })
                    .unwrap_or_default(),
                ),
            )
        };
        assert_eq!(apply(&mut server, 0, &gens[0]).0, 200);
        assert_eq!(apply(&mut server, 0, &gens[0]).0, 200);
        let fork = anchor(1, [0x77; 16], [0_u8; 32])?;
        assert_eq!(apply(&mut server, 0, &fork).0, 409);
        assert_eq!(apply(&mut server, 1, &gens[2]).0, 422);
        let wrong_prev = anchor(2, [0x32; 16], [0x42; 32])?;
        assert_eq!(apply(&mut server, 1, &wrong_prev).0, 422);
        let padded = {
            let mut bytes = gens[0].clone();
            bytes.push(b' ');
            bytes
        };
        assert_eq!(apply(&mut server, 0, &padded).0, 422);
        let other_anchor = AuditAnchorV2::new([0x99; 16], 1, 1, 1, [0x55; 16], [0_u8; 32], 0)?;
        let other_vault = serialize_anchor(&other_anchor)?;
        assert_eq!(apply(&mut server, 0, &other_vault).0, 422);
        Ok(())
    }

    #[test]
    fn client_rejects_non_canonical_anchor_before_sending() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = TestDoubleServer::default();
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let mut malformed = generations(1)?[0].clone();
        malformed.push(b'}');
        let error = sink
            .compare_and_set(0, &malformed)
            .err()
            .ok_or("expected failure")?;
        assert_eq!(error, VaultError::InvalidFormat);
        Ok(())
    }

    #[test]
    fn corrupt_anchor_in_a_200_response_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut server = TestDoubleServer::default();
        server.set_corrupt_anchor_response(true);
        let transport = ScriptedTransport {
            server,
            script: VecDeque::new(),
        };
        let mut sink = new_client(transport);
        let first = &generations(1)?[0];
        let error = sink
            .compare_and_set(0, first)
            .err()
            .ok_or("expected failure")?;
        assert_eq!(error, VaultError::InvalidFormat);
        assert_eq!(
            sink.transport.server.state.as_ref().map(|value| value.0),
            Some(1)
        );
        Ok(())
    }
}
