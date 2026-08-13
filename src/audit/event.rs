use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    identity::{AuthenticationMethod, Caller, CallerId, CallerKind},
    policy::{DenyReason, Operation, PolicyDecision, VaultOperation},
    secret::SecretId,
};

/// Safe audit data for one authorization decision.
///
/// This type has no field capable of carrying a Secret Value, master password,
/// key, or encrypted payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    caller: Caller,
    authentication_method: AuthenticationMethod,
    secret_id: Option<SecretId>,
    operation: Option<Operation>,
    vault_operation: Option<VaultOperation>,
    decision: PolicyDecision,
    unix_time_millis: u64,
}

const FORMAT_NAME: &str = "envvault-audit-event";
const AUTHORIZATION_FORMAT_VERSION: u32 = 1;
const AUTHENTICATION_FORMAT_VERSION: u32 = 2;
pub(crate) const MAX_AUDIT_EVENT_BYTES: usize = 4 * 1024;

impl AuditEvent {
    pub(crate) fn now_authentication(
        caller: Caller,
        authentication_method: AuthenticationMethod,
        decision: PolicyDecision,
    ) -> Self {
        let unix_time_millis = current_unix_time_millis();
        Self {
            caller,
            authentication_method,
            secret_id: None,
            operation: None,
            vault_operation: None,
            decision,
            unix_time_millis,
        }
    }

    pub(crate) fn now(
        caller: Caller,
        authentication_method: AuthenticationMethod,
        secret_id: SecretId,
        operation: Operation,
        decision: PolicyDecision,
    ) -> Self {
        let unix_time_millis = current_unix_time_millis();
        Self {
            caller,
            authentication_method,
            secret_id: Some(secret_id),
            operation: Some(operation),
            vault_operation: None,
            decision,
            unix_time_millis,
        }
    }

    pub(crate) fn now_vault(
        caller: Caller,
        authentication_method: AuthenticationMethod,
        operation: VaultOperation,
        decision: PolicyDecision,
    ) -> Self {
        let unix_time_millis = current_unix_time_millis();
        Self {
            caller,
            authentication_method,
            secret_id: None,
            operation: None,
            vault_operation: Some(operation),
            decision,
            unix_time_millis,
        }
    }

    /// Returns the authenticated caller subject.
    #[must_use]
    pub const fn caller(self) -> Caller {
        self.caller
    }

    /// Returns how the identity was verified.
    #[must_use]
    pub const fn authentication_method(self) -> AuthenticationMethod {
        self.authentication_method
    }

    /// Returns the exact Secret covered by the decision.
    #[must_use]
    pub const fn secret_id(self) -> Option<SecretId> {
        self.secret_id
    }

    /// Returns the exact operation covered by the decision.
    #[must_use]
    pub const fn operation(self) -> Option<Operation> {
        self.operation
    }

    /// Returns the Vault operation for a control-plane event.
    #[must_use]
    pub const fn vault_operation(self) -> Option<VaultOperation> {
        self.vault_operation
    }

    /// Returns whether this event records an identity authentication attempt.
    #[must_use]
    pub const fn is_authentication_attempt(self) -> bool {
        self.secret_id.is_none() && self.operation.is_none() && self.vault_operation.is_none()
    }

    /// Returns the authorization decision.
    pub const fn decision(self) -> PolicyDecision {
        self.decision
    }

    /// Returns milliseconds since the Unix epoch, or zero if the system clock
    /// was before the epoch.
    #[must_use]
    pub const fn unix_time_millis(self) -> u64 {
        self.unix_time_millis
    }

    pub(crate) fn encode(self) -> Result<Vec<u8>, AuditEventError> {
        let (decision, deny_reason) = match self.decision {
            PolicyDecision::Allow => ("allow", None),
            PolicyDecision::Deny(reason) => ("deny", Some(deny_reason_code(reason))),
        };
        let (version, target, secret_id, operation, vault_operation) =
            match (self.secret_id, self.operation, self.vault_operation) {
                (Some(secret_id), Some(operation), None) => (
                    AUTHORIZATION_FORMAT_VERSION,
                    "secret",
                    Some(secret_id.to_string()),
                    Some(operation.as_str().to_owned()),
                    None,
                ),
                (None, None, Some(operation)) => (
                    AUTHORIZATION_FORMAT_VERSION,
                    "vault",
                    None,
                    None,
                    Some(operation.as_str().to_owned()),
                ),
                (None, None, None) => (
                    AUTHENTICATION_FORMAT_VERSION,
                    "authentication",
                    None,
                    None,
                    None,
                ),
                _ => return Err(AuditEventError),
            };
        let file = AuditEventFile {
            format: FORMAT_NAME.to_owned(),
            version,
            caller_id: self.caller.id().to_string(),
            caller_kind: self.caller.kind().as_str().to_owned(),
            authentication_method: self.authentication_method.as_str().to_owned(),
            target: target.to_owned(),
            secret_id,
            operation,
            vault_operation,
            decision: decision.to_owned(),
            deny_reason: deny_reason.map(str::to_owned),
            unix_time_millis: self.unix_time_millis,
        };
        let bytes = serde_json::to_vec(&file).map_err(|_| AuditEventError)?;
        if bytes.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(AuditEventError);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AuditEventError> {
        if bytes.len() > MAX_AUDIT_EVENT_BYTES {
            return Err(AuditEventError);
        }
        let file: AuditEventFile = serde_json::from_slice(bytes).map_err(|_| AuditEventError)?;
        if file.format != FORMAT_NAME {
            return Err(AuditEventError);
        }
        let caller_id = CallerId::from_str(&file.caller_id).map_err(|_| AuditEventError)?;
        let caller_kind = CallerKind::from_str(&file.caller_kind).map_err(|_| AuditEventError)?;
        let authentication_method = AuthenticationMethod::from_str(&file.authentication_method)
            .map_err(|_| AuditEventError)?;
        let (secret_id, operation, vault_operation) = match (
            file.version,
            file.target.as_str(),
            file.secret_id.as_deref(),
            file.operation.as_deref(),
            file.vault_operation.as_deref(),
        ) {
            (AUTHORIZATION_FORMAT_VERSION, "secret", Some(secret_id), Some(operation), None) => (
                Some(SecretId::from_str(secret_id).map_err(|_| AuditEventError)?),
                Some(Operation::from_str(operation).map_err(|_| AuditEventError)?),
                None,
            ),
            (AUTHORIZATION_FORMAT_VERSION, "vault", None, None, Some(operation)) => (
                None,
                None,
                Some(VaultOperation::from_str(operation).map_err(|_| AuditEventError)?),
            ),
            (AUTHENTICATION_FORMAT_VERSION, "authentication", None, None, None) => {
                (None, None, None)
            }
            _ => return Err(AuditEventError),
        };
        let decision = match (file.decision.as_str(), file.deny_reason.as_deref()) {
            ("allow", None) => PolicyDecision::Allow,
            ("deny", Some(reason)) => PolicyDecision::Deny(parse_deny_reason(reason)?),
            _ => return Err(AuditEventError),
        };
        Ok(Self {
            caller: Caller::new(caller_id, caller_kind),
            authentication_method,
            secret_id,
            operation,
            vault_operation,
            decision,
            unix_time_millis: file.unix_time_millis,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditEventFile {
    format: String,
    version: u32,
    caller_id: String,
    caller_kind: String,
    authentication_method: String,
    target: String,
    secret_id: Option<String>,
    operation: Option<String>,
    vault_operation: Option<String>,
    decision: String,
    deny_reason: Option<String>,
    unix_time_millis: u64,
}

const fn deny_reason_code(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::DefaultDeny => "default_deny",
        DenyReason::NoMatchingGrant => "no_matching_grant",
        DenyReason::ExplicitDeny => "explicit_deny",
        DenyReason::InvalidRequest => "invalid_request",
    }
}

fn parse_deny_reason(value: &str) -> Result<DenyReason, AuditEventError> {
    match value {
        "default_deny" => Ok(DenyReason::DefaultDeny),
        "no_matching_grant" => Ok(DenyReason::NoMatchingGrant),
        "explicit_deny" => Ok(DenyReason::ExplicitDeny),
        "invalid_request" => Ok(DenyReason::InvalidRequest),
        _ => Err(AuditEventError),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditEventError;

fn current_unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::AuditEvent;
    use crate::{
        identity::{AuthenticationMethod, Caller, CallerId, CallerKind},
        policy::{DenyReason, Operation, PolicyDecision, VaultOperation},
        secret::SecretId,
    };

    #[test]
    fn event_payload_round_trips_without_a_value_field() -> Result<(), Box<dyn std::error::Error>> {
        let event = AuditEvent {
            caller: Caller::new(CallerId::from_bytes([0x11; 16]), CallerKind::Application),
            authentication_method: AuthenticationMethod::ApplicationCredential,
            secret_id: Some(SecretId::from_bytes([0x22; 16])),
            operation: Some(Operation::Use),
            vault_operation: None,
            decision: PolicyDecision::Deny(DenyReason::NoMatchingGrant),
            unix_time_millis: 42,
        };
        let encoded = event.encode().map_err(|_| "audit encode failed")?;
        let decoded = AuditEvent::decode(&encoded).map_err(|_| "audit decode failed")?;

        assert_eq!(decoded, event);
        assert!(!String::from_utf8(encoded)?.contains("value"));
        Ok(())
    }

    #[test]
    fn audit_and_error_rendering_cannot_echo_secret_material()
    -> Result<(), Box<dyn std::error::Error>> {
        const SENTINEL: &str = "ENVVAULT_SECRET_SENTINEL_9f2c7a";
        let event = AuditEvent {
            caller: Caller::new(CallerId::from_bytes([0x33; 16]), CallerKind::AiAgent),
            authentication_method: AuthenticationMethod::AgentCredential,
            secret_id: Some(SecretId::from_bytes([0x44; 16])),
            operation: Some(Operation::Use),
            vault_operation: None,
            decision: PolicyDecision::Deny(DenyReason::ExplicitDeny),
            unix_time_millis: 44,
        };

        let encoded = String::from_utf8(event.encode().map_err(|_| "audit encode failed")?)?;
        let debug = format!("{event:?}");
        let audit_error = crate::audit::AuditError.to_string();
        let broker_error = crate::broker::BrokerError::AuditUnavailable.to_string();
        for rendered in [&encoded, &debug, &audit_error, &broker_error] {
            assert!(!rendered.contains(SENTINEL));
            assert!(!rendered.to_ascii_lowercase().contains("secret_value"));
            assert!(!rendered.to_ascii_lowercase().contains("master_password"));
        }
        Ok(())
    }

    #[test]
    fn rejects_inconsistent_allow_with_a_deny_reason() {
        let invalid = br#"{
          "format":"envvault-audit-event","version":1,
          "caller_id":"11111111-1111-1111-1111-111111111111",
          "caller_kind":"application",
          "authentication_method":"application_credential",
          "target":"secret",
          "secret_id":"22222222-2222-2222-2222-222222222222",
          "operation":"use","decision":"allow",
          "deny_reason":"default_deny","unix_time_millis":42
        }"#;

        assert!(AuditEvent::decode(invalid).is_err());
    }

    #[test]
    fn vault_target_round_trips_without_a_fake_secret_id() -> Result<(), Box<dyn std::error::Error>>
    {
        let event = AuditEvent {
            caller: Caller::new(CallerId::from_bytes([0x41; 16]), CallerKind::Human),
            authentication_method: AuthenticationMethod::MasterPassword,
            secret_id: None,
            operation: None,
            vault_operation: Some(VaultOperation::ManagePolicy),
            decision: PolicyDecision::Allow,
            unix_time_millis: 43,
        };
        let encoded = event.encode().map_err(|_| "audit encode failed")?;
        let decoded = AuditEvent::decode(&encoded).map_err(|_| "audit decode failed")?;

        assert_eq!(decoded, event);
        assert_eq!(decoded.secret_id(), None);
        assert_eq!(
            decoded.vault_operation(),
            Some(VaultOperation::ManagePolicy)
        );
        Ok(())
    }

    #[test]
    fn authentication_target_round_trips_without_authorization_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let event = AuditEvent::now_authentication(
            Caller::new(CallerId::from_bytes([0x51; 16]), CallerKind::AiAgent),
            AuthenticationMethod::AgentCredential,
            PolicyDecision::Deny(DenyReason::InvalidRequest),
        );
        let encoded = event.encode().map_err(|_| "audit encode failed")?;
        let decoded = AuditEvent::decode(&encoded).map_err(|_| "audit decode failed")?;

        assert_eq!(decoded, event);
        assert!(decoded.is_authentication_attempt());
        assert_eq!(decoded.secret_id(), None);
        assert_eq!(decoded.operation(), None);
        assert_eq!(decoded.vault_operation(), None);
        assert!(String::from_utf8(encoded)?.contains("\"target\":\"authentication\""));
        Ok(())
    }
}
