use super::{
    AuthorizationRequest, DenyReason, PolicyDecision, PolicyDocument, PolicyDocumentError,
    PolicySet, VaultAuthorizationRequest, VaultPolicySet,
};

/// Interface for evaluating a complete per-secret authorization request.
pub trait PolicyEvaluator: Send + Sync {
    /// Evaluates exactly one caller, one secret, and one operation.
    fn evaluate(&self, request: &AuthorizationRequest) -> PolicyDecision;
}

/// Interface for evaluating a complete Vault control-plane request.
pub trait VaultPolicyEvaluator: Send + Sync {
    /// Evaluates exactly one caller and one Vault operation.
    fn evaluate_vault(&self, request: &VaultAuthorizationRequest) -> PolicyDecision;
}

/// Fail-closed policy used when no configured evaluator is available.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAllPolicy;

impl PolicyEvaluator for DenyAllPolicy {
    fn evaluate(&self, _request: &AuthorizationRequest) -> PolicyDecision {
        PolicyDecision::Deny(DenyReason::DefaultDeny)
    }
}

impl VaultPolicyEvaluator for DenyAllPolicy {
    fn evaluate_vault(&self, _request: &VaultAuthorizationRequest) -> PolicyDecision {
        PolicyDecision::Deny(DenyReason::DefaultDeny)
    }
}

/// Availability state of the policy source used by [`PolicyEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyAvailability {
    /// A structurally valid policy is active.
    Active,
    /// No policy document was available.
    Missing,
    /// The policy document could not be decoded or validated.
    Invalid,
}

/// Fail-closed policy evaluator with observable source availability.
///
/// Missing and invalid sources evaluate every request as default deny. Storage
/// authentication must happen before a decoded document is supplied here.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy: Option<PolicySet>,
    vault_policy: Option<VaultPolicySet>,
    availability: PolicyAvailability,
}

impl PolicyEngine {
    /// Builds an engine from the result of loading an authenticated policy
    /// payload.
    #[must_use]
    pub fn from_document_result(
        result: Result<Option<PolicyDocument>, PolicyDocumentError>,
    ) -> Self {
        match result {
            Ok(Some(document)) => {
                let (policy, vault_policy) = document.into_policies();
                Self {
                    policy: Some(policy),
                    vault_policy: Some(vault_policy),
                    availability: PolicyAvailability::Active,
                }
            }
            Ok(None) => Self {
                policy: None,
                vault_policy: None,
                availability: PolicyAvailability::Missing,
            },
            Err(_) => Self {
                policy: None,
                vault_policy: None,
                availability: PolicyAvailability::Invalid,
            },
        }
    }

    /// Returns whether the source was active, missing, or invalid.
    #[must_use]
    pub const fn availability(&self) -> PolicyAvailability {
        self.availability
    }
}

impl VaultPolicyEvaluator for PolicyEngine {
    fn evaluate_vault(&self, request: &VaultAuthorizationRequest) -> PolicyDecision {
        self.vault_policy.as_ref().map_or_else(
            || PolicyDecision::Deny(DenyReason::DefaultDeny),
            |policy| policy.evaluate_vault(request),
        )
    }
}

impl PolicyEvaluator for PolicyEngine {
    fn evaluate(&self, request: &AuthorizationRequest) -> PolicyDecision {
        self.policy.as_ref().map_or_else(
            || PolicyDecision::Deny(DenyReason::DefaultDeny),
            |policy| policy.evaluate(request),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DenyAllPolicy, PolicyAvailability, PolicyEngine, PolicyEvaluator, VaultPolicyEvaluator,
    };
    use crate::{
        identity::{Caller, CallerId, CallerKind},
        policy::{
            AuthorizationRequest, DenyReason, Operation, PolicyDecision, PolicyDocumentError,
            VaultAuthorizationRequest, VaultOperation,
        },
        secret::SecretId,
    };

    #[test]
    fn deny_all_policy_fails_closed_for_a_complete_request() {
        let caller = Caller::new(
            CallerId::from_bytes([0x11; CallerId::BYTE_LENGTH]),
            CallerKind::Application,
        );
        let request = AuthorizationRequest::new(
            caller,
            SecretId::from_bytes([0x22; SecretId::BYTE_LENGTH]),
            Operation::Use,
        );

        assert_eq!(
            DenyAllPolicy.evaluate(&request),
            PolicyDecision::Deny(DenyReason::DefaultDeny)
        );
    }

    #[test]
    fn missing_and_invalid_policy_sources_fail_closed() {
        let caller = Caller::new(
            CallerId::from_bytes([0x11; CallerId::BYTE_LENGTH]),
            CallerKind::Application,
        );
        let request = AuthorizationRequest::new(
            caller,
            SecretId::from_bytes([0x22; SecretId::BYTE_LENGTH]),
            Operation::Use,
        );
        let missing = PolicyEngine::from_document_result(Ok(None));
        let invalid = PolicyEngine::from_document_result(Err(PolicyDocumentError::InvalidFormat));

        assert_eq!(missing.availability(), PolicyAvailability::Missing);
        assert_eq!(invalid.availability(), PolicyAvailability::Invalid);
        assert_eq!(
            missing.evaluate(&request),
            PolicyDecision::Deny(DenyReason::DefaultDeny)
        );
        assert_eq!(
            invalid.evaluate(&request),
            PolicyDecision::Deny(DenyReason::DefaultDeny)
        );
        let vault_request = VaultAuthorizationRequest::new(caller, VaultOperation::ManagePolicy);
        assert_eq!(
            missing.evaluate_vault(&vault_request),
            PolicyDecision::Deny(DenyReason::DefaultDeny)
        );
        assert_eq!(
            invalid.evaluate_vault(&vault_request),
            PolicyDecision::Deny(DenyReason::DefaultDeny)
        );
    }
}
