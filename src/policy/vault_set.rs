use std::collections::BTreeSet;

use super::{
    DenyReason, PolicyDecision, PolicyEffect, VaultAuthorizationRequest, VaultPolicyEvaluator,
    VaultPolicyRule,
};

/// In-memory exact Vault control-plane rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VaultPolicySet {
    rules: BTreeSet<VaultPolicyRule>,
}

impl VaultPolicySet {
    /// Creates an empty, deny-by-default Vault policy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: BTreeSet::new(),
        }
    }

    /// Adds one exact rule, returning false for a duplicate.
    pub fn insert(&mut self, rule: VaultPolicyRule) -> bool {
        self.rules.insert(rule)
    }

    /// Removes one exact rule, returning false if absent.
    pub fn remove(&mut self, rule: &VaultPolicyRule) -> bool {
        self.rules.remove(rule)
    }

    /// Returns the number of rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether no Vault grants or denies are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterates rules in deterministic canonical order.
    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &VaultPolicyRule> {
        self.rules.iter()
    }
}

impl VaultPolicyEvaluator for VaultPolicySet {
    fn evaluate_vault(&self, request: &VaultAuthorizationRequest) -> PolicyDecision {
        let mut matching_allow = false;
        for rule in &self.rules {
            if rule.caller() != request.caller() || rule.operation() != request.operation() {
                continue;
            }
            match rule.effect() {
                PolicyEffect::Deny => {
                    return PolicyDecision::Deny(DenyReason::ExplicitDeny);
                }
                PolicyEffect::Allow => matching_allow = true,
            }
        }
        if matching_allow {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny(DenyReason::NoMatchingGrant)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VaultPolicySet;
    use crate::{
        identity::{Caller, CallerId, CallerKind},
        policy::{
            DenyReason, PolicyDecision, PolicyEffect, VaultAuthorizationRequest, VaultOperation,
            VaultPolicyEvaluator, VaultPolicyRule,
        },
    };

    #[test]
    fn exact_owner_grant_does_not_grant_other_humans() {
        let owner = Caller::new(CallerId::from_bytes([1; 16]), CallerKind::Human);
        let other = Caller::new(CallerId::from_bytes([2; 16]), CallerKind::Human);
        let mut policy = VaultPolicySet::new();
        assert!(policy.insert(VaultPolicyRule::new(
            owner,
            VaultOperation::ManagePolicy,
            PolicyEffect::Allow,
        )));

        assert_eq!(
            policy.evaluate_vault(&VaultAuthorizationRequest::new(
                owner,
                VaultOperation::ManagePolicy,
            )),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate_vault(&VaultAuthorizationRequest::new(
                other,
                VaultOperation::ManagePolicy,
            )),
            PolicyDecision::Deny(DenyReason::NoMatchingGrant)
        );
    }

    #[test]
    fn explicit_vault_deny_overrides_allow() {
        let owner = Caller::new(CallerId::from_bytes([3; 16]), CallerKind::Human);
        let request = VaultAuthorizationRequest::new(owner, VaultOperation::CreateSecret);
        let mut policy = VaultPolicySet::new();
        assert!(policy.insert(VaultPolicyRule::new(
            owner,
            VaultOperation::CreateSecret,
            PolicyEffect::Allow,
        )));
        assert!(policy.insert(VaultPolicyRule::new(
            owner,
            VaultOperation::CreateSecret,
            PolicyEffect::Deny,
        )));

        assert_eq!(
            policy.evaluate_vault(&request),
            PolicyDecision::Deny(DenyReason::ExplicitDeny)
        );
    }
}
