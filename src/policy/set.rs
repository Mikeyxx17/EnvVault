use std::collections::BTreeSet;

use super::{
    AuthorizationRequest, DenyReason, PolicyDecision, PolicyEffect, PolicyEvaluation,
    PolicyEvaluator, PolicyRule,
};

/// In-memory set of exact authorization rules.
///
/// An empty set denies every request. When matching allow and deny rules both
/// exist, deny takes precedence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySet {
    rules: BTreeSet<PolicyRule>,
}

impl PolicySet {
    /// Creates an empty, deny-by-default policy set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: BTreeSet::new(),
        }
    }

    /// Adds one exact rule.
    ///
    /// Returns `false` when the identical rule already existed.
    pub fn insert(&mut self, rule: PolicyRule) -> bool {
        self.rules.insert(rule)
    }

    /// Removes one exact rule.
    ///
    /// Returns `false` when the rule did not exist.
    pub fn remove(&mut self, rule: &PolicyRule) -> bool {
        self.rules.remove(rule)
    }

    /// Returns the number of exact rules.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether no authorization rules are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterates rules in deterministic canonical order.
    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &PolicyRule> {
        self.rules.iter()
    }

    /// Evaluates each request independently and preserves request-decision
    /// pairing in the returned result.
    pub fn evaluate_batch(
        &self,
        requests: impl IntoIterator<Item = AuthorizationRequest>,
    ) -> Vec<PolicyEvaluation> {
        requests
            .into_iter()
            .map(|request| PolicyEvaluation::new(request, self.evaluate(&request)))
            .collect()
    }

    fn evaluate_exact(&self, request: &AuthorizationRequest) -> PolicyDecision {
        let mut matching_allow = false;

        for rule in &self.rules {
            if rule.caller() != request.caller()
                || rule.secret_id() != request.secret_id()
                || rule.operation() != request.operation()
            {
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

impl PolicyEvaluator for PolicySet {
    fn evaluate(&self, request: &AuthorizationRequest) -> PolicyDecision {
        self.evaluate_exact(request)
    }
}

#[cfg(test)]
mod tests {
    use super::PolicySet;
    use crate::{
        identity::{Caller, CallerId, CallerKind},
        policy::{
            AuthorizationRequest, DenyReason, Operation, PolicyDecision, PolicyEffect,
            PolicyEvaluator, PolicyRule,
        },
        secret::SecretId,
    };

    fn caller(byte: u8) -> Caller {
        Caller::new(
            CallerId::from_bytes([byte; CallerId::BYTE_LENGTH]),
            CallerKind::Application,
        )
    }

    fn secret(byte: u8) -> SecretId {
        SecretId::from_bytes([byte; SecretId::BYTE_LENGTH])
    }

    #[test]
    fn empty_policy_denies_by_default() {
        let request = AuthorizationRequest::new(caller(1), secret(2), Operation::Use);

        assert_eq!(
            PolicySet::new().evaluate(&request),
            PolicyDecision::Deny(DenyReason::NoMatchingGrant)
        );
    }

    #[test]
    fn grant_matches_only_the_exact_tuple() {
        let permitted = AuthorizationRequest::new(caller(1), secret(2), Operation::Use);
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            permitted.caller(),
            permitted.secret_id(),
            permitted.operation(),
            PolicyEffect::Allow,
        )));

        assert_eq!(policy.evaluate(&permitted), PolicyDecision::Allow);
        assert!(
            policy
                .evaluate(&AuthorizationRequest::new(
                    caller(3),
                    secret(2),
                    Operation::Use,
                ))
                .is_denied()
        );
        assert!(
            policy
                .evaluate(&AuthorizationRequest::new(
                    caller(1),
                    secret(4),
                    Operation::Use,
                ))
                .is_denied()
        );
        assert!(
            policy
                .evaluate(&AuthorizationRequest::new(
                    caller(1),
                    secret(2),
                    Operation::ReadPlaintext,
                ))
                .is_denied()
        );
    }

    #[test]
    fn explicit_deny_overrides_a_matching_allow() {
        let request = AuthorizationRequest::new(caller(1), secret(2), Operation::Export);
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            request.caller(),
            request.secret_id(),
            request.operation(),
            PolicyEffect::Allow,
        )));
        assert!(policy.insert(PolicyRule::new(
            request.caller(),
            request.secret_id(),
            request.operation(),
            PolicyEffect::Deny,
        )));

        assert_eq!(
            policy.evaluate(&request),
            PolicyDecision::Deny(DenyReason::ExplicitDeny)
        );
    }

    #[test]
    fn batch_evaluates_every_secret_independently() {
        let first = AuthorizationRequest::new(caller(1), secret(2), Operation::Use);
        let second = AuthorizationRequest::new(caller(1), secret(3), Operation::Use);
        let third = AuthorizationRequest::new(caller(1), secret(4), Operation::Use);
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            first.caller(),
            first.secret_id(),
            first.operation(),
            PolicyEffect::Allow,
        )));
        assert!(policy.insert(PolicyRule::new(
            third.caller(),
            third.secret_id(),
            third.operation(),
            PolicyEffect::Allow,
        )));

        let evaluations = policy.evaluate_batch([first, second, third]);

        assert_eq!(evaluations.len(), 3);
        assert_eq!(evaluations[0].request(), first);
        assert_eq!(evaluations[0].decision(), PolicyDecision::Allow);
        assert_eq!(
            evaluations[1].decision(),
            PolicyDecision::Deny(DenyReason::NoMatchingGrant)
        );
        assert_eq!(evaluations[2].request(), third);
        assert_eq!(evaluations[2].decision(), PolicyDecision::Allow);
    }

    #[test]
    fn list_and_exists_need_separate_grants() {
        let list = AuthorizationRequest::new(caller(1), secret(2), Operation::List);
        let exists = AuthorizationRequest::new(caller(1), secret(2), Operation::Exists);
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            list.caller(),
            list.secret_id(),
            list.operation(),
            PolicyEffect::Allow,
        )));

        assert_eq!(policy.evaluate(&list), PolicyDecision::Allow);
        assert!(policy.evaluate(&exists).is_denied());
    }

    #[test]
    fn caller_kind_is_part_of_the_exact_subject() {
        let application = AuthorizationRequest::new(caller(1), secret(2), Operation::Use);
        let agent = AuthorizationRequest::new(
            Caller::new(application.caller_id(), CallerKind::AiAgent),
            application.secret_id(),
            application.operation(),
        );
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            application.caller(),
            application.secret_id(),
            application.operation(),
            PolicyEffect::Allow,
        )));

        assert_eq!(policy.evaluate(&application), PolicyDecision::Allow);
        assert!(policy.evaluate(&agent).is_denied());
    }
}
