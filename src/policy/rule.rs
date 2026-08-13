use crate::{
    identity::{Caller, CallerId, CallerKind},
    secret::SecretId,
};

use super::Operation;

/// Effect of one exact authorization rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyEffect {
    /// Grants the exact caller, secret, and operation tuple.
    Allow,
    /// Rejects the exact tuple and takes precedence over a matching grant.
    Deny,
}

impl PolicyEffect {
    /// Returns the stable serialization code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// One exact `Caller × SecretId × Operation` authorization rule.
///
/// V1 rules contain no wildcard, caller-kind shortcut, profile implication, or
/// implicit Human bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRule {
    caller: Caller,
    secret_id: SecretId,
    operation: Operation,
    effect: PolicyEffect,
}

impl PolicyRule {
    /// Creates an exact authorization rule.
    #[must_use]
    pub const fn new(
        caller: Caller,
        secret_id: SecretId,
        operation: Operation,
        effect: PolicyEffect,
    ) -> Self {
        Self {
            caller,
            secret_id,
            operation,
            effect,
        }
    }

    /// Returns the exact caller targeted by this rule.
    #[must_use]
    pub const fn caller_id(self) -> CallerId {
        self.caller.id()
    }

    /// Returns the exact caller kind targeted by this rule.
    #[must_use]
    pub const fn caller_kind(self) -> CallerKind {
        self.caller.kind()
    }

    /// Returns the complete caller subject targeted by this rule.
    #[must_use]
    pub const fn caller(self) -> Caller {
        self.caller
    }

    /// Returns the exact Secret targeted by this rule.
    #[must_use]
    pub const fn secret_id(self) -> SecretId {
        self.secret_id
    }

    /// Returns the exact operation targeted by this rule.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns whether the rule allows or denies its exact tuple.
    #[must_use]
    pub const fn effect(self) -> PolicyEffect {
        self.effect
    }
}
