use crate::identity::{Caller, CallerId, CallerKind};

use super::{PolicyEffect, VaultOperation};

/// Exact `Caller × VaultOperation` control-plane rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultPolicyRule {
    caller: Caller,
    operation: VaultOperation,
    effect: PolicyEffect,
}

impl VaultPolicyRule {
    /// Creates an exact Vault-scoped authorization rule.
    #[must_use]
    pub const fn new(caller: Caller, operation: VaultOperation, effect: PolicyEffect) -> Self {
        Self {
            caller,
            operation,
            effect,
        }
    }

    /// Returns the complete targeted caller.
    #[must_use]
    pub const fn caller(self) -> Caller {
        self.caller
    }

    /// Returns the exact caller ID.
    #[must_use]
    pub const fn caller_id(self) -> CallerId {
        self.caller.id()
    }

    /// Returns the exact caller kind.
    #[must_use]
    pub const fn caller_kind(self) -> CallerKind {
        self.caller.kind()
    }

    /// Returns the targeted Vault operation.
    #[must_use]
    pub const fn operation(self) -> VaultOperation {
        self.operation
    }

    /// Returns the rule effect.
    #[must_use]
    pub const fn effect(self) -> PolicyEffect {
        self.effect
    }
}
