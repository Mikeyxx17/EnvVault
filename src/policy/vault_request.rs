use crate::identity::{Caller, CallerId};

use super::VaultOperation;

/// Complete input for one Vault control-plane authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VaultAuthorizationRequest {
    caller: Caller,
    operation: VaultOperation,
}

impl VaultAuthorizationRequest {
    /// Creates a Vault-scoped request without evaluating it.
    #[must_use]
    pub const fn new(caller: Caller, operation: VaultOperation) -> Self {
        Self { caller, operation }
    }

    /// Returns the verified caller data supplied by the Broker.
    #[must_use]
    pub const fn caller(self) -> Caller {
        self.caller
    }

    /// Returns the stable caller identifier.
    #[must_use]
    pub const fn caller_id(self) -> CallerId {
        self.caller.id()
    }

    /// Returns the exact Vault operation.
    #[must_use]
    pub const fn operation(self) -> VaultOperation {
        self.operation
    }
}
