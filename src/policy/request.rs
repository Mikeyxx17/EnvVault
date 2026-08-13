use crate::{
    identity::{Caller, CallerId},
    secret::SecretId,
};

use super::Operation;

/// Complete input required for one per-secret authorization decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorizationRequest {
    caller: Caller,
    secret_id: SecretId,
    operation: Operation,
}

impl AuthorizationRequest {
    /// Creates a request without performing evaluation.
    #[must_use]
    pub const fn new(caller: Caller, secret_id: SecretId, operation: Operation) -> Self {
        Self {
            caller,
            secret_id,
            operation,
        }
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

    /// Returns the one secret covered by this decision.
    #[must_use]
    pub const fn secret_id(self) -> SecretId {
        self.secret_id
    }

    /// Returns the one operation covered by this decision.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }
}
