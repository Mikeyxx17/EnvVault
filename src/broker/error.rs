use core::fmt;

use crate::{keystore::KeystoreError, policy::DenyReason, vault::VaultError};

/// Non-sensitive Broker failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerError {
    /// Policy rejected the exact request.
    AccessDenied(DenyReason),
    /// The Audit sink failed before Secret access and the operation stopped.
    AuditUnavailable,
    /// Explicit Audit V1 to V2 migration was invalid or already completed.
    AuditMigrationInvalid,
    /// Owner identity bootstrap or authenticated identity loading failed.
    IdentityUnavailable,
    /// A proposed Policy document violated format or resource invariants.
    PolicyUpdateInvalid,
    /// A proposed Identity Registry change violated an invariant.
    IdentityUpdateInvalid,
    /// The underlying encrypted Vault operation failed.
    Vault(VaultError),
    /// Platform machine-unlock setup or credential access failed.
    Keystore(KeystoreError),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied(reason) => write!(formatter, "access denied: {reason:?}"),
            Self::AuditUnavailable => formatter.write_str("audit service is unavailable"),
            Self::AuditMigrationInvalid => {
                formatter.write_str("Audit V2 migration is invalid or already completed")
            }
            Self::IdentityUnavailable => formatter.write_str("caller identity is unavailable"),
            Self::PolicyUpdateInvalid => formatter.write_str("the Policy update is invalid"),
            Self::IdentityUpdateInvalid => {
                formatter.write_str("the Identity Registry update is invalid")
            }
            Self::Vault(error) => write!(formatter, "Vault operation failed: {error}"),
            Self::Keystore(error) => write!(formatter, "Keystore operation failed: {error}"),
        }
    }
}

impl std::error::Error for BrokerError {}

impl From<VaultError> for BrokerError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl From<KeystoreError> for BrokerError {
    fn from(error: KeystoreError) -> Self {
        Self::Keystore(error)
    }
}
