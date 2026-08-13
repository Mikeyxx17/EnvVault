use core::fmt;
use std::io;

use crate::secret::SecretId;

/// Non-sensitive Vault failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// The requested Vault or Secret already exists.
    AlreadyExists,
    /// The requested Vault or Secret does not exist.
    NotFound,
    /// The file changed after it was opened and was not overwritten.
    ConcurrentModification,
    /// The file is malformed or violates a format invariant.
    InvalidFormat,
    /// The file uses a format version this build does not support.
    UnsupportedVersion,
    /// The file requests more resources than the reader permits.
    ResourceLimitExceeded,
    /// The password was incorrect or the key-check data failed authentication.
    UnlockFailed,
    /// One independently encrypted Secret failed authentication or decoding.
    CorruptedSecret(SecretId),
    /// The authenticated Policy payload failed authentication or decoding.
    CorruptedPolicy,
    /// The authenticated Identity Registry failed authentication or decoding.
    CorruptedIdentity,
    /// The authenticated Audit key or event chain failed verification.
    CorruptedAudit,
    /// A mandatory Audit anchor could not be confirmed.
    AuditAnchorDegraded,
    /// The Policy generation did not match the expected update baseline.
    PolicyGenerationMismatch,
    /// The Identity Registry generation did not match the update baseline.
    IdentityGenerationMismatch,
    /// The Policy payload exceeds the V1 size limit.
    PolicyPayloadTooLarge,
    /// The owner Identity payload exceeds the V1 size limit.
    IdentityPayloadTooLarge,
    /// One Audit event exceeds the V1 size limit.
    AuditPayloadTooLarge,
    /// The provided Secret Value exceeds the V1 size limit.
    SecretValueTooLarge,
    /// Secure randomness was unavailable.
    RandomSourceUnavailable,
    /// Key derivation failed without exposing password or key material.
    KeyDerivationFailed,
    /// Authenticated encryption failed.
    EncryptionFailed,
    /// A filesystem operation failed.
    Io(io::ErrorKind),
    /// The target path is unsafe for Vault persistence.
    UnsafePath,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("the requested item already exists"),
            Self::NotFound => formatter.write_str("the requested item was not found"),
            Self::ConcurrentModification => {
                formatter.write_str("the Vault changed since it was opened")
            }
            Self::InvalidFormat => formatter.write_str("the Vault format is invalid"),
            Self::UnsupportedVersion => formatter.write_str("the Vault version is unsupported"),
            Self::ResourceLimitExceeded => {
                formatter.write_str("the Vault exceeds configured resource limits")
            }
            Self::UnlockFailed => formatter.write_str("the Vault could not be unlocked"),
            Self::CorruptedSecret(id) => write!(formatter, "Secret {id} is corrupted"),
            Self::CorruptedPolicy => formatter.write_str("the Policy payload is corrupted"),
            Self::CorruptedIdentity => formatter.write_str("the Identity Registry is corrupted"),
            Self::CorruptedAudit => formatter.write_str("the Audit chain is corrupted"),
            Self::AuditAnchorDegraded => {
                formatter.write_str("the mandatory Audit anchor is degraded")
            }
            Self::PolicyGenerationMismatch => {
                formatter.write_str("the Policy generation does not match")
            }
            Self::IdentityGenerationMismatch => {
                formatter.write_str("the Identity generation does not match")
            }
            Self::PolicyPayloadTooLarge => formatter.write_str("the Policy payload is too large"),
            Self::IdentityPayloadTooLarge => {
                formatter.write_str("the Identity Registry payload is too large")
            }
            Self::AuditPayloadTooLarge => formatter.write_str("the Audit event is too large"),
            Self::SecretValueTooLarge => formatter.write_str("the Secret Value is too large"),
            Self::RandomSourceUnavailable => {
                formatter.write_str("secure randomness is unavailable")
            }
            Self::KeyDerivationFailed => formatter.write_str("key derivation failed"),
            Self::EncryptionFailed => formatter.write_str("Secret encryption failed"),
            Self::Io(kind) => write!(formatter, "Vault filesystem operation failed: {kind:?}"),
            Self::UnsafePath => formatter.write_str("the Vault path is unsafe"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
