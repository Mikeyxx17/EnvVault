use core::fmt;

/// Non-sensitive cryptographic failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoError {
    /// The operating system could not provide secure random bytes.
    RandomSourceUnavailable,
    /// Stored or requested KDF parameters are outside accepted limits.
    InvalidKdfParameters,
    /// Argon2id key derivation failed.
    KeyDerivationFailed,
    /// Authenticated encryption failed.
    EncryptionFailed,
    /// Authentication or decryption failed.
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomSourceUnavailable => "secure random source is unavailable",
            Self::InvalidKdfParameters => "KDF parameters are invalid",
            Self::KeyDerivationFailed => "key derivation failed",
            Self::EncryptionFailed => "authenticated encryption failed",
            Self::AuthenticationFailed => "authentication failed",
        })
    }
}

impl std::error::Error for CryptoError {}
