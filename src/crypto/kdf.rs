use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::{CryptoError, MasterKey, MasterPassword};

/// Argon2id resource limits accepted from an untrusted Vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfLimits {
    pub(crate) minimum_memory_kib: u32,
    pub(crate) maximum_memory_kib: u32,
    pub(crate) minimum_iterations: u32,
    pub(crate) maximum_iterations: u32,
    pub(crate) minimum_parallelism: u32,
    pub(crate) maximum_parallelism: u32,
}

impl Default for KdfLimits {
    fn default() -> Self {
        Self {
            minimum_memory_kib: 8 * 1024,
            maximum_memory_kib: 256 * 1024,
            minimum_iterations: 1,
            maximum_iterations: 10,
            minimum_parallelism: 1,
            maximum_parallelism: 16,
        }
    }
}

/// Versioned Argon2id parameters stored in the Vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
}

impl KdfParams {
    pub(crate) const ALGORITHM: &'static str = "argon2id";
    pub(crate) const VERSION: u32 = 19;

    pub(crate) const fn recommended() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }

    pub(crate) fn validate(self, limits: KdfLimits) -> Result<(), CryptoError> {
        if !(limits.minimum_memory_kib..=limits.maximum_memory_kib).contains(&self.memory_kib)
            || !(limits.minimum_iterations..=limits.maximum_iterations).contains(&self.iterations)
            || !(limits.minimum_parallelism..=limits.maximum_parallelism)
                .contains(&self.parallelism)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }
        Ok(())
    }
}

/// Complete public KDF configuration, including the unique Vault salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfConfig {
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; Self::SALT_LENGTH],
}

impl KdfConfig {
    pub(crate) const SALT_LENGTH: usize = 16;

    pub(crate) const fn new(params: KdfParams, salt: [u8; Self::SALT_LENGTH]) -> Self {
        Self { params, salt }
    }
}

pub(crate) fn derive_master_key(
    password: &MasterPassword,
    config: KdfConfig,
    limits: KdfLimits,
) -> Result<MasterKey, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::KeyDerivationFailed);
    }
    derive_key_material(password.expose_secret(), config, limits).map(MasterKey::new)
}

pub(crate) fn derive_key_material(
    secret: &[u8],
    config: KdfConfig,
    limits: KdfLimits,
) -> Result<Zeroizing<[u8; MasterKey::LENGTH]>, CryptoError> {
    if secret.is_empty() {
        return Err(CryptoError::KeyDerivationFailed);
    }
    config.params.validate(limits)?;

    let params = Params::new(
        config.params.memory_kib,
        config.params.iterations,
        config.params.parallelism,
        Some(MasterKey::LENGTH),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; MasterKey::LENGTH]);
    argon2
        .hash_password_into(secret, &config.salt, key.as_mut())
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{KdfConfig, KdfLimits, KdfParams, derive_master_key};
    use crate::crypto::MasterPassword;

    #[test]
    fn identical_inputs_derive_identical_keys() -> Result<(), Box<dyn std::error::Error>> {
        let password = MasterPassword::new(b"test-only-password".to_vec());
        let config = KdfConfig::new(
            KdfParams {
                memory_kib: 8 * 1024,
                iterations: 1,
                parallelism: 1,
            },
            [0x33; KdfConfig::SALT_LENGTH],
        );
        let first = derive_master_key(&password, config, KdfLimits::default())?;
        let second = derive_master_key(&password, config, KdfLimits::default())?;

        assert_eq!(first.expose_secret(), second.expose_secret());
        Ok(())
    }

    #[test]
    fn rejects_resource_exhaustion_parameters() {
        let password = MasterPassword::new(b"test-only-password".to_vec());
        let config = KdfConfig::new(
            KdfParams {
                memory_kib: 256 * 1024 + 1,
                iterations: 1,
                parallelism: 1,
            },
            [0x44; KdfConfig::SALT_LENGTH],
        );

        assert!(derive_master_key(&password, config, KdfLimits::default()).is_err());
    }
}
