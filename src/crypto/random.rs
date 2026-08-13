use crate::secret::SecretId;

use super::CryptoError;

pub(crate) fn generate_array<const LENGTH: usize>() -> Result<[u8; LENGTH], CryptoError> {
    let mut bytes = [0_u8; LENGTH];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomSourceUnavailable)?;
    Ok(bytes)
}

pub(crate) fn generate_secret_id() -> Result<SecretId, CryptoError> {
    generate_array().map(SecretId::from_bytes)
}
