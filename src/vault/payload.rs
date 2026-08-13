use zeroize::Zeroizing;

use crate::secret::{SecretName, SecretValue};

use super::VaultError;

pub(super) const MAX_SECRET_VALUE_BYTES: usize = 1024 * 1024;

const PAYLOAD_VERSION: u8 = 1;
const METADATA_MAGIC: &[u8; 4] = b"EVSM";
const VALUE_MAGIC: &[u8; 4] = b"EVSV";

pub(super) fn encode_metadata(name: &SecretName) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let name_bytes = name.as_str().as_bytes();
    let name_length = u16::try_from(name_bytes.len()).map_err(|_| VaultError::InvalidFormat)?;
    let capacity = 7_usize
        .checked_add(name_bytes.len())
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
    payload.extend_from_slice(METADATA_MAGIC);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&name_length.to_be_bytes());
    payload.extend_from_slice(name_bytes);
    Ok(payload)
}

pub(super) fn decode_metadata(payload: &[u8]) -> Result<SecretName, VaultError> {
    if payload.len() < 7 || payload.get(..4) != Some(METADATA_MAGIC.as_slice()) {
        return Err(VaultError::InvalidFormat);
    }
    if payload.get(4).copied() != Some(PAYLOAD_VERSION) {
        return Err(VaultError::UnsupportedVersion);
    }
    let length_bytes: [u8; 2] = payload
        .get(5..7)
        .ok_or(VaultError::InvalidFormat)?
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    let name_length = usize::from(u16::from_be_bytes(length_bytes));
    let expected_length = 7_usize
        .checked_add(name_length)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    if payload.len() != expected_length {
        return Err(VaultError::InvalidFormat);
    }
    let name = core::str::from_utf8(payload.get(7..).ok_or(VaultError::InvalidFormat)?)
        .map_err(|_| VaultError::InvalidFormat)?;
    SecretName::new(name).map_err(|_| VaultError::InvalidFormat)
}

pub(super) fn encode_value(value: &SecretValue) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if value.len() > MAX_SECRET_VALUE_BYTES {
        return Err(VaultError::SecretValueTooLarge);
    }
    let value_length = u32::try_from(value.len()).map_err(|_| VaultError::SecretValueTooLarge)?;
    let capacity = 9_usize
        .checked_add(value.len())
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
    payload.extend_from_slice(VALUE_MAGIC);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&value_length.to_be_bytes());
    payload.extend_from_slice(value.expose_secret());
    Ok(payload)
}

pub(super) fn decode_value(payload: &[u8]) -> Result<SecretValue, VaultError> {
    if payload.len() < 9 || payload.get(..4) != Some(VALUE_MAGIC.as_slice()) {
        return Err(VaultError::InvalidFormat);
    }
    if payload.get(4).copied() != Some(PAYLOAD_VERSION) {
        return Err(VaultError::UnsupportedVersion);
    }
    let length_bytes: [u8; 4] = payload
        .get(5..9)
        .ok_or(VaultError::InvalidFormat)?
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)?;
    let value_length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| VaultError::ResourceLimitExceeded)?;
    if value_length > MAX_SECRET_VALUE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let expected_length = 9_usize
        .checked_add(value_length)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    if payload.len() != expected_length {
        return Err(VaultError::InvalidFormat);
    }

    let value = payload.get(9..).ok_or(VaultError::InvalidFormat)?.to_vec();
    Ok(SecretValue::new(value))
}

#[cfg(test)]
mod tests {
    use super::{decode_metadata, decode_value, encode_metadata, encode_value};
    use crate::secret::{SecretName, SecretValue};

    #[test]
    fn metadata_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let name = SecretName::new("DATABASE_URL")?;
        let encoded = encode_metadata(&name)?;
        let decoded = decode_metadata(&encoded)?;

        assert_eq!(decoded, name);
        Ok(())
    }

    #[test]
    fn value_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let value = SecretValue::new(b"test-only-value".to_vec());
        let encoded = encode_value(&value)?;
        let decoded = decode_value(&encoded)?;

        assert_eq!(decoded.expose_secret(), value.expose_secret());
        Ok(())
    }

    #[test]
    fn rejects_trailing_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let name = SecretName::new("DATABASE_URL")?;
        let mut encoded = encode_metadata(&name)?;
        encoded.push(0);

        assert!(decode_metadata(&encoded).is_err());
        Ok(())
    }
}
