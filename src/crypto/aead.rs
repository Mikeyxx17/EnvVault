use core::fmt;

use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

use super::{CryptoError, generate_array};

/// Master encryption key, zeroized when dropped.
pub(crate) struct MasterKey(Zeroizing<[u8; Self::LENGTH]>);

impl MasterKey {
    pub(crate) const LENGTH: usize = 32;

    pub(crate) const fn new(bytes: Zeroizing<[u8; Self::LENGTH]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose_secret(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Independent key used only for the authenticated Audit event chain.
pub(crate) struct AuditKey(Zeroizing<[u8; Self::LENGTH]>);

impl AuditKey {
    pub(crate) const LENGTH: usize = 32;

    pub(crate) const fn new(bytes: Zeroizing<[u8; Self::LENGTH]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose_secret(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Independent wrapping key stored only in an operating-system credential store.
pub(crate) struct KeystoreKey(Zeroizing<[u8; Self::LENGTH]>);

impl KeystoreKey {
    pub(crate) const LENGTH: usize = 32;

    pub(crate) const fn new(bytes: Zeroizing<[u8; Self::LENGTH]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn expose_secret(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// XChaCha20-Poly1305 encrypted bytes and their unique nonce.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct EncryptedEnvelope {
    pub(crate) nonce: [u8; Self::NONCE_LENGTH],
    pub(crate) ciphertext: Vec<u8>,
}

impl fmt::Debug for EncryptedEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedEnvelope")
            .field("nonce", &"<redacted>")
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

impl EncryptedEnvelope {
    pub(crate) const NONCE_LENGTH: usize = 24;
    pub(crate) const TAG_LENGTH: usize = 16;
}

pub(crate) fn encrypt(
    key: &MasterKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    encrypt_with_key(key.expose_secret(), plaintext, aad)
}

pub(crate) fn encrypt_audit(
    key: &AuditKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    encrypt_with_key(key.expose_secret(), plaintext, aad)
}

pub(crate) fn encrypt_keystore(
    key: &KeystoreKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    encrypt_with_key(key.expose_secret(), plaintext, aad)
}

fn encrypt_with_key(
    key: &[u8; MasterKey::LENGTH],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedEnvelope, CryptoError> {
    let nonce = generate_array()?;
    let key_array: &Key = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let nonce_array: &XNonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let cipher = XChaCha20Poly1305::new(key_array);
    let ciphertext = cipher
        .encrypt(
            nonce_array,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EncryptedEnvelope { nonce, ciphertext })
}

pub(crate) fn decrypt(
    key: &MasterKey,
    envelope: &EncryptedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decrypt_with_key(key.expose_secret(), envelope, aad)
}

pub(crate) fn decrypt_audit(
    key: &AuditKey,
    envelope: &EncryptedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decrypt_with_key(key.expose_secret(), envelope, aad)
}

pub(crate) fn decrypt_keystore(
    key: &KeystoreKey,
    envelope: &EncryptedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decrypt_with_key(key.expose_secret(), envelope, aad)
}

fn decrypt_with_key(
    key: &[u8; MasterKey::LENGTH],
    envelope: &EncryptedEnvelope,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.ciphertext.len() < EncryptedEnvelope::TAG_LENGTH {
        return Err(CryptoError::AuthenticationFailed);
    }
    let key_array: &Key = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let nonce_array: &XNonce = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let cipher = XChaCha20Poly1305::new(key_array);
    cipher
        .decrypt(
            nonce_array,
            Payload {
                msg: &envelope.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::{MasterKey, decrypt, encrypt};
    use zeroize::Zeroizing;

    #[test]
    fn round_trip_requires_matching_aad() -> Result<(), Box<dyn std::error::Error>> {
        let key = MasterKey::new(Zeroizing::new([0x55; MasterKey::LENGTH]));
        let envelope = encrypt(&key, b"test-only-plaintext", b"record-a")?;
        let plaintext = decrypt(&key, &envelope, b"record-a")?;

        assert_eq!(plaintext.as_slice(), b"test-only-plaintext");
        assert!(decrypt(&key, &envelope, b"record-b").is_err());
        Ok(())
    }

    #[test]
    fn independent_encryptions_receive_distinct_nonces() -> Result<(), Box<dyn std::error::Error>> {
        let key = MasterKey::new(Zeroizing::new([0x66; MasterKey::LENGTH]));
        let first = encrypt(&key, b"same", b"same-aad")?;
        let second = encrypt(&key, b"same", b"same-aad")?;

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        Ok(())
    }

    #[test]
    fn detects_modified_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
        let key = MasterKey::new(Zeroizing::new([0x77; MasterKey::LENGTH]));
        let mut envelope = encrypt(&key, b"test-only-plaintext", b"aad")?;
        if let Some(byte) = envelope.ciphertext.first_mut() {
            *byte ^= 1;
        }

        assert!(decrypt(&key, &envelope, b"aad").is_err());
        Ok(())
    }
}
