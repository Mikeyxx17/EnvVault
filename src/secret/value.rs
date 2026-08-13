use zeroize::Zeroizing;

/// Plaintext secret bytes with zeroization on drop.
///
/// This type deliberately implements neither `Clone`, `Debug`, `Display`, nor
/// serialization. Calling [`SecretValue::expose_secret`] is an explicit
/// acknowledgement that the returned bytes are sensitive.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Creates a protected value from owned bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes the plaintext bytes to an authorized consumer.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the length of the plaintext in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the plaintext has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecretValue {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretValue;

    #[test]
    fn requires_explicit_exposure() {
        let value = SecretValue::new(b"test-only-secret".to_vec());

        assert_eq!(value.len(), 16);
        assert!(!value.is_empty());
        assert_eq!(value.expose_secret(), b"test-only-secret");
    }
}
