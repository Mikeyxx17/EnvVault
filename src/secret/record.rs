use super::{SecretId, SecretName};

/// Non-secret domain record used by authorization and audit paths.
///
/// The record deliberately contains neither plaintext nor encrypted payload.
/// Vault persistence will bind this metadata to a separate encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    id: SecretId,
    name: SecretName,
}

impl SecretRecord {
    /// Creates a record from its stable identifier and validated name.
    #[must_use]
    pub const fn new(id: SecretId, name: SecretName) -> Self {
        Self { id, name }
    }

    /// Returns the stable identifier used by Policy and Audit.
    #[must_use]
    pub const fn id(&self) -> SecretId {
        self.id
    }

    /// Returns the human-readable, mutable-in-future name.
    #[must_use]
    pub const fn name(&self) -> &SecretName {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::SecretRecord;
    use crate::secret::{SecretId, SecretName};

    #[test]
    fn record_keeps_identity_separate_from_name() {
        let id = SecretId::from_bytes([0x42; SecretId::BYTE_LENGTH]);
        let name_result = SecretName::new("OPENAI_API_KEY");
        assert!(name_result.is_ok());

        let record = name_result.map(|name| SecretRecord::new(id, name));

        assert_eq!(record.as_ref().map(SecretRecord::id), Ok(id));
        assert_eq!(
            record.as_ref().map(|value| value.name().as_str()),
            Ok("OPENAI_API_KEY")
        );
    }
}
