use core::fmt;

/// Validated, human-readable name of a secret.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretName(String);

impl SecretName {
    /// Maximum UTF-8 byte length accepted for a secret name.
    pub const MAX_LENGTH_BYTES: usize = 255;

    /// Validates and creates a secret name.
    ///
    /// # Errors
    ///
    /// Returns [`SecretNameError`] when the name is empty, has surrounding
    /// whitespace, contains control characters, or exceeds the length limit.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretNameError> {
        let value = value.into();

        if value.is_empty() {
            return Err(SecretNameError::Empty);
        }
        if value.trim() != value {
            return Err(SecretNameError::SurroundingWhitespace);
        }
        if value.chars().any(char::is_control) {
            return Err(SecretNameError::ControlCharacter);
        }
        if value.len() > Self::MAX_LENGTH_BYTES {
            return Err(SecretNameError::TooLong {
                actual_bytes: value.len(),
                max_bytes: Self::MAX_LENGTH_BYTES,
            });
        }

        Ok(Self(value))
    }

    /// Returns the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecretName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SecretName").field(&self.0).finish()
    }
}

impl TryFrom<&str> for SecretName {
    type Error = SecretNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for SecretName {
    type Error = SecretNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Reason a secret name failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretNameError {
    /// The name had zero bytes.
    Empty,
    /// The name started or ended with whitespace.
    SurroundingWhitespace,
    /// The name contained a control character that could corrupt output.
    ControlCharacter,
    /// The UTF-8 representation exceeded the supported limit.
    TooLong {
        /// Actual UTF-8 byte length.
        actual_bytes: usize,
        /// Maximum allowed UTF-8 byte length.
        max_bytes: usize,
    },
}

impl fmt::Display for SecretNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("secret name cannot be empty"),
            Self::SurroundingWhitespace => {
                formatter.write_str("secret name cannot have surrounding whitespace")
            }
            Self::ControlCharacter => {
                formatter.write_str("secret name cannot contain control characters")
            }
            Self::TooLong {
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "secret name is {actual_bytes} bytes; maximum is {max_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for SecretNameError {}

#[cfg(test)]
mod tests {
    use super::{SecretName, SecretNameError};

    #[test]
    fn accepts_a_regular_secret_name() {
        let name = SecretName::new("DATABASE_URL");

        assert_eq!(name.as_ref().map(SecretName::as_str), Ok("DATABASE_URL"));
    }

    #[test]
    fn rejects_names_that_can_confuse_output() {
        assert_eq!(SecretName::new(""), Err(SecretNameError::Empty));
        assert_eq!(
            SecretName::new(" DATABASE_URL"),
            Err(SecretNameError::SurroundingWhitespace)
        );
        assert_eq!(
            SecretName::new("DATABASE_URL\nFORGED_AUDIT_ENTRY"),
            Err(SecretNameError::ControlCharacter)
        );
    }

    #[test]
    fn rejects_an_overlong_name() {
        let value = "A".repeat(SecretName::MAX_LENGTH_BYTES + 1);

        assert_eq!(
            SecretName::new(value),
            Err(SecretNameError::TooLong {
                actual_bytes: SecretName::MAX_LENGTH_BYTES + 1,
                max_bytes: SecretName::MAX_LENGTH_BYTES,
            })
        );
    }
}
