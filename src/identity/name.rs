use core::fmt;

/// Human-readable caller label used only for management and audit UX.
///
/// Policy matching always uses [`super::CallerId`], never this mutable label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallerName(String);

impl CallerName {
    /// Maximum UTF-8 encoded length.
    pub const MAX_BYTES: usize = 128;

    /// Validates and creates a caller label.
    ///
    /// # Errors
    ///
    /// Rejects empty, surrounding-whitespace, control-character, or oversized
    /// labels.
    pub fn new(value: impl Into<String>) -> Result<Self, CallerNameError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > Self::MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CallerNameError);
        }
        Ok(Self(value))
    }

    /// Returns the validated label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Safe caller-label validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerNameError;

impl fmt::Display for CallerNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid caller name")
    }
}

impl std::error::Error for CallerNameError {}
