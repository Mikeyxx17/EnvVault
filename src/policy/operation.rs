use core::{fmt, str::FromStr};

/// Operation a caller requests against one secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Operation {
    /// Discover the secret in a filtered name listing.
    List,
    /// Learn whether the secret exists.
    Exists,
    /// Compare a supplied value without revealing the stored plaintext.
    Verify,
    /// Consume the secret through an approved runtime path.
    Use,
    /// Receive the secret's plaintext value directly.
    ReadPlaintext,
    /// Create or replace the secret value.
    Write,
    /// Delete the secret record.
    Delete,
    /// Export the secret outside normal runtime consumption.
    Export,
    /// Replace the value as an explicit rotation operation.
    Rotate,
    /// Change authorization rules that target this secret.
    ManagePolicy,
}

impl Operation {
    /// Returns the stable code intended for policy and audit serialization.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Exists => "exists",
            Self::Verify => "verify",
            Self::Use => "use",
            Self::ReadPlaintext => "read_plaintext",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Export => "export",
            Self::Rotate => "rotate",
            Self::ManagePolicy => "manage_policy",
        }
    }
}

impl FromStr for Operation {
    type Err = OperationParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "list" => Ok(Self::List),
            "exists" => Ok(Self::Exists),
            "verify" => Ok(Self::Verify),
            "use" => Ok(Self::Use),
            "read_plaintext" => Ok(Self::ReadPlaintext),
            "write" => Ok(Self::Write),
            "delete" => Ok(Self::Delete),
            "export" => Ok(Self::Export),
            "rotate" => Ok(Self::Rotate),
            "manage_policy" => Ok(Self::ManagePolicy),
            _ => Err(OperationParseError),
        }
    }
}

/// Error returned for an unknown operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationParseError;

impl fmt::Display for OperationParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown policy operation")
    }
}

impl std::error::Error for OperationParseError {}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Operation;

    #[test]
    fn use_and_plaintext_read_have_distinct_codes() {
        assert_eq!(Operation::Use.as_str(), "use");
        assert_eq!(Operation::ReadPlaintext.as_str(), "read_plaintext");
        assert_ne!(Operation::Use, Operation::ReadPlaintext);
    }

    #[test]
    fn stable_codes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let operations = [
            Operation::List,
            Operation::Exists,
            Operation::Verify,
            Operation::Use,
            Operation::ReadPlaintext,
            Operation::Write,
            Operation::Delete,
            Operation::Export,
            Operation::Rotate,
            Operation::ManagePolicy,
        ];

        for operation in operations {
            assert_eq!(operation.as_str().parse::<Operation>()?, operation);
        }
        assert!("read".parse::<Operation>().is_err());
        Ok(())
    }
}
