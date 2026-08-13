use core::{fmt, str::FromStr};

/// Operation targeting the Vault control plane rather than one Secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum VaultOperation {
    /// Create a new independently authorized Secret record.
    CreateSecret,
    /// Change authenticated Secret or Vault policy rules.
    ManagePolicy,
    /// Register, revoke, or recover caller identities.
    ManageIdentity,
    /// Read safe Audit metadata through an approved interface.
    ReadAudit,
    /// Enable, rotate, inspect, or disable platform-keystore machine unlock.
    ManageKeystore,
}

impl VaultOperation {
    /// Returns the stable policy and audit serialization code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateSecret => "create_secret",
            Self::ManagePolicy => "manage_policy",
            Self::ManageIdentity => "manage_identity",
            Self::ReadAudit => "read_audit",
            Self::ManageKeystore => "manage_keystore",
        }
    }
}

impl FromStr for VaultOperation {
    type Err = VaultOperationParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "create_secret" => Ok(Self::CreateSecret),
            "manage_policy" => Ok(Self::ManagePolicy),
            "manage_identity" => Ok(Self::ManageIdentity),
            "read_audit" => Ok(Self::ReadAudit),
            "manage_keystore" => Ok(Self::ManageKeystore),
            _ => Err(VaultOperationParseError),
        }
    }
}

impl fmt::Display for VaultOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned for an unknown Vault operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultOperationParseError;

impl fmt::Display for VaultOperationParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown Vault policy operation")
    }
}

impl std::error::Error for VaultOperationParseError {}
