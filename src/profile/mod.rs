//! Strict, value-free runtime Profile documents.
//!
//! A Profile maps child-process environment keys to stable Secret identifiers.
//! It describes a request set only; it never authenticates a caller or grants
//! an operation.

use core::{fmt, str::FromStr as _};
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::secret::SecretId;

const FORMAT_NAME: &str = "envvault-profile";
const FORMAT_VERSION: u32 = 1;

/// Maximum encoded Profile size accepted by the parser.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// Maximum number of environment-to-Secret bindings in one Profile.
pub const MAX_PROFILE_BINDINGS: usize = 1_024;

/// One explicit child environment key to Secret identifier binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProfileBinding {
    environment: String,
    secret_id: SecretId,
}

impl ProfileBinding {
    /// Creates a binding after validating a portable dotenv-style environment key.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::InvalidFormat`] when the environment name is not
    /// `[A-Za-z_][A-Za-z0-9_]*`.
    pub fn new(environment: impl Into<String>, secret_id: SecretId) -> Result<Self, ProfileError> {
        let environment = environment.into();
        if !is_environment_key(environment.as_bytes()) {
            return Err(ProfileError::InvalidFormat);
        }
        Ok(Self {
            environment,
            secret_id,
        })
    }

    /// Returns the exact environment key created in the child process.
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// Returns the exact Secret requested for this binding.
    #[must_use]
    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }
}

/// Versioned, value-free set of runtime Secret requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    bindings: Vec<ProfileBinding>,
}

impl Profile {
    /// Creates a strict Profile with deterministic binding order.
    ///
    /// # Errors
    ///
    /// Rejects empty Profiles, resource-limit violations, duplicate environment
    /// keys, and duplicate Secret identifiers.
    pub fn new(mut bindings: Vec<ProfileBinding>) -> Result<Self, ProfileError> {
        if bindings.is_empty() {
            return Err(ProfileError::InvalidFormat);
        }
        if bindings.len() > MAX_PROFILE_BINDINGS {
            return Err(ProfileError::ResourceLimitExceeded);
        }
        bindings.sort();
        let mut environments = BTreeSet::new();
        let mut secret_ids = BTreeSet::new();
        for binding in &bindings {
            if !environments.insert(binding.environment.clone())
                || !secret_ids.insert(binding.secret_id)
            {
                return Err(ProfileError::InvalidFormat);
            }
        }
        Ok(Self { bindings })
    }

    /// Parses a strict versioned JSON Profile.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, unknown fields or versions, non-canonical IDs,
    /// invalid environment keys, duplicates, and resource-limit violations.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::ResourceLimitExceeded);
        }
        let document: ProfileDocument =
            serde_json::from_slice(bytes).map_err(|_| ProfileError::InvalidFormat)?;
        if document.format != FORMAT_NAME {
            return Err(ProfileError::InvalidFormat);
        }
        if document.version != FORMAT_VERSION {
            return Err(ProfileError::UnsupportedVersion);
        }
        if document.bindings.len() > MAX_PROFILE_BINDINGS {
            return Err(ProfileError::ResourceLimitExceeded);
        }
        let bindings = document
            .bindings
            .into_iter()
            .map(|binding| {
                let secret_id = SecretId::from_str(&binding.secret_id)
                    .map_err(|_| ProfileError::InvalidFormat)?;
                ProfileBinding::new(binding.environment, secret_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(bindings)
    }

    /// Encodes this Profile as deterministic, value-free JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization exceeds the configured size limit.
    pub fn encode(&self) -> Result<Vec<u8>, ProfileError> {
        let document = ProfileDocument {
            format: FORMAT_NAME.to_owned(),
            version: FORMAT_VERSION,
            bindings: self
                .bindings
                .iter()
                .map(|binding| BindingDocument {
                    environment: binding.environment.clone(),
                    secret_id: binding.secret_id.to_string(),
                })
                .collect(),
        };
        let mut bytes =
            serde_json::to_vec_pretty(&document).map_err(|_| ProfileError::InvalidFormat)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::ResourceLimitExceeded);
        }
        Ok(bytes)
    }

    /// Returns bindings in deterministic environment-key order.
    #[must_use]
    pub fn bindings(&self) -> &[ProfileBinding] {
        &self.bindings
    }
}

/// Safe Profile parsing and validation failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileError {
    /// The document is malformed or violates a Profile invariant.
    InvalidFormat,
    /// The document uses a version this binary does not understand.
    UnsupportedVersion,
    /// The document exceeds configured byte or binding limits.
    ResourceLimitExceeded,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "Profile document is invalid",
            Self::UnsupportedVersion => "Profile document version is unsupported",
            Self::ResourceLimitExceeded => "Profile document exceeds resource limits",
        })
    }
}

impl std::error::Error for ProfileError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    format: String,
    version: u32,
    bindings: Vec<BindingDocument>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingDocument {
    environment: String,
    secret_id: String,
}

fn is_environment_key(bytes: &[u8]) -> bool {
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::{Profile, ProfileBinding, ProfileError};
    use crate::secret::SecretId;

    #[test]
    fn round_trips_canonically_and_sorts_bindings() -> Result<(), Box<dyn std::error::Error>> {
        let profile = Profile::new(vec![
            ProfileBinding::new("JWT_SECRET", SecretId::from_bytes([2; 16]))?,
            ProfileBinding::new("DATABASE_URL", SecretId::from_bytes([1; 16]))?,
        ])?;
        let encoded = profile.encode()?;
        let decoded = Profile::decode(&encoded)?;

        assert_eq!(decoded, profile);
        assert_eq!(decoded.bindings()[0].environment(), "DATABASE_URL");
        assert_eq!(decoded.encode()?, encoded);
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_invalid_keys_and_duplicates() {
        let unknown = br#"{
          "format":"envvault-profile","version":1,"bindings":[],"caller":"forbidden"
        }"#;
        assert_eq!(Profile::decode(unknown), Err(ProfileError::InvalidFormat));
        assert!(ProfileBinding::new("BAD-KEY", SecretId::from_bytes([1; 16])).is_err());
        assert!(
            Profile::new(vec![
                ProfileBinding::new("FIRST", SecretId::from_bytes([1; 16]))
                    .unwrap_or_else(|_| unreachable!()),
                ProfileBinding::new("SECOND", SecretId::from_bytes([1; 16]))
                    .unwrap_or_else(|_| unreachable!()),
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_and_future_profiles() {
        assert_eq!(Profile::new(Vec::new()), Err(ProfileError::InvalidFormat));
        let future = br#"{
          "format":"envvault-profile","version":2,"bindings":[
            {"environment":"TOKEN","secret_id":"11111111-1111-1111-1111-111111111111"}
          ]
        }"#;
        assert_eq!(
            Profile::decode(future),
            Err(ProfileError::UnsupportedVersion)
        );
    }
}
