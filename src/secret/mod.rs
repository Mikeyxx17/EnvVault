//! Secret identifiers, records, metadata, and secret-safe value types.
//!
//! Stable identifiers, rather than mutable display names, will anchor policy
//! relationships.

mod id;
mod name;
mod record;
mod value;

pub use id::{SecretId, SecretIdParseError};
pub use name::{SecretName, SecretNameError};
pub use record::SecretRecord;
pub use value::SecretValue;
