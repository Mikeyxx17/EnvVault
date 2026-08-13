//! Cryptographic primitives and key-derivation boundaries.
//!
//! V1 uses Argon2id key derivation and XChaCha20-Poly1305 authenticated
//! encryption behind crate-private interfaces. External callers cannot use
//! this module to bypass the future Broker authorization boundary.

mod aead;
mod digest;
mod error;
mod kdf;
mod password;
mod random;

pub(crate) use aead::{
    AuditKey, EncryptedEnvelope, KeystoreKey, MasterKey, decrypt, decrypt_audit, decrypt_keystore,
    encrypt, encrypt_audit, encrypt_keystore,
};
pub(crate) use digest::{sensitive_values_equal, sha256};
pub(crate) use error::CryptoError;
pub(crate) use kdf::{KdfConfig, KdfLimits, KdfParams, derive_key_material, derive_master_key};
pub use password::MasterPassword;
pub(crate) use random::{generate_array, generate_secret_id};
