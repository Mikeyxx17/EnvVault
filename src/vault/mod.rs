//! Encrypted, per-secret storage and atomic persistence.
//!
//! The vault stores independent secret records and does not treat an entire
//! `.env` file as one authorization unit.

mod anchor_cas;
mod anchor_http;
mod anchor_protocol;
mod anchor_store;
mod anchor_tls;
mod audit_anchor;
mod audit_descriptor;
mod audit_recovery;
mod audit_rotation;
mod audit_runtime;
mod audit_segment_builder;
mod audit_segment_store;
mod audit_v2;
mod error;
mod file;
mod format;
mod payload;

pub use error::VaultError;

pub(crate) use anchor_http::{AnchorHttpServer, default_listen_addr};
#[cfg(test)]
pub(crate) use anchor_store::issue_anchor_token_file;
pub(crate) use anchor_store::{configure_anchor_client, load_anchor_status};
pub(crate) use audit_runtime::AuditRuntimeV2;
pub(crate) use file::FileVault;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse(bytes: &[u8]) {
    let _result = format::parse(bytes);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_audit_segment_v2(bytes: &[u8]) {
    let _result = audit_v2::parse_segment(bytes);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_audit_anchor_v2(bytes: &[u8]) {
    let _result = audit_v2::parse_anchor(bytes);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_audit_recovery(bytes: &[u8]) {
    let _result = audit_recovery::parse(bytes);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_audit_descriptor_v2(bytes: &[u8]) {
    let _result = audit_descriptor::parse(bytes);
}
