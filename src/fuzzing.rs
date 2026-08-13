//! Parser-only entrypoints used by the separate `cargo-fuzz` package.
//!
//! This module is excluded from normal builds. Its functions deliberately
//! discard parsed values so internal persistence types remain private.

use crate::{
    audit::AuditEvent, dotenv, identity::IdentityRegistryDocument, policy::PolicyDocument,
    profile::Profile, vault,
};

/// Exercises the strict Vault file parser.
pub fn parse_vault(bytes: &[u8]) {
    vault::fuzz_parse(bytes);
}

/// Exercises the strict Identity Registry parser.
pub fn parse_identity_registry(bytes: &[u8]) {
    let _result = IdentityRegistryDocument::decode(bytes);
}

/// Exercises the strict Policy document parser.
pub fn parse_policy(bytes: &[u8]) {
    let _result = PolicyDocument::decode(bytes);
}

/// Exercises the strict value-free Profile parser.
pub fn parse_profile(bytes: &[u8]) {
    let _result = Profile::decode(bytes);
}

/// Exercises the bounded authenticated Audit Event parser.
pub fn parse_audit_event(bytes: &[u8]) {
    let _result = AuditEvent::decode(bytes);
}

/// Exercises the strict Audit V2 sealed-segment parser.
pub fn parse_audit_segment_v2(bytes: &[u8]) {
    vault::fuzz_parse_audit_segment_v2(bytes);
}

/// Exercises the strict Audit V2 external-anchor parser.
pub fn parse_audit_anchor_v2(bytes: &[u8]) {
    vault::fuzz_parse_audit_anchor_v2(bytes);
}

/// Exercises the strict Audit rotation recovery-manifest parser.
pub fn parse_audit_recovery(bytes: &[u8]) {
    vault::fuzz_parse_audit_recovery(bytes);
}

/// Exercises the strict Audit V2 Vault-descriptor parser.
pub fn parse_audit_descriptor_v2(bytes: &[u8]) {
    vault::fuzz_parse_audit_descriptor_v2(bytes);
}

/// Exercises the strict dotenv migration parser.
pub fn parse_dotenv(bytes: &[u8]) {
    let _result = dotenv::parse(bytes);
}
