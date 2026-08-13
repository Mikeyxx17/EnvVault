//! `EnvVault` core library.
//!
//! The crate is organized around per-secret authorization:
//! `Caller × Secret × Operation → Policy Decision`.

#![forbid(unsafe_code)]

#[allow(
    dead_code,
    reason = "staged Audit APIs are exercised by tests and will be wired by later Phase 5 commands"
)]
pub mod audit;
#[allow(
    dead_code,
    reason = "staged Broker APIs are exercised by tests and will be wired by later Phase 5 commands"
)]
pub mod broker;
pub mod cli;
pub mod config;
#[allow(
    dead_code,
    reason = "internal Crypto APIs are exercised through staged Broker paths and tests"
)]
pub mod crypto;
pub mod dotenv;
pub mod error;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
pub mod identity;
pub mod keystore;
pub mod policy;
pub mod process;
pub mod profile;
pub mod secret;
pub(crate) mod secure_fs;
#[allow(
    dead_code,
    reason = "internal Vault APIs remain inaccessible except through staged Broker paths"
)]
pub mod vault;
