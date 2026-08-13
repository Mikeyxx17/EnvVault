//! Secret request orchestration and controlled release.
//!
//! The broker obtains caller identity, requests a policy decision for every
//! secret, accesses only allowed records, and emits safe audit events.

mod error;
pub(crate) mod service;

pub use error::BrokerError;
pub use service::SecretUseResult;
