//! Audit event creation and persistence boundaries.
//!
//! Audit data may identify callers, secrets, operations, decisions, and time,
//! but must never include secret values.

mod event;
mod sink;

pub use event::AuditEvent;
pub use sink::{AuditError, AuditSink};
