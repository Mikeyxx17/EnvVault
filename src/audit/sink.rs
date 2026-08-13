use core::fmt;

use super::AuditEvent;

/// Failure to durably accept an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditError;

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("audit event could not be recorded")
    }
}

impl std::error::Error for AuditError {}

/// Sink for safe authorization audit events.
pub trait AuditSink: Send {
    /// Records an event before an allowed operation reads Secret material.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] if the event was not accepted. The Broker fails
    /// closed and does not proceed to Secret access.
    fn record(&mut self, event: AuditEvent) -> Result<(), AuditError>;
}
