/// Safe reason code for a denied policy decision.
///
/// Reasons contain no caller-supplied text or secret value and are therefore
/// suitable for structured audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    /// Secure fallback before any policy rule is evaluated.
    DefaultDeny,
    /// No grant matched the complete authorization request.
    NoMatchingGrant,
    /// A matching deny rule overrode any grants.
    ExplicitDeny,
    /// The request failed structural or contextual validation.
    InvalidRequest,
}

/// Result of evaluating one caller, one secret, and one operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use = "an authorization decision must be enforced"]
pub enum PolicyDecision {
    /// The exact request is authorized.
    Allow,
    /// The exact request is rejected for a safe, structured reason.
    Deny(DenyReason),
}

impl PolicyDecision {
    /// Returns whether this exact request was allowed.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns whether this exact request was denied.
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Returns the denial reason, or `None` for an allowed request.
    #[must_use]
    pub const fn deny_reason(self) -> Option<DenyReason> {
        match self {
            Self::Allow => None,
            Self::Deny(reason) => Some(reason),
        }
    }
}

impl Default for PolicyDecision {
    fn default() -> Self {
        Self::Deny(DenyReason::DefaultDeny)
    }
}

#[cfg(test)]
mod tests {
    use super::{DenyReason, PolicyDecision};

    #[test]
    fn defaults_to_deny() {
        let decision = PolicyDecision::default();

        assert!(decision.is_denied());
        assert!(!decision.is_allowed());
        assert_eq!(decision.deny_reason(), Some(DenyReason::DefaultDeny));
    }
}
