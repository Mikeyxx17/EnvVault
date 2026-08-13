use super::{AuthorizationRequest, PolicyDecision};

/// Decision paired with the exact request that produced it.
///
/// Keeping the request attached prevents callers from applying one decision to
/// a different Secret in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyEvaluation {
    request: AuthorizationRequest,
    decision: PolicyDecision,
}

impl PolicyEvaluation {
    pub(crate) const fn new(request: AuthorizationRequest, decision: PolicyDecision) -> Self {
        Self { request, decision }
    }

    /// Returns the exact evaluated request.
    #[must_use]
    pub const fn request(self) -> AuthorizationRequest {
        self.request
    }

    /// Returns the decision for that exact request.
    pub const fn decision(self) -> PolicyDecision {
        self.decision
    }
}
