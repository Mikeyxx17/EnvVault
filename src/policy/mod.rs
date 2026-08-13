//! Authorization policy evaluation.
//!
//! Every decision is scoped to one caller, one secret, and one operation. The
//! default decision must be deny.

mod batch;
mod decision;
mod document;
mod engine;
mod operation;
mod request;
mod rule;
mod set;
mod vault_operation;
mod vault_request;
mod vault_rule;
mod vault_set;

pub use batch::PolicyEvaluation;
pub use decision::{DenyReason, PolicyDecision};
pub use document::{PolicyDocument, PolicyDocumentError};
pub use engine::{
    DenyAllPolicy, PolicyAvailability, PolicyEngine, PolicyEvaluator, VaultPolicyEvaluator,
};
pub use operation::{Operation, OperationParseError};
pub use request::AuthorizationRequest;
pub use rule::{PolicyEffect, PolicyRule};
pub use set::PolicySet;
pub use vault_operation::{VaultOperation, VaultOperationParseError};
pub use vault_request::VaultAuthorizationRequest;
pub use vault_rule::VaultPolicyRule;
pub use vault_set::VaultPolicySet;
