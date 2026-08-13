//! Caller identity and authentication boundaries.
//!
//! Human, application, and AI-agent callers require explicit identities.
//! Authentication alone never grants vault-wide authorization.

mod caller;
mod credential;
mod name;
mod registry;
mod throttle;
mod verified;

pub use caller::{Caller, CallerId, CallerIdParseError, CallerKind, CallerKindParseError};
pub use credential::{CallerCredential, IssuedCallerCredential};
pub use name::{CallerName, CallerNameError};
pub use registry::RegisteredCaller;
pub(crate) use registry::{
    CredentialVerifier, DEFAULT_CREDENTIAL_LIFETIME_MILLIS, IdentityRegistryDocument,
};
pub(crate) use throttle::AuthenticationDisposition;
pub use verified::{AuthenticationMethod, AuthenticationMethodParseError, VerifiedCaller};
