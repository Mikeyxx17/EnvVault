use core::{fmt, str::FromStr};

use super::Caller;

/// Authentication mechanism that established a caller identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthenticationMethod {
    /// The Vault owner was authenticated while unlocking with the master
    /// password. This proves password knowledge, not physical human presence.
    MasterPassword,
    /// An application credential verifier established the identity.
    ApplicationCredential,
    /// A restricted-agent credential verifier established the identity.
    AgentCredential,
}

impl AuthenticationMethod {
    /// Returns the stable audit serialization code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MasterPassword => "master_password",
            Self::ApplicationCredential => "application_credential",
            Self::AgentCredential => "agent_credential",
        }
    }
}

impl FromStr for AuthenticationMethod {
    type Err = AuthenticationMethodParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "master_password" => Ok(Self::MasterPassword),
            "application_credential" => Ok(Self::ApplicationCredential),
            "agent_credential" => Ok(Self::AgentCredential),
            _ => Err(AuthenticationMethodParseError),
        }
    }
}

/// Error returned for an unknown authentication-method code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticationMethodParseError;

impl fmt::Display for AuthenticationMethodParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown authentication method")
    }
}

impl std::error::Error for AuthenticationMethodParseError {}

/// Caller identity accepted by the Broker after authentication.
///
/// External callers cannot construct this token directly. An Identity provider
/// must verify evidence and then create it inside the crate's trust boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedCaller {
    caller: Caller,
    method: AuthenticationMethod,
}

impl VerifiedCaller {
    pub(crate) const fn new(caller: Caller, method: AuthenticationMethod) -> Self {
        Self { caller, method }
    }

    /// Returns the authenticated policy subject.
    #[must_use]
    pub const fn caller(&self) -> Caller {
        self.caller
    }

    /// Returns how this identity was established.
    #[must_use]
    pub const fn authentication_method(&self) -> AuthenticationMethod {
        self.method
    }
}
