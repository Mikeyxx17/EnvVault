use core::{fmt, str::FromStr};

/// Stable, opaque identity of a caller.
///
/// Possession of this value is not authentication proof. The Identity boundary
/// must verify a caller before the Broker creates an authorization request.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallerId([u8; Self::BYTE_LENGTH]);

impl CallerId {
    /// Number of bytes in a caller identifier.
    pub const BYTE_LENGTH: usize = 16;

    /// Creates an identifier from its canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::BYTE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns a reference to the canonical bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LENGTH] {
        &self.0
    }

    /// Consumes the identifier and returns its canonical bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; Self::BYTE_LENGTH] {
        self.0
    }
}

impl fmt::Display for CallerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for CallerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CallerId({self})")
    }
}

impl FromStr for CallerId {
    type Err = CallerIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 36
            || !value.as_bytes().iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return Err(CallerIdParseError);
        }

        let mut bytes = [0_u8; Self::BYTE_LENGTH];
        let mut byte_index = 0_usize;
        let mut high_nibble = None;

        for byte in value.bytes().filter(|byte| *byte != b'-') {
            let nibble = hex_nibble(byte).ok_or(CallerIdParseError)?;
            if let Some(high) = high_nibble.take() {
                let destination = bytes.get_mut(byte_index).ok_or(CallerIdParseError)?;
                *destination = (high << 4) | nibble;
                byte_index = byte_index.checked_add(1).ok_or(CallerIdParseError)?;
            } else {
                high_nibble = Some(nibble);
            }
        }

        if byte_index != Self::BYTE_LENGTH || high_nibble.is_some() {
            return Err(CallerIdParseError);
        }

        Ok(Self(bytes))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Error returned when a caller identifier is not canonical hexadecimal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerIdParseError;

impl fmt::Display for CallerIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid caller identifier")
    }
}

impl std::error::Error for CallerIdParseError {}

/// Broad caller category supplied to policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CallerKind {
    /// A directly authenticated human operator.
    Human,
    /// A locally executing application.
    Application,
    /// An AI coding or automation agent.
    AiAgent,
}

impl fmt::Display for CallerKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl CallerKind {
    /// Returns the stable policy and audit serialization code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Application => "application",
            Self::AiAgent => "ai_agent",
        }
    }
}

impl FromStr for CallerKind {
    type Err = CallerKindParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "human" => Ok(Self::Human),
            "application" => Ok(Self::Application),
            "ai_agent" => Ok(Self::AiAgent),
            _ => Err(CallerKindParseError),
        }
    }
}

/// Error returned for an unknown caller-kind code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerKindParseError;

impl fmt::Display for CallerKindParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown caller kind")
    }
}

impl std::error::Error for CallerKindParseError {}

/// Caller information used as policy input after identity verification.
///
/// The type stores identity data only; constructing it does not perform
/// authentication and does not grant any operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Caller {
    id: CallerId,
    kind: CallerKind,
}

impl Caller {
    /// Creates caller data from an identifier and category.
    #[must_use]
    pub const fn new(id: CallerId, kind: CallerKind) -> Self {
        Self { id, kind }
    }

    /// Returns the stable caller identifier.
    #[must_use]
    pub const fn id(self) -> CallerId {
        self.id
    }

    /// Returns the caller category.
    #[must_use]
    pub const fn kind(self) -> CallerKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use super::{Caller, CallerId, CallerKind};

    #[test]
    fn keeps_id_and_kind_as_separate_policy_inputs() {
        let id = CallerId::from_bytes([0x24; CallerId::BYTE_LENGTH]);
        let caller = Caller::new(id, CallerKind::AiAgent);

        assert_eq!(caller.id(), id);
        assert_eq!(caller.kind(), CallerKind::AiAgent);
        assert_eq!(caller.kind().to_string(), "ai_agent");
    }

    #[test]
    fn caller_kind_codes_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        for kind in [
            CallerKind::Human,
            CallerKind::Application,
            CallerKind::AiAgent,
        ] {
            assert_eq!(kind.as_str().parse::<CallerKind>()?, kind);
        }
        assert!("agent".parse::<CallerKind>().is_err());
        Ok(())
    }

    #[test]
    fn parses_the_canonical_display_form() -> Result<(), Box<dyn std::error::Error>> {
        let expected = CallerId::from_bytes([0xcd; CallerId::BYTE_LENGTH]);
        let parsed: CallerId = expected.to_string().parse()?;

        assert_eq!(parsed, expected);
        assert!(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                .parse::<CallerId>()
                .is_err()
        );
        Ok(())
    }
}
