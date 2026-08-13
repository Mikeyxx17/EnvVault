use core::{fmt, str::FromStr};

/// Stable, opaque identity of one independently authorized secret.
///
/// ID generation is intentionally outside this type. The future generator must
/// use a cryptographically secure random source.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretId([u8; Self::BYTE_LENGTH]);

impl SecretId {
    /// Number of bytes in a secret identifier.
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

impl fmt::Display for SecretId {
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

impl fmt::Debug for SecretId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretId({self})")
    }
}

impl FromStr for SecretId {
    type Err = SecretIdParseError;

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
            return Err(SecretIdParseError);
        }

        let mut bytes = [0_u8; Self::BYTE_LENGTH];
        let mut byte_index = 0_usize;
        let mut high_nibble = None;

        for byte in value.bytes().filter(|byte| *byte != b'-') {
            let nibble = hex_nibble(byte).ok_or(SecretIdParseError)?;
            if let Some(high) = high_nibble.take() {
                let destination = bytes.get_mut(byte_index).ok_or(SecretIdParseError)?;
                *destination = (high << 4) | nibble;
                byte_index = byte_index.checked_add(1).ok_or(SecretIdParseError)?;
            } else {
                high_nibble = Some(nibble);
            }
        }

        if byte_index != Self::BYTE_LENGTH || high_nibble.is_some() {
            return Err(SecretIdParseError);
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

/// Error returned when a secret identifier is not canonical hexadecimal text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretIdParseError;

impl fmt::Display for SecretIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid secret identifier")
    }
}

impl std::error::Error for SecretIdParseError {}

#[cfg(test)]
mod tests {
    use super::SecretId;

    #[test]
    fn formats_as_a_stable_hyphenated_identifier() {
        let id = SecretId::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);

        assert_eq!(id.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn round_trips_canonical_bytes() {
        let bytes = [0x5a; SecretId::BYTE_LENGTH];
        let id = SecretId::from_bytes(bytes);

        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
    }

    #[test]
    fn parses_the_canonical_display_form() -> Result<(), Box<dyn std::error::Error>> {
        let expected = SecretId::from_bytes([0xab; SecretId::BYTE_LENGTH]);
        let parsed: SecretId = expected.to_string().parse()?;

        assert_eq!(parsed, expected);
        assert!(
            "abababababababababababababababab"
                .parse::<SecretId>()
                .is_err()
        );
        Ok(())
    }
}
