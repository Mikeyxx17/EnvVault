//! Strict `.env` migration parsing and value-free example generation.
//!
//! This adapter never treats one `.env` file as a Vault authorization unit.
//! Each parsed key and value becomes an independent Secret input.

use core::fmt;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

use crate::secret::{SecretName, SecretValue};

/// Maximum accepted source size for one import.
pub const MAX_DOTENV_BYTES: usize = 1024 * 1024;
/// Maximum number of entries accepted in one import.
pub const MAX_DOTENV_ENTRIES: usize = 1024;

/// One independently managed Secret parsed from a dotenv source.
///
/// This type deliberately implements neither `Debug` nor `Clone` because it
/// owns plaintext Secret Value material.
pub struct DotenvEntry {
    name: SecretName,
    value: SecretValue,
}

impl DotenvEntry {
    /// Returns the validated dotenv key as a Secret Name.
    #[must_use]
    pub const fn name(&self) -> &SecretName {
        &self.name
    }

    /// Consumes the entry into independently managed Secret fields.
    #[must_use]
    pub fn into_parts(self) -> (SecretName, SecretValue) {
        (self.name, self.value)
    }
}

/// Parses a strict, non-expanding dotenv document.
///
/// # Errors
///
/// Rejects invalid UTF-8, resource-limit violations, duplicate or invalid
/// keys, malformed quoting, unsupported escapes, NUL bytes, and trailing
/// non-comment data after quoted values.
pub fn parse(source: &[u8]) -> Result<Vec<DotenvEntry>, DotenvError> {
    if source.len() > MAX_DOTENV_BYTES {
        return Err(DotenvError::new(None, DotenvErrorKind::ResourceLimit));
    }
    let source = std::str::from_utf8(source)
        .map_err(|_| DotenvError::new(None, DotenvErrorKind::InvalidUtf8))?;
    let source = source.strip_prefix('\u{feff}').unwrap_or(source);
    if source.contains('\0') {
        return Err(DotenvError::new(None, DotenvErrorKind::NulByte));
    }
    if source.as_bytes().iter().enumerate().any(|(index, byte)| {
        (*byte == b'\r' && source.as_bytes().get(index + 1) != Some(&b'\n'))
            || (*byte < 0x20 && !matches!(*byte, b'\n' | b'\r' | b'\t'))
    }) {
        return Err(DotenvError::new(None, DotenvErrorKind::InvalidControl));
    }

    let mut entries = Vec::new();
    let mut keys = BTreeSet::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if entries.len() >= MAX_DOTENV_ENTRIES {
            return Err(DotenvError::new(
                Some(line_number),
                DotenvErrorKind::ResourceLimit,
            ));
        }

        let assignment = line.strip_prefix("export ").unwrap_or(line);
        let (raw_key, raw_value) = assignment.split_once('=').ok_or_else(|| {
            DotenvError::new(Some(line_number), DotenvErrorKind::MissingAssignment)
        })?;
        let key = raw_key.trim();
        if !is_valid_key(key) {
            return Err(DotenvError::new(
                Some(line_number),
                DotenvErrorKind::InvalidKey,
            ));
        }
        if !keys.insert(key.to_owned()) {
            return Err(DotenvError::new(
                Some(line_number),
                DotenvErrorKind::DuplicateKey,
            ));
        }
        let value = parse_value(raw_value.trim_start(), line_number)?;
        entries.push(DotenvEntry {
            name: SecretName::new(key)
                .map_err(|_| DotenvError::new(Some(line_number), DotenvErrorKind::InvalidKey))?,
            value: SecretValue::new(value.as_bytes().to_vec()),
        });
    }
    Ok(entries)
}

/// Renders sorted dotenv keys with empty values and no Secret material.
///
/// # Errors
///
/// Rejects names that are not valid dotenv keys or duplicate names.
pub fn render_example<'a>(
    names: impl IntoIterator<Item = &'a SecretName>,
) -> Result<Vec<u8>, DotenvError> {
    let mut keys = BTreeSet::new();
    for name in names {
        if !is_valid_key(name.as_str()) {
            return Err(DotenvError::new(None, DotenvErrorKind::InvalidKey));
        }
        if !keys.insert(name.as_str()) {
            return Err(DotenvError::new(None, DotenvErrorKind::DuplicateKey));
        }
    }
    let mut output = Vec::new();
    for key in keys {
        output.extend_from_slice(key.as_bytes());
        output.extend_from_slice(b"=\n");
    }
    Ok(output)
}

fn is_valid_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn parse_value(value: &str, line: usize) -> Result<Zeroizing<String>, DotenvError> {
    match value.as_bytes().first().copied() {
        Some(b'\'') => parse_single_quoted(value, line),
        Some(b'"') => parse_double_quoted(value, line),
        _ => Ok(Zeroizing::new(parse_unquoted(value).to_owned())),
    }
}

fn parse_single_quoted(value: &str, line: usize) -> Result<Zeroizing<String>, DotenvError> {
    let remainder = value
        .strip_prefix('\'')
        .ok_or_else(|| DotenvError::new(Some(line), DotenvErrorKind::MalformedQuote))?;
    let end = remainder
        .find('\'')
        .ok_or_else(|| DotenvError::new(Some(line), DotenvErrorKind::MalformedQuote))?;
    validate_quoted_tail(&remainder[end + 1..], line)?;
    Ok(Zeroizing::new(remainder[..end].to_owned()))
}

fn parse_double_quoted(value: &str, line: usize) -> Result<Zeroizing<String>, DotenvError> {
    let mut output = Zeroizing::new(String::new());
    let mut escaped = false;
    let mut closing_index = None;
    for (index, character) in value[1..].char_indices() {
        if escaped {
            output.push(match character {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                _ => {
                    return Err(DotenvError::new(
                        Some(line),
                        DotenvErrorKind::UnsupportedEscape,
                    ));
                }
            });
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            closing_index = Some(index + 1);
            break;
        } else {
            output.push(character);
        }
    }
    let closing_index = closing_index
        .ok_or_else(|| DotenvError::new(Some(line), DotenvErrorKind::MalformedQuote))?;
    validate_quoted_tail(&value[closing_index + 1..], line)?;
    Ok(output)
}

fn validate_quoted_tail(tail: &str, line: usize) -> Result<(), DotenvError> {
    let tail = tail.trim_start();
    if tail.is_empty() || tail.starts_with('#') {
        Ok(())
    } else {
        Err(DotenvError::new(Some(line), DotenvErrorKind::TrailingData))
    }
}

fn parse_unquoted(value: &str) -> &str {
    let bytes = value.as_bytes();
    let comment = bytes.iter().enumerate().find_map(|(index, byte)| {
        if *byte == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            Some(index)
        } else {
            None
        }
    });
    value[..comment.unwrap_or(value.len())].trim_end()
}

/// Safe dotenv parsing or rendering failure without source values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DotenvError {
    line: Option<usize>,
    kind: DotenvErrorKind,
}

impl DotenvError {
    const fn new(line: Option<usize>, kind: DotenvErrorKind) -> Self {
        Self { line, kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotenvErrorKind {
    InvalidUtf8,
    ResourceLimit,
    NulByte,
    InvalidControl,
    MissingAssignment,
    InvalidKey,
    DuplicateKey,
    MalformedQuote,
    UnsupportedEscape,
    TrailingData,
}

impl fmt::Display for DotenvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(
                formatter,
                "invalid dotenv input at line {line}: {}",
                self.kind.as_str()
            )
        } else {
            write!(formatter, "invalid dotenv input: {}", self.kind.as_str())
        }
    }
}

impl std::error::Error for DotenvError {}

impl DotenvErrorKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::ResourceLimit => "resource limit exceeded",
            Self::NulByte => "NUL byte is not allowed",
            Self::InvalidControl => "control byte is not allowed",
            Self::MissingAssignment => "missing assignment",
            Self::InvalidKey => "invalid key",
            Self::DuplicateKey => "duplicate key",
            Self::MalformedQuote => "malformed quoted value",
            Self::UnsupportedEscape => "unsupported escape",
            Self::TrailingData => "unexpected data after quoted value",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, render_example};
    use crate::secret::SecretName;

    #[test]
    fn parse_errors_never_echo_source_values() {
        const SENTINEL: &str = "ENVVAULT_SECRET_SENTINEL_9f2c7a";
        for source in [
            format!("TOKEN='{SENTINEL}' trailing"),
            format!("INVALID KEY={SENTINEL}"),
            format!("TOKEN=\"{SENTINEL}\\q\""),
        ] {
            let error = parse(source.as_bytes()).err();
            assert!(error.is_some());
            let rendered = error.map(|value| value.to_string()).unwrap_or_default();
            assert!(!rendered.contains(SENTINEL));
        }
    }

    #[test]
    fn parses_common_strict_forms_without_expansion() -> Result<(), Box<dyn std::error::Error>> {
        let entries = parse(
            b"# test only\nexport DATABASE_URL=postgres://localhost/db\nAPI_TOKEN='literal $TOKEN'\nMESSAGE=\"line\\nnext\" # note\nHASH=value#kept\nEMPTY=\n",
        )?;
        let values: Vec<_> = entries
            .into_iter()
            .map(|entry| {
                let (name, value) = entry.into_parts();
                (name.as_str().to_owned(), value.expose_secret().to_vec())
            })
            .collect();
        assert_eq!(values[0].1, b"postgres://localhost/db");
        assert_eq!(values[1].1, b"literal $TOKEN");
        assert_eq!(values[2].1, b"line\nnext");
        assert_eq!(values[3].1, b"value#kept");
        assert!(values[4].1.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_duplicates_invalid_keys_and_malformed_quotes() {
        assert!(parse(b"A=1\nA=2\n").is_err());
        assert!(parse(b"BAD-NAME=value\n").is_err());
        assert!(parse(b"A=\"unterminated\n").is_err());
        assert!(parse(b"A=\"value\" trailing\n").is_err());
        assert!(parse(b"A=\"bad\\xescape\"\n").is_err());
        assert!(parse(b"A=value\rB=other").is_err());
    }

    #[test]
    fn renders_only_sorted_empty_keys() -> Result<(), Box<dyn std::error::Error>> {
        let first = SecretName::new("Z_TOKEN")?;
        let second = SecretName::new("API_KEY")?;
        assert_eq!(render_example([&first, &second])?, b"API_KEY=\nZ_TOKEN=\n");
        assert!(render_example([&SecretName::new("not dotenv")?]).is_err());
        Ok(())
    }
}
