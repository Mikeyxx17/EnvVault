use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::crypto::EncryptedEnvelope;

use super::VaultError;

const SEGMENT_FORMAT_NAME: &str = "envvault-audit-segment";
const ANCHOR_FORMAT_NAME: &str = "envvault-audit-anchor";
const FORMAT_VERSION: u32 = 2;
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const DIGEST_ALGORITHM: &str = "sha256";
const EVENT_AAD_DOMAIN: &[u8] = b"envvault:audit-event:v2\0";
const SEGMENT_KEY_AAD_DOMAIN: &[u8] = b"envvault:audit-segment-key:v2\0";
const VAULT_ID_LENGTH: usize = 16;
const ANCHOR_DIGEST_LENGTH: usize = 32;
const MAX_EVENT_CIPHERTEXT_BYTES: usize = 4 * 1024 + EncryptedEnvelope::TAG_LENGTH;
pub(super) const MAX_SEGMENT_EVENTS: usize = 4_096;
pub(super) const MAX_SEGMENT_FILE_BYTES: usize = 32 * 1024 * 1024;
pub(super) const MAX_ANCHOR_FILE_BYTES: usize = 4 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AuditSegmentV2 {
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    created_unix_time_millis: u64,
    previous_segment_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
    terminal_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
    events: Vec<AuditSegmentEventV2>,
}

#[derive(Clone, PartialEq, Eq)]
struct AuditSegmentEventV2 {
    sequence: u64,
    envelope: EncryptedEnvelope,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct AuditAnchorV2 {
    vault_id: [u8; VAULT_ID_LENGTH],
    anchor_generation: u64,
    segment_id: u64,
    sequence: u64,
    terminal_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
    previous_anchor_digest: [u8; ANCHOR_DIGEST_LENGTH],
    created_unix_time_millis: u64,
}

impl AuditSegmentV2 {
    pub(super) fn new(
        vault_id: [u8; VAULT_ID_LENGTH],
        segment_id: u64,
        start_sequence: u64,
        created_unix_time_millis: u64,
        previous_segment_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
        events: Vec<(u64, EncryptedEnvelope)>,
    ) -> Result<Self, VaultError> {
        let events = events
            .into_iter()
            .map(|(sequence, envelope)| AuditSegmentEventV2 { sequence, envelope })
            .collect::<Vec<_>>();
        let end_sequence = events
            .last()
            .map(|event| event.sequence)
            .ok_or(VaultError::InvalidFormat)?;
        let terminal_authenticator =
            envelope_authenticator(&events.last().ok_or(VaultError::InvalidFormat)?.envelope)?;
        let segment = Self {
            vault_id,
            segment_id,
            start_sequence,
            end_sequence,
            created_unix_time_millis,
            previous_segment_authenticator,
            terminal_authenticator,
            events,
        };
        validate_segment(&segment)?;
        Ok(segment)
    }

    pub(super) const fn vault_id(&self) -> [u8; VAULT_ID_LENGTH] {
        self.vault_id
    }

    pub(super) const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub(super) const fn start_sequence(&self) -> u64 {
        self.start_sequence
    }

    pub(super) const fn end_sequence(&self) -> u64 {
        self.end_sequence
    }

    pub(super) const fn created_unix_time_millis(&self) -> u64 {
        self.created_unix_time_millis
    }

    pub(super) const fn terminal_authenticator(&self) -> [u8; EncryptedEnvelope::TAG_LENGTH] {
        self.terminal_authenticator
    }

    pub(super) const fn previous_segment_authenticator(
        &self,
    ) -> [u8; EncryptedEnvelope::TAG_LENGTH] {
        self.previous_segment_authenticator
    }

    pub(super) fn encrypted_events(&self) -> impl Iterator<Item = (u64, &EncryptedEnvelope)> {
        self.events
            .iter()
            .map(|event| (event.sequence, &event.envelope))
    }

    pub(super) fn into_encrypted_events(self) -> Vec<(u64, EncryptedEnvelope)> {
        self.events
            .into_iter()
            .map(|event| (event.sequence, event.envelope))
            .collect()
    }
}

impl AuditAnchorV2 {
    pub(super) fn new(
        vault_id: [u8; VAULT_ID_LENGTH],
        anchor_generation: u64,
        segment_id: u64,
        sequence: u64,
        terminal_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
        previous_anchor_digest: [u8; ANCHOR_DIGEST_LENGTH],
        created_unix_time_millis: u64,
    ) -> Result<Self, VaultError> {
        let anchor = Self {
            vault_id,
            anchor_generation,
            segment_id,
            sequence,
            terminal_authenticator,
            previous_anchor_digest,
            created_unix_time_millis,
        };
        validate_anchor(&anchor)?;
        Ok(anchor)
    }

    pub(super) const fn vault_id(&self) -> [u8; VAULT_ID_LENGTH] {
        self.vault_id
    }

    pub(super) const fn anchor_generation(&self) -> u64 {
        self.anchor_generation
    }

    pub(super) const fn segment_id(&self) -> u64 {
        self.segment_id
    }

    pub(super) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(super) const fn terminal_authenticator(&self) -> [u8; EncryptedEnvelope::TAG_LENGTH] {
        self.terminal_authenticator
    }

    pub(super) const fn previous_anchor_digest(&self) -> [u8; ANCHOR_DIGEST_LENGTH] {
        self.previous_anchor_digest
    }
}

pub(super) fn parse_segment(bytes: &[u8]) -> Result<AuditSegmentV2, VaultError> {
    if bytes.len() > MAX_SEGMENT_FILE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let file: SegmentFile = serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
    if file.format != SEGMENT_FORMAT_NAME {
        return Err(VaultError::InvalidFormat);
    }
    if file.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if file.aead.algorithm != AEAD_ALGORITHM || file.events.len() > MAX_SEGMENT_EVENTS {
        return Err(VaultError::InvalidFormat);
    }
    let events = file
        .events
        .into_iter()
        .map(|event| {
            Ok(AuditSegmentEventV2 {
                sequence: event.sequence,
                envelope: decode_envelope(event.envelope)?,
            })
        })
        .collect::<Result<Vec<_>, VaultError>>()?;
    let segment = AuditSegmentV2 {
        vault_id: decode_array(&file.vault_id)?,
        segment_id: file.segment_id,
        start_sequence: file.start_sequence,
        end_sequence: file.end_sequence,
        created_unix_time_millis: file.created_unix_time_millis,
        previous_segment_authenticator: decode_array(&file.previous_segment_authenticator)?,
        terminal_authenticator: decode_array(&file.terminal_authenticator)?,
        events,
    };
    validate_segment(&segment)?;
    Ok(segment)
}

pub(super) fn serialize_segment(segment: &AuditSegmentV2) -> Result<Vec<u8>, VaultError> {
    validate_segment(segment)?;
    let file = SegmentFile {
        format: SEGMENT_FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        vault_id: STANDARD.encode(segment.vault_id),
        segment_id: segment.segment_id,
        start_sequence: segment.start_sequence,
        end_sequence: segment.end_sequence,
        created_unix_time_millis: segment.created_unix_time_millis,
        previous_segment_authenticator: STANDARD.encode(segment.previous_segment_authenticator),
        terminal_authenticator: STANDARD.encode(segment.terminal_authenticator),
        aead: AeadFile {
            algorithm: AEAD_ALGORITHM.to_owned(),
        },
        events: segment
            .events
            .iter()
            .map(|event| SegmentEventFile {
                sequence: event.sequence,
                envelope: encode_envelope(&event.envelope),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&file).map_err(|_| VaultError::InvalidFormat)?;
    if bytes.len() > MAX_SEGMENT_FILE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

pub(super) fn parse_anchor(bytes: &[u8]) -> Result<AuditAnchorV2, VaultError> {
    if bytes.len() > MAX_ANCHOR_FILE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let file: AnchorFile = serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
    if file.format != ANCHOR_FORMAT_NAME || file.digest_algorithm != DIGEST_ALGORITHM {
        return Err(VaultError::InvalidFormat);
    }
    if file.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let anchor = AuditAnchorV2 {
        vault_id: decode_array(&file.vault_id)?,
        anchor_generation: file.anchor_generation,
        segment_id: file.segment_id,
        sequence: file.sequence,
        terminal_authenticator: decode_array(&file.terminal_authenticator)?,
        previous_anchor_digest: decode_array(&file.previous_anchor_digest)?,
        created_unix_time_millis: file.created_unix_time_millis,
    };
    validate_anchor(&anchor)?;
    Ok(anchor)
}

pub(super) fn serialize_anchor(anchor: &AuditAnchorV2) -> Result<Vec<u8>, VaultError> {
    validate_anchor(anchor)?;
    let file = AnchorFile {
        format: ANCHOR_FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        vault_id: STANDARD.encode(anchor.vault_id),
        anchor_generation: anchor.anchor_generation,
        segment_id: anchor.segment_id,
        sequence: anchor.sequence,
        terminal_authenticator: STANDARD.encode(anchor.terminal_authenticator),
        digest_algorithm: DIGEST_ALGORITHM.to_owned(),
        previous_anchor_digest: STANDARD.encode(anchor.previous_anchor_digest),
        created_unix_time_millis: anchor.created_unix_time_millis,
    };
    let bytes = serde_json::to_vec(&file).map_err(|_| VaultError::InvalidFormat)?;
    if bytes.len() > MAX_ANCHOR_FILE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

pub(super) fn event_aad(
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    sequence: u64,
    previous_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(EVENT_AAD_DOMAIN.len() + 52);
    aad.extend_from_slice(EVENT_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&segment_id.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&previous_authenticator);
    aad
}

pub(super) fn segment_key_aad(segment: &AuditSegmentV2) -> Result<Vec<u8>, VaultError> {
    validate_segment(segment)?;
    let mut aad = Vec::with_capacity(SEGMENT_KEY_AAD_DOMAIN.len() + 84);
    aad.extend_from_slice(SEGMENT_KEY_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&segment.vault_id);
    aad.extend_from_slice(&segment.segment_id.to_be_bytes());
    aad.extend_from_slice(&segment.start_sequence.to_be_bytes());
    aad.extend_from_slice(&segment.end_sequence.to_be_bytes());
    aad.extend_from_slice(&segment.created_unix_time_millis.to_be_bytes());
    aad.extend_from_slice(&segment.previous_segment_authenticator);
    aad.extend_from_slice(&segment.terminal_authenticator);
    Ok(aad)
}

fn validate_segment(segment: &AuditSegmentV2) -> Result<(), VaultError> {
    if segment.segment_id == 0
        || segment.start_sequence == 0
        || segment.events.is_empty()
        || segment.events.len() > MAX_SEGMENT_EVENTS
    {
        return Err(VaultError::InvalidFormat);
    }
    let expected_count = segment
        .end_sequence
        .checked_sub(segment.start_sequence)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(VaultError::InvalidFormat)?;
    if usize::try_from(expected_count).map_err(|_| VaultError::ResourceLimitExceeded)?
        != segment.events.len()
    {
        return Err(VaultError::InvalidFormat);
    }
    let initial_authenticator = [0_u8; EncryptedEnvelope::TAG_LENGTH];
    if (segment.segment_id == 1
        && (segment.start_sequence != 1
            || segment.previous_segment_authenticator != initial_authenticator))
        || (segment.segment_id > 1
            && (segment.start_sequence == 1
                || segment.previous_segment_authenticator == initial_authenticator))
    {
        return Err(VaultError::InvalidFormat);
    }
    for (index, event) in segment.events.iter().enumerate() {
        let offset = u64::try_from(index).map_err(|_| VaultError::ResourceLimitExceeded)?;
        let expected_sequence = segment
            .start_sequence
            .checked_add(offset)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        if event.sequence != expected_sequence {
            return Err(VaultError::InvalidFormat);
        }
        validate_envelope(&event.envelope)?;
    }
    let terminal = envelope_authenticator(
        &segment
            .events
            .last()
            .ok_or(VaultError::InvalidFormat)?
            .envelope,
    )?;
    if segment.end_sequence
        != segment
            .events
            .last()
            .ok_or(VaultError::InvalidFormat)?
            .sequence
        || segment.terminal_authenticator != terminal
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn validate_anchor(anchor: &AuditAnchorV2) -> Result<(), VaultError> {
    let initial_digest = [0_u8; ANCHOR_DIGEST_LENGTH];
    if anchor.anchor_generation == 0 || anchor.segment_id == 0 || anchor.sequence == 0 {
        return Err(VaultError::InvalidFormat);
    }
    if (anchor.anchor_generation == 1 && anchor.previous_anchor_digest != initial_digest)
        || (anchor.anchor_generation > 1 && anchor.previous_anchor_digest == initial_digest)
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn encode_envelope(envelope: &EncryptedEnvelope) -> EnvelopeFile {
    EnvelopeFile {
        nonce: STANDARD.encode(envelope.nonce),
        ciphertext: STANDARD.encode(&envelope.ciphertext),
    }
}

fn decode_envelope(file: EnvelopeFile) -> Result<EncryptedEnvelope, VaultError> {
    let envelope = EncryptedEnvelope {
        nonce: decode_array(&file.nonce)?,
        ciphertext: STANDARD
            .decode(file.ciphertext)
            .map_err(|_| VaultError::InvalidFormat)?,
    };
    validate_envelope(&envelope)?;
    Ok(envelope)
}

fn validate_envelope(envelope: &EncryptedEnvelope) -> Result<(), VaultError> {
    if envelope.ciphertext.len() < EncryptedEnvelope::TAG_LENGTH
        || envelope.ciphertext.len() > MAX_EVENT_CIPHERTEXT_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(())
}

fn envelope_authenticator(
    envelope: &EncryptedEnvelope,
) -> Result<[u8; EncryptedEnvelope::TAG_LENGTH], VaultError> {
    let start = envelope
        .ciphertext
        .len()
        .checked_sub(EncryptedEnvelope::TAG_LENGTH)
        .ok_or(VaultError::InvalidFormat)?;
    envelope.ciphertext[start..]
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)
}

fn decode_array<const LENGTH: usize>(encoded: &str) -> Result<[u8; LENGTH], VaultError> {
    STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidFormat)?
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentFile {
    format: String,
    version: u32,
    vault_id: String,
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    created_unix_time_millis: u64,
    previous_segment_authenticator: String,
    terminal_authenticator: String,
    aead: AeadFile,
    events: Vec<SegmentEventFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentEventFile {
    sequence: u64,
    envelope: EnvelopeFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AeadFile {
    algorithm: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFile {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorFile {
    format: String,
    version: u32,
    vault_id: String,
    anchor_generation: u64,
    segment_id: u64,
    sequence: u64,
    terminal_authenticator: String,
    digest_algorithm: String,
    previous_anchor_digest: String,
    created_unix_time_millis: u64,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        AuditSegmentV2, event_aad, parse_anchor, parse_segment, segment_key_aad, serialize_anchor,
        serialize_segment,
    };

    const SEGMENT_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/segment-v2.json"
    ));
    const ANCHOR_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/anchor-v2.json"
    ));

    #[test]
    fn segment_vector_is_canonical_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let segment = parse_segment(SEGMENT_VECTOR)?;
        let canonical = serialize_segment(&segment)?;
        assert_eq!(canonical, fixture_payload(SEGMENT_VECTOR));
        assert!(parse_segment(&canonical)? == segment);
        Ok(())
    }

    #[test]
    fn anchor_vector_is_canonical_and_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let anchor = parse_anchor(ANCHOR_VECTOR)?;
        let canonical = serialize_anchor(&anchor)?;
        assert_eq!(canonical, fixture_payload(ANCHOR_VECTOR));
        assert!(parse_anchor(&canonical)? == anchor);
        Ok(())
    }

    #[test]
    fn segment_rejects_sequence_gaps_terminal_mismatch_and_unknown_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(SEGMENT_VECTOR)?;
        document["events"][0]["sequence"] = Value::from(43_u64);
        assert!(parse_segment(&serde_json::to_vec(&document)?).is_err());

        let mut document: Value = serde_json::from_slice(SEGMENT_VECTOR)?;
        document["terminal_authenticator"] = Value::String("IiIiIiIiIiIiIiIiIiIiIg==".into());
        assert!(parse_segment(&serde_json::to_vec(&document)?).is_err());

        let mut document: Value = serde_json::from_slice(SEGMENT_VECTOR)?;
        document["unexpected"] = Value::Bool(true);
        assert!(parse_segment(&serde_json::to_vec(&document)?).is_err());
        Ok(())
    }

    #[test]
    fn anchor_rejects_a_missing_digest_predecessor_and_unknown_algorithm()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(ANCHOR_VECTOR)?;
        document["previous_anchor_digest"] =
            Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into());
        assert!(parse_anchor(&serde_json::to_vec(&document)?).is_err());

        let mut document: Value = serde_json::from_slice(ANCHOR_VECTOR)?;
        document["digest_algorithm"] = Value::String("unknown".into());
        assert!(parse_anchor(&serde_json::to_vec(&document)?).is_err());
        Ok(())
    }

    #[test]
    fn aad_layouts_match_fixed_binary_vectors() -> Result<(), Box<dyn std::error::Error>> {
        let segment: AuditSegmentV2 = parse_segment(SEGMENT_VECTOR)?;
        let event = event_aad([0x11; 16], 7, 42, [0x22; 16]);
        let segment_key = segment_key_aad(&segment)?;

        assert_eq!(
            to_hex(&event),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/audit_v2/event-aad-v2.hex"
            ))
            .trim()
        );
        assert_eq!(
            to_hex(&segment_key),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/audit_v2/segment-key-aad-v2.hex"
            ))
            .trim()
        );
        Ok(())
    }

    fn to_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn fixture_payload(bytes: &[u8]) -> &[u8] {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    }
}
