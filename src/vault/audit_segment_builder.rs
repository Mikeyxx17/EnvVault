use std::path::Path;

use zeroize::Zeroizing;

use crate::{
    audit::AuditEvent,
    crypto::{
        AuditKey, CryptoError, EncryptedEnvelope, MasterKey, decrypt, decrypt_audit, encrypt,
        encrypt_audit, generate_array,
    },
    secure_fs,
};

use super::{
    VaultError,
    audit_descriptor::{DescriptorStore, VaultDescriptorV3, lock_path_for},
    audit_recovery::{AnchorMode, AuditRotationManifest, AuditRotationPlan, ManifestStore},
    audit_segment_store::segment_digest,
    audit_v2::{AuditSegmentV2, MAX_SEGMENT_EVENTS, event_aad, parse_segment, serialize_segment},
};

const ACTIVE_KEY_AAD_DOMAIN: &[u8] = b"envvault:audit-active-key:v3\0";
const ACTIVE_KEY_FORMAT_VERSION: u32 = 3;
const VAULT_ID_LENGTH: usize = 16;
const AUTHENTICATOR_LENGTH: usize = EncryptedEnvelope::TAG_LENGTH;

/// Builds one non-empty encrypted Audit V2 segment in sequence order.
pub(super) struct AuditSegmentBuilderV2 {
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    start_sequence: u64,
    created_unix_time_millis: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
    head_authenticator: [u8; AUTHENTICATOR_LENGTH],
    key: AuditKey,
    events: Vec<(u64, EncryptedEnvelope)>,
}

impl AuditSegmentBuilderV2 {
    pub(super) fn new(
        vault_id: [u8; VAULT_ID_LENGTH],
        segment_id: u64,
        start_sequence: u64,
        created_unix_time_millis: u64,
        previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
        key: AuditKey,
    ) -> Result<Self, VaultError> {
        if segment_id == 0 || start_sequence == 0 {
            return Err(VaultError::InvalidFormat);
        }
        if (segment_id == 1
            && (start_sequence != 1
                || previous_segment_authenticator != [0_u8; AUTHENTICATOR_LENGTH]))
            || (segment_id > 1
                && (start_sequence == 1
                    || previous_segment_authenticator == [0_u8; AUTHENTICATOR_LENGTH]))
        {
            return Err(VaultError::InvalidFormat);
        }
        Ok(Self {
            vault_id,
            segment_id,
            start_sequence,
            created_unix_time_millis,
            previous_segment_authenticator,
            head_authenticator: previous_segment_authenticator,
            key,
            events: Vec::new(),
        })
    }

    pub(super) fn append(&mut self, event: AuditEvent) -> Result<u64, VaultError> {
        if self.events.len() >= MAX_SEGMENT_EVENTS {
            return Err(VaultError::ResourceLimitExceeded);
        }
        let offset =
            u64::try_from(self.events.len()).map_err(|_| VaultError::ResourceLimitExceeded)?;
        let sequence = self
            .start_sequence
            .checked_add(offset)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let plaintext = event
            .encode()
            .map_err(|_| VaultError::AuditPayloadTooLarge)?;
        let envelope = encrypt_audit(
            &self.key,
            &plaintext,
            &event_aad(
                self.vault_id,
                self.segment_id,
                sequence,
                self.head_authenticator,
            ),
        )
        .map_err(map_crypto_error)?;
        self.head_authenticator = envelope_authenticator(&envelope)?;
        self.events.push((sequence, envelope));
        Ok(sequence)
    }

    pub(super) fn resume(segment: AuditSegmentV2, key: AuditKey) -> Result<Self, VaultError> {
        let builder = Self {
            vault_id: segment.vault_id(),
            segment_id: segment.segment_id(),
            start_sequence: segment.start_sequence(),
            created_unix_time_millis: segment.created_unix_time_millis(),
            previous_segment_authenticator: segment.previous_segment_authenticator(),
            head_authenticator: segment.terminal_authenticator(),
            key,
            events: segment.into_encrypted_events(),
        };
        if builder.events.is_empty() || builder.events.len() > MAX_SEGMENT_EVENTS {
            return Err(VaultError::InvalidFormat);
        }
        Ok(builder)
    }

    pub(super) fn seal(self) -> Result<Vec<u8>, VaultError> {
        let segment = AuditSegmentV2::new(
            self.vault_id,
            self.segment_id,
            self.start_sequence,
            self.created_unix_time_millis,
            self.previous_segment_authenticator,
            self.events,
        )?;
        serialize_segment(&segment)
    }
}

pub(super) fn verify_and_decode_segment(
    key: &AuditKey,
    canonical_segment: &[u8],
) -> Result<Vec<AuditEvent>, VaultError> {
    let segment = parse_segment(canonical_segment)?;
    if serialize_segment(&segment)? != canonical_segment {
        return Err(VaultError::InvalidFormat);
    }
    let mut previous = segment.previous_segment_authenticator();
    let mut events = Vec::new();
    for (sequence, envelope) in segment.encrypted_events() {
        let plaintext = decrypt_audit(
            key,
            envelope,
            &event_aad(segment.vault_id(), segment.segment_id(), sequence, previous),
        )
        .map_err(|_| VaultError::CorruptedAudit)?;
        let event = AuditEvent::decode(&plaintext).map_err(|_| VaultError::CorruptedAudit)?;
        previous = envelope_authenticator(envelope)?;
        events.push(event);
    }
    if previous != segment.terminal_authenticator() {
        return Err(VaultError::CorruptedAudit);
    }
    Ok(events)
}

pub(super) fn wrap_active_key(
    master_key: &MasterKey,
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    start_sequence: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
    key_bytes: &[u8; AuditKey::LENGTH],
) -> Result<EncryptedEnvelope, VaultError> {
    encrypt(
        master_key,
        key_bytes,
        &active_key_aad(
            vault_id,
            segment_id,
            start_sequence,
            previous_segment_authenticator,
        )?,
    )
    .map_err(map_crypto_error)
}

pub(super) fn unwrap_active_key(
    master_key: &MasterKey,
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    start_sequence: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
    envelope: &EncryptedEnvelope,
) -> Result<AuditKey, VaultError> {
    let plaintext = decrypt(
        master_key,
        envelope,
        &active_key_aad(
            vault_id,
            segment_id,
            start_sequence,
            previous_segment_authenticator,
        )?,
    )
    .map_err(|_| VaultError::CorruptedAudit)?;
    let key_bytes: [u8; AuditKey::LENGTH] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::CorruptedAudit)?;
    Ok(AuditKey::new(Zeroizing::new(key_bytes)))
}

fn active_key_aad(
    vault_id: [u8; VAULT_ID_LENGTH],
    segment_id: u64,
    start_sequence: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
) -> Result<Vec<u8>, VaultError> {
    if segment_id == 0 || start_sequence == 0 {
        return Err(VaultError::InvalidFormat);
    }
    let mut aad = Vec::with_capacity(ACTIVE_KEY_AAD_DOMAIN.len() + 52);
    aad.extend_from_slice(ACTIVE_KEY_AAD_DOMAIN);
    aad.extend_from_slice(&ACTIVE_KEY_FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&segment_id.to_be_bytes());
    aad.extend_from_slice(&start_sequence.to_be_bytes());
    aad.extend_from_slice(&previous_segment_authenticator);
    Ok(aad)
}

/// Creates the durable recovery manifest for one already-built active segment.
pub(super) fn prepare_rotation_for_vault(
    vault_path: &Path,
    master_key: &MasterKey,
    canonical_segment: &[u8],
    operation_id: [u8; 16],
    anchor_mode: AnchorMode,
    expected_anchor_generation: u64,
) -> Result<AuditRotationManifest, VaultError> {
    let vault_lock_path = lock_path_for(vault_path);
    let vault_lock = secure_fs::open_lock(&vault_lock_path).map_err(map_secure_io)?;
    vault_lock.lock()?;
    let descriptor = DescriptorStore::for_vault(vault_path).load()?;
    let segment = parse_segment(canonical_segment)?;
    if serialize_segment(&segment)? != canonical_segment
        || !descriptor.matches_active_segment(&segment)
    {
        return Err(VaultError::InvalidFormat);
    }
    let (segment_id, start_sequence, predecessor, current_key_envelope) =
        descriptor.active_key_context();
    let current_key = unwrap_active_key(
        master_key,
        descriptor.vault_id(),
        segment_id,
        start_sequence,
        predecessor,
        current_key_envelope,
    )?;
    verify_and_decode_segment(&current_key, canonical_segment)?;

    let next_segment_id = segment
        .segment_id()
        .checked_add(1)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let next_start_sequence = segment
        .end_sequence()
        .checked_add(1)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let next_key_bytes =
        Zeroizing::new(generate_array::<{ AuditKey::LENGTH }>().map_err(map_crypto_error)?);
    let next_active_key_envelope = wrap_active_key(
        master_key,
        segment.vault_id(),
        next_segment_id,
        next_start_sequence,
        segment.terminal_authenticator(),
        &next_key_bytes,
    )?;
    let manifest = AuditRotationManifest::new(AuditRotationPlan {
        vault_id: segment.vault_id(),
        operation_id,
        expected_vault_generation: descriptor.generation(),
        segment_id: segment.segment_id(),
        start_sequence: segment.start_sequence(),
        end_sequence: segment.end_sequence(),
        terminal_authenticator: segment.terminal_authenticator(),
        segment_digest: segment_digest(canonical_segment),
        next_active_key_envelope,
        anchor_mode,
        expected_anchor_generation,
    })?;
    ManifestStore::create_for_vault(vault_path, &manifest)?;
    Ok(manifest)
}

pub(super) fn descriptor_with_active_key(
    master_key: &MasterKey,
    vault_id: [u8; VAULT_ID_LENGTH],
    generation: u64,
    segment: &AuditSegmentV2,
    key_bytes: &[u8; AuditKey::LENGTH],
) -> Result<VaultDescriptorV3, VaultError> {
    let key_envelope = wrap_active_key(
        master_key,
        vault_id,
        segment.segment_id(),
        segment.start_sequence(),
        segment.previous_segment_authenticator(),
        key_bytes,
    )?;
    VaultDescriptorV3::new_active_from_segment(vault_id, generation, segment, key_envelope)
}

fn envelope_authenticator(
    envelope: &EncryptedEnvelope,
) -> Result<[u8; AUTHENTICATOR_LENGTH], VaultError> {
    let start = envelope
        .ciphertext
        .len()
        .checked_sub(AUTHENTICATOR_LENGTH)
        .ok_or(VaultError::CorruptedAudit)?;
    envelope.ciphertext[start..]
        .try_into()
        .map_err(|_| VaultError::CorruptedAudit)
}

fn map_crypto_error(error: CryptoError) -> VaultError {
    match error {
        CryptoError::RandomSourceUnavailable => VaultError::RandomSourceUnavailable,
        CryptoError::EncryptionFailed => VaultError::EncryptionFailed,
        CryptoError::AuthenticationFailed => VaultError::CorruptedAudit,
        CryptoError::InvalidKdfParameters | CryptoError::KeyDerivationFailed => {
            VaultError::InvalidFormat
        }
    }
}

fn map_secure_io(error: std::io::Error) -> VaultError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        VaultError::UnsafePath
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;
    use std::{ffi::OsString, fs, path::PathBuf};

    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::{
        AuditSegmentBuilderV2, descriptor_with_active_key, prepare_rotation_for_vault,
        unwrap_active_key, verify_and_decode_segment, wrap_active_key,
    };
    use crate::{
        audit::AuditEvent,
        crypto::{AuditKey, MasterKey},
        identity::{AuthenticationMethod, Caller, CallerId, CallerKind},
        policy::{Operation, PolicyDecision},
        secret::SecretId,
        vault::{
            audit_descriptor::DescriptorStore,
            audit_recovery::{
                AnchorEvidence, AnchorMode, ArtifactEvidence, ManifestStore, RecoveryAction,
                RecoveryState,
            },
            audit_rotation::AuditRotationCoordinator,
            audit_segment_store::SegmentStore,
            audit_v2::parse_segment,
        },
    };

    fn event(byte: u8) -> AuditEvent {
        AuditEvent::now(
            Caller::new(CallerId::from_bytes([byte; 16]), CallerKind::Application),
            AuthenticationMethod::ApplicationCredential,
            SecretId::from_bytes([byte.wrapping_add(1); 16]),
            Operation::Use,
            PolicyDecision::Allow,
        )
    }

    fn recover_through_descriptor_commit(
        coordinator: &AuditRotationCoordinator,
        master_key: &MasterKey,
        canonical: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let expected = [
            RecoveryAction::RebuildOwnedStaging,
            RecoveryAction::SyncAndSealStaging,
            RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced),
            RecoveryAction::CommitVaultDescriptor,
        ];
        for action in expected {
            assert_eq!(
                coordinator.step(
                    master_key,
                    Some(canonical),
                    AnchorEvidence::ExpectedGeneration,
                )?,
                action
            );
        }
        Ok(())
    }

    #[test]
    fn builder_encrypts_contiguous_events_and_wrong_key_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_bytes = [0x77; AuditKey::LENGTH];
        let key = AuditKey::new(Zeroizing::new(key_bytes));
        let first = event(0x31);
        let second = event(0x32);
        let mut builder =
            AuditSegmentBuilderV2::new([0x11; 16], 7, 42, 1_700_000_000_123, [0x22; 16], key)?;
        assert_eq!(builder.append(first)?, 42);
        assert_eq!(builder.append(second)?, 43);
        let canonical = builder.seal()?;
        let segment = parse_segment(&canonical)?;
        assert_eq!(segment.end_sequence(), 43);

        let verified =
            verify_and_decode_segment(&AuditKey::new(Zeroizing::new(key_bytes)), &canonical)?;
        assert_eq!(verified, vec![first, second]);
        assert!(
            verify_and_decode_segment(
                &AuditKey::new(Zeroizing::new([0x78; AuditKey::LENGTH])),
                &canonical,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn active_key_envelope_is_bound_to_its_immutable_segment_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let master_key = MasterKey::new(Zeroizing::new([0x51; MasterKey::LENGTH]));
        let key_bytes = [0x61; AuditKey::LENGTH];
        let envelope = wrap_active_key(&master_key, [0x11; 16], 7, 42, [0x22; 16], &key_bytes)?;
        let _key = unwrap_active_key(&master_key, [0x11; 16], 7, 42, [0x22; 16], &envelope)?;
        assert!(unwrap_active_key(&master_key, [0x11; 16], 8, 42, [0x22; 16], &envelope,).is_err());
        Ok(())
    }

    #[test]
    fn active_key_aad_matches_the_fixed_v3_vector() -> Result<(), Box<dyn std::error::Error>> {
        let expected = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/audit_v2/active-key-aad-v3.hex"
        ));
        let aad = super::active_key_aad([0x11; 16], 7, 42, [0x22; 16])?;
        let actual = aad.iter().fold(String::new(), |mut encoded, byte| {
            let _result = write!(encoded, "{byte:02x}");
            encoded
        });
        assert_eq!(actual, expected.trim());
        Ok(())
    }

    #[test]
    fn preparation_persists_next_key_and_recovery_commits_a_decryptable_active_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let master_key = MasterKey::new(Zeroizing::new([0x51; MasterKey::LENGTH]));
        let current_key_bytes = [0x71; AuditKey::LENGTH];
        let current_key = AuditKey::new(Zeroizing::new(current_key_bytes));
        let current_event = event(0x41);
        let mut builder = AuditSegmentBuilderV2::new(
            [0x11; 16],
            7,
            42,
            1_700_000_000_123,
            [0x22; 16],
            current_key,
        )?;
        builder.append(current_event)?;
        let canonical = builder.seal()?;
        let segment = parse_segment(&canonical)?;
        let descriptor =
            descriptor_with_active_key(&master_key, [0x11; 16], 9, &segment, &current_key_bytes)?;
        DescriptorStore::create_for_vault(&vault_path, &descriptor)?;

        let prepared = prepare_rotation_for_vault(
            &vault_path,
            &master_key,
            &canonical,
            [0x33; 16],
            AnchorMode::Mandatory,
            2,
        )?;
        assert_eq!(prepared.state(), RecoveryState::Prepared);
        assert_eq!(ManifestStore::open_for_vault(&vault_path).load()?, prepared);

        let coordinator = AuditRotationCoordinator::for_vault(&vault_path)?;
        recover_through_descriptor_commit(&coordinator, &master_key, &canonical)?;

        let committed = DescriptorStore::for_vault(&vault_path).load()?;
        let (sealed_start, sealed_predecessor, sealed_envelope) =
            committed
                .sealed_key_context(7)
                .ok_or("sealed key reference missing")?;
        let sealed_key = unwrap_active_key(
            &master_key,
            committed.vault_id(),
            7,
            sealed_start,
            sealed_predecessor,
            sealed_envelope,
        )?;
        assert_eq!(
            verify_and_decode_segment(&sealed_key, &canonical)?,
            vec![current_event]
        );
        let (segment_id, start_sequence, predecessor, envelope) = committed.active_key_context();
        assert_eq!((segment_id, start_sequence), (8, 43));
        let next_key = unwrap_active_key(
            &master_key,
            committed.vault_id(),
            segment_id,
            start_sequence,
            predecessor,
            envelope,
        )?;
        let next_event = event(0x42);
        let mut next_builder = AuditSegmentBuilderV2::new(
            committed.vault_id(),
            segment_id,
            start_sequence,
            1_700_000_001_123,
            predecessor,
            next_key,
        )?;
        next_builder.append(next_event)?;
        let next_segment = next_builder.seal()?;
        assert_eq!(
            verify_and_decode_segment(
                &unwrap_active_key(
                    &master_key,
                    committed.vault_id(),
                    segment_id,
                    start_sequence,
                    predecessor,
                    envelope,
                )?,
                &next_segment,
            )?,
            vec![next_event]
        );
        Ok(())
    }

    #[test]
    fn tampered_pending_key_is_rejected_before_any_staging_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let master_key = MasterKey::new(Zeroizing::new([0x51; MasterKey::LENGTH]));
        let current_key_bytes = [0x71; AuditKey::LENGTH];
        let mut builder = AuditSegmentBuilderV2::new(
            [0x11; 16],
            7,
            42,
            1_700_000_000_123,
            [0x22; 16],
            AuditKey::new(Zeroizing::new(current_key_bytes)),
        )?;
        builder.append(event(0x41))?;
        let canonical = builder.seal()?;
        let segment = parse_segment(&canonical)?;
        let descriptor =
            descriptor_with_active_key(&master_key, [0x11; 16], 9, &segment, &current_key_bytes)?;
        DescriptorStore::create_for_vault(&vault_path, &descriptor)?;
        let prepared = prepare_rotation_for_vault(
            &vault_path,
            &master_key,
            &canonical,
            [0x33; 16],
            AnchorMode::Mandatory,
            2,
        )?;

        let mut manifest_name = OsString::from(vault_path.as_os_str());
        manifest_name.push(".audit-rotation-recovery.json");
        let manifest_path = PathBuf::from(manifest_name);
        let mut bytes = fs::read(&manifest_path)?;
        let marker =
            b"\"next_active_key_envelope\":{\"algorithm\":\"xchacha20poly1305\",\"nonce\":\"";
        let marker_start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .ok_or("key envelope marker missing")?;
        let ciphertext_marker = b"\",\"ciphertext\":\"";
        let ciphertext_start = bytes[marker_start + marker.len()..]
            .windows(ciphertext_marker.len())
            .position(|window| window == ciphertext_marker)
            .ok_or("ciphertext marker missing")?
            + marker_start
            + marker.len()
            + ciphertext_marker.len();
        bytes[ciphertext_start] = if bytes[ciphertext_start] == b'A' {
            b'B'
        } else {
            b'A'
        };
        fs::write(&manifest_path, bytes)?;

        let coordinator = AuditRotationCoordinator::for_vault(&vault_path)?;
        assert!(
            coordinator
                .step(
                    &master_key,
                    Some(&canonical),
                    AnchorEvidence::ExpectedGeneration,
                )
                .is_err()
        );
        let evidence = SegmentStore::for_vault(&vault_path)?.collect_evidence(&prepared)?;
        assert_eq!(evidence.staging, ArtifactEvidence::Missing);
        Ok(())
    }
}
