use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{crypto::EncryptedEnvelope, secure_fs};

use super::VaultError;

const FORMAT_NAME: &str = "envvault-audit-rotation-recovery";
const FORMAT_VERSION: u32 = 2;
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const DIGEST_ALGORITHM: &str = "sha256";
const VAULT_ID_LENGTH: usize = 16;
const OPERATION_ID_LENGTH: usize = 16;
const AUTHENTICATOR_LENGTH: usize = 16;
const DIGEST_LENGTH: usize = 32;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SEGMENT_EVENTS: u64 = 4_096;
const ACTIVE_KEY_CIPHERTEXT_LENGTH: usize = 32 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RecoveryState {
    Prepared,
    SealedFileSynced,
    VaultCommitted,
    AnchorConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AnchorMode {
    Mandatory,
    Optional,
    LocalMirror,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditRotationManifest {
    state: RecoveryState,
    vault_id: [u8; VAULT_ID_LENGTH],
    operation_id: [u8; OPERATION_ID_LENGTH],
    expected_vault_generation: u64,
    committed_vault_generation: u64,
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    terminal_authenticator: [u8; AUTHENTICATOR_LENGTH],
    segment_digest: [u8; DIGEST_LENGTH],
    next_active_key_envelope: EncryptedEnvelope,
    staging_file: String,
    sealed_file: String,
    anchor_mode: AnchorMode,
    expected_anchor_generation: u64,
    committed_anchor_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuditRotationPlan {
    pub(super) vault_id: [u8; VAULT_ID_LENGTH],
    pub(super) operation_id: [u8; OPERATION_ID_LENGTH],
    pub(super) expected_vault_generation: u64,
    pub(super) segment_id: u64,
    pub(super) start_sequence: u64,
    pub(super) end_sequence: u64,
    pub(super) terminal_authenticator: [u8; AUTHENTICATOR_LENGTH],
    pub(super) segment_digest: [u8; DIGEST_LENGTH],
    pub(super) next_active_key_envelope: EncryptedEnvelope,
    pub(super) anchor_mode: AnchorMode,
    pub(super) expected_anchor_generation: u64,
}

impl AuditRotationManifest {
    pub(super) fn new(plan: AuditRotationPlan) -> Result<Self, VaultError> {
        let committed_vault_generation = plan
            .expected_vault_generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let committed_anchor_generation = plan
            .expected_anchor_generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let manifest = Self {
            state: RecoveryState::Prepared,
            vault_id: plan.vault_id,
            operation_id: plan.operation_id,
            expected_vault_generation: plan.expected_vault_generation,
            committed_vault_generation,
            segment_id: plan.segment_id,
            start_sequence: plan.start_sequence,
            end_sequence: plan.end_sequence,
            terminal_authenticator: plan.terminal_authenticator,
            segment_digest: plan.segment_digest,
            next_active_key_envelope: plan.next_active_key_envelope,
            staging_file: staging_file_name(plan.operation_id),
            sealed_file: sealed_file_name(plan.segment_id),
            anchor_mode: plan.anchor_mode,
            expected_anchor_generation: plan.expected_anchor_generation,
            committed_anchor_generation,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub(super) const fn state(&self) -> RecoveryState {
        self.state
    }

    pub(super) const fn vault_id(&self) -> [u8; VAULT_ID_LENGTH] {
        self.vault_id
    }

    pub(super) const fn expected_vault_generation(&self) -> u64 {
        self.expected_vault_generation
    }

    pub(super) const fn committed_vault_generation(&self) -> u64 {
        self.committed_vault_generation
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

    pub(super) const fn terminal_authenticator(&self) -> [u8; AUTHENTICATOR_LENGTH] {
        self.terminal_authenticator
    }

    pub(super) const fn segment_digest(&self) -> [u8; DIGEST_LENGTH] {
        self.segment_digest
    }

    pub(super) const fn anchor_mode(&self) -> AnchorMode {
        self.anchor_mode
    }

    pub(super) const fn expected_anchor_generation(&self) -> u64 {
        self.expected_anchor_generation
    }

    pub(super) const fn committed_anchor_generation(&self) -> u64 {
        self.committed_anchor_generation
    }

    pub(super) fn next_active_key_envelope(&self) -> &EncryptedEnvelope {
        &self.next_active_key_envelope
    }

    pub(super) fn staging_file(&self) -> &str {
        &self.staging_file
    }

    pub(super) fn sealed_file(&self) -> &str {
        &self.sealed_file
    }

    pub(super) fn advance(&self, next: RecoveryState) -> Result<Self, VaultError> {
        let valid = matches!(
            (self.state, next),
            (RecoveryState::Prepared, RecoveryState::SealedFileSynced)
                | (
                    RecoveryState::SealedFileSynced,
                    RecoveryState::VaultCommitted
                )
                | (
                    RecoveryState::VaultCommitted,
                    RecoveryState::AnchorConfirmed
                )
        );
        if !valid {
            return Err(VaultError::InvalidFormat);
        }
        let mut advanced = self.clone();
        advanced.state = next;
        Ok(advanced)
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.operation_id == [0_u8; OPERATION_ID_LENGTH]
            || self.expected_vault_generation == 0
            || self.committed_vault_generation
                != self
                    .expected_vault_generation
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)?
            || self.segment_id == 0
            || self.start_sequence == 0
            || self.end_sequence < self.start_sequence
            || self.segment_digest == [0_u8; DIGEST_LENGTH]
            || self.next_active_key_envelope.ciphertext.len() != ACTIVE_KEY_CIPHERTEXT_LENGTH
            || self.committed_anchor_generation
                != self
                    .expected_anchor_generation
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)?
        {
            return Err(VaultError::InvalidFormat);
        }
        let event_count = self
            .end_sequence
            .checked_sub(self.start_sequence)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(VaultError::ResourceLimitExceeded)?;
        if event_count > MAX_SEGMENT_EVENTS
            || self.staging_file != staging_file_name(self.operation_id)
            || self.sealed_file != sealed_file_name(self.segment_id)
            || self.staging_file == self.sealed_file
        {
            return Err(VaultError::InvalidFormat);
        }
        Ok(())
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<AuditRotationManifest, VaultError> {
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_MANIFEST_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let file: ManifestFile =
        serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
    if file.format != FORMAT_NAME || file.digest_algorithm != DIGEST_ALGORITHM {
        return Err(VaultError::InvalidFormat);
    }
    if file.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let manifest = AuditRotationManifest {
        state: file.state,
        vault_id: decode_array(&file.vault_id)?,
        operation_id: decode_array(&file.operation_id)?,
        expected_vault_generation: file.expected_vault_generation,
        committed_vault_generation: file.committed_vault_generation,
        segment_id: file.segment_id,
        start_sequence: file.start_sequence,
        end_sequence: file.end_sequence,
        terminal_authenticator: decode_array(&file.terminal_authenticator)?,
        segment_digest: decode_array(&file.segment_digest)?,
        next_active_key_envelope: decode_key_envelope(file.next_active_key_envelope)?,
        staging_file: file.staging_file,
        sealed_file: file.sealed_file,
        anchor_mode: file.anchor_mode,
        expected_anchor_generation: file.expected_anchor_generation,
        committed_anchor_generation: file.committed_anchor_generation,
    };
    manifest.validate()?;
    Ok(manifest)
}

pub(super) fn serialize(manifest: &AuditRotationManifest) -> Result<Vec<u8>, VaultError> {
    manifest.validate()?;
    let file = ManifestFile {
        format: FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        state: manifest.state,
        vault_id: STANDARD.encode(manifest.vault_id),
        operation_id: STANDARD.encode(manifest.operation_id),
        expected_vault_generation: manifest.expected_vault_generation,
        committed_vault_generation: manifest.committed_vault_generation,
        segment_id: manifest.segment_id,
        start_sequence: manifest.start_sequence,
        end_sequence: manifest.end_sequence,
        terminal_authenticator: STANDARD.encode(manifest.terminal_authenticator),
        digest_algorithm: DIGEST_ALGORITHM.to_owned(),
        segment_digest: STANDARD.encode(manifest.segment_digest),
        next_active_key_envelope: encode_key_envelope(&manifest.next_active_key_envelope),
        staging_file: manifest.staging_file.clone(),
        sealed_file: manifest.sealed_file.clone(),
        anchor_mode: manifest.anchor_mode,
        expected_anchor_generation: manifest.expected_anchor_generation,
        committed_anchor_generation: manifest.committed_anchor_generation,
    };
    let bytes = serde_json::to_vec(&file).map_err(|_| VaultError::InvalidFormat)?;
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_MANIFEST_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

pub(super) struct ManifestStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl ManifestStore {
    pub(super) fn create_for_vault(
        vault_path: &Path,
        manifest: &AuditRotationManifest,
    ) -> Result<Self, VaultError> {
        let path = manifest_path_for(vault_path);
        let lock_path = lock_path_for(&path);
        let lock = secure_fs::open_lock(&lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        let bytes = serialize(manifest)?;
        let mut file = secure_fs::create_new(&path).map_err(map_secure_io)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(Self { path, lock_path })
    }

    pub(super) fn open_for_vault(vault_path: &Path) -> Self {
        let path = manifest_path_for(vault_path);
        let lock_path = lock_path_for(&path);
        Self { path, lock_path }
    }

    pub(super) fn exists_for_vault(vault_path: &Path) -> Result<bool, VaultError> {
        let path = manifest_path_for(vault_path);
        secure_fs::ensure_safe_path(&path, true).map_err(map_secure_io)?;
        Ok(path.exists())
    }

    pub(super) fn load(&self) -> Result<AuditRotationManifest, VaultError> {
        read_manifest(&self.path)
    }

    pub(super) fn advance(
        &self,
        expected: &AuditRotationManifest,
        next: RecoveryState,
    ) -> Result<AuditRotationManifest, VaultError> {
        let lock = secure_fs::open_lock(&self.lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        let current = self.load()?;
        if current != *expected {
            return Err(VaultError::ConcurrentModification);
        }
        let advanced = current.advance(next)?;
        write_manifest_atomically(&self.path, &advanced)?;
        Ok(advanced)
    }

    pub(super) fn remove_confirmed(
        &self,
        expected: &AuditRotationManifest,
    ) -> Result<(), VaultError> {
        let lock = secure_fs::open_lock(&self.lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        let current = self.load()?;
        if current != *expected {
            return Err(VaultError::ConcurrentModification);
        }
        if current.state != RecoveryState::AnchorConfirmed {
            return Err(VaultError::InvalidFormat);
        }
        secure_fs::ensure_safe_path(&self.path, false).map_err(map_secure_io)?;
        fs::remove_file(&self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArtifactEvidence {
    Missing,
    Empty,
    MatchesDigest,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VaultEvidence {
    ExpectedGeneration,
    ReferencesSegment,
    Unexpected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorEvidence {
    ExpectedGeneration,
    Matches,
    Unavailable,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecoveryEvidence {
    pub(super) staging: ArtifactEvidence,
    pub(super) sealed: ArtifactEvidence,
    pub(super) vault: VaultEvidence,
    pub(super) anchor: AnchorEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryAction {
    RebuildOwnedStaging,
    SyncAndSealStaging,
    AdvanceManifest(RecoveryState),
    CommitVaultDescriptor,
    RetryMandatoryAnchorCas,
    RetryOptionalAnchorCas,
    RemoveConfirmedManifest,
    StopForManualRecovery,
}

pub(super) fn plan_recovery(
    manifest: &AuditRotationManifest,
    evidence: RecoveryEvidence,
) -> RecoveryAction {
    if evidence.vault == VaultEvidence::Unexpected || evidence.anchor == AnchorEvidence::Conflict {
        return RecoveryAction::StopForManualRecovery;
    }
    if evidence.anchor == AnchorEvidence::Matches
        && evidence.vault != VaultEvidence::ReferencesSegment
    {
        return RecoveryAction::StopForManualRecovery;
    }
    if evidence.vault == VaultEvidence::ReferencesSegment {
        if evidence.sealed != ArtifactEvidence::MatchesDigest {
            return RecoveryAction::StopForManualRecovery;
        }
        return match manifest.state {
            RecoveryState::Prepared => {
                RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced)
            }
            RecoveryState::SealedFileSynced => {
                RecoveryAction::AdvanceManifest(RecoveryState::VaultCommitted)
            }
            RecoveryState::VaultCommitted if evidence.anchor == AnchorEvidence::Matches => {
                RecoveryAction::AdvanceManifest(RecoveryState::AnchorConfirmed)
            }
            RecoveryState::VaultCommitted => anchor_retry_action(manifest.anchor_mode),
            RecoveryState::AnchorConfirmed if evidence.anchor == AnchorEvidence::Matches => {
                RecoveryAction::RemoveConfirmedManifest
            }
            RecoveryState::AnchorConfirmed => RecoveryAction::StopForManualRecovery,
        };
    }
    match manifest.state {
        RecoveryState::Prepared => match evidence.sealed {
            ArtifactEvidence::MatchesDigest => {
                RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced)
            }
            ArtifactEvidence::Empty | ArtifactEvidence::Mismatch => {
                RecoveryAction::StopForManualRecovery
            }
            ArtifactEvidence::Missing => match evidence.staging {
                ArtifactEvidence::MatchesDigest => RecoveryAction::SyncAndSealStaging,
                ArtifactEvidence::Missing
                | ArtifactEvidence::Empty
                | ArtifactEvidence::Mismatch => RecoveryAction::RebuildOwnedStaging,
            },
        },
        RecoveryState::SealedFileSynced => match evidence.sealed {
            ArtifactEvidence::MatchesDigest => RecoveryAction::CommitVaultDescriptor,
            ArtifactEvidence::Missing if evidence.staging == ArtifactEvidence::MatchesDigest => {
                RecoveryAction::SyncAndSealStaging
            }
            ArtifactEvidence::Missing | ArtifactEvidence::Empty | ArtifactEvidence::Mismatch => {
                RecoveryAction::StopForManualRecovery
            }
        },
        RecoveryState::VaultCommitted | RecoveryState::AnchorConfirmed => {
            RecoveryAction::StopForManualRecovery
        }
    }
}

const fn anchor_retry_action(mode: AnchorMode) -> RecoveryAction {
    match mode {
        AnchorMode::Mandatory => RecoveryAction::RetryMandatoryAnchorCas,
        AnchorMode::Optional | AnchorMode::LocalMirror => RecoveryAction::RetryOptionalAnchorCas,
    }
}

fn read_manifest(path: &Path) -> Result<AuditRotationManifest, VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    let length = file.metadata()?.len();
    if length > MAX_MANIFEST_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let capacity = usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
    let manifest = parse(&bytes)?;
    if serialize(&manifest)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(manifest)
}

fn write_manifest_atomically(
    path: &Path,
    manifest: &AuditRotationManifest,
) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    let bytes = serialize(manifest)?;
    let mut file = AtomicWriteFile::open(path)?;

    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;

    file.write_all(&bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(path).map_err(map_secure_io)
}

fn staging_file_name(operation_id: [u8; OPERATION_ID_LENGTH]) -> String {
    format!(".envvault-audit-{}.segment.tmp", encode_hex(&operation_id))
}

fn sealed_file_name(segment_id: u64) -> String {
    format!("envvault-audit-segment-{segment_id:020}.json")
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn manifest_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".audit-rotation-recovery.json");
    PathBuf::from(value)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_array<const LENGTH: usize>(encoded: &str) -> Result<[u8; LENGTH], VaultError> {
    STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidFormat)?
        .try_into()
        .map_err(|_| VaultError::InvalidFormat)
}

fn encode_key_envelope(envelope: &EncryptedEnvelope) -> KeyEnvelopeFile {
    KeyEnvelopeFile {
        algorithm: AEAD_ALGORITHM.to_owned(),
        nonce: STANDARD.encode(envelope.nonce),
        ciphertext: STANDARD.encode(&envelope.ciphertext),
    }
}

fn decode_key_envelope(file: KeyEnvelopeFile) -> Result<EncryptedEnvelope, VaultError> {
    if file.algorithm != AEAD_ALGORITHM {
        return Err(VaultError::InvalidFormat);
    }
    let ciphertext = STANDARD
        .decode(file.ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?;
    if ciphertext.len() != ACTIVE_KEY_CIPHERTEXT_LENGTH {
        return Err(VaultError::InvalidFormat);
    }
    Ok(EncryptedEnvelope {
        nonce: decode_array(&file.nonce)?,
        ciphertext,
    })
}

fn map_secure_io(error: std::io::Error) -> VaultError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        VaultError::UnsafePath
    } else {
        error.into()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    format: String,
    version: u32,
    state: RecoveryState,
    vault_id: String,
    operation_id: String,
    expected_vault_generation: u64,
    committed_vault_generation: u64,
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    terminal_authenticator: String,
    digest_algorithm: String,
    segment_digest: String,
    next_active_key_envelope: KeyEnvelopeFile,
    staging_file: String,
    sealed_file: String,
    anchor_mode: AnchorMode,
    expected_anchor_generation: u64,
    committed_anchor_generation: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEnvelopeFile {
    algorithm: String,
    nonce: String,
    ciphertext: String,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;
    use tempfile::tempdir;

    use super::{
        AnchorEvidence, AnchorMode, ArtifactEvidence, AuditRotationManifest, AuditRotationPlan,
        ManifestStore, RecoveryAction, RecoveryEvidence, RecoveryState, VaultEvidence,
        manifest_path_for, parse, plan_recovery, serialize,
    };
    use crate::{crypto::EncryptedEnvelope, vault::VaultError};

    const MANIFEST_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/rotation-recovery-v2.json"
    ));

    fn manifest(mode: AnchorMode) -> Result<AuditRotationManifest, VaultError> {
        AuditRotationManifest::new(AuditRotationPlan {
            vault_id: [0x11; 16],
            operation_id: [0x22; 16],
            expected_vault_generation: 9,
            segment_id: 7,
            start_sequence: 42,
            end_sequence: 43,
            terminal_authenticator: [0x55; 16],
            segment_digest: [0x66; 32],
            next_active_key_envelope: test_key_envelope(),
            anchor_mode: mode,
            expected_anchor_generation: 2,
        })
    }

    fn test_key_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            nonce: [0x44; EncryptedEnvelope::NONCE_LENGTH],
            ciphertext: vec![0x66; 32 + EncryptedEnvelope::TAG_LENGTH],
        }
    }

    fn evidence(
        staging: ArtifactEvidence,
        sealed: ArtifactEvidence,
        vault: VaultEvidence,
        anchor: AnchorEvidence,
    ) -> RecoveryEvidence {
        RecoveryEvidence {
            staging,
            sealed,
            vault,
            anchor,
        }
    }

    #[test]
    fn manifest_vector_is_canonical_and_strict() -> Result<(), Box<dyn std::error::Error>> {
        let decoded = parse(MANIFEST_VECTOR)?;
        assert_eq!(decoded, manifest(AnchorMode::Mandatory)?);
        assert_eq!(serialize(&decoded)?, fixture_payload(MANIFEST_VECTOR));

        let mut document: Value = serde_json::from_slice(MANIFEST_VECTOR)?;
        document["staging_file"] = Value::String("../unowned.tmp".into());
        assert!(parse(&serde_json::to_vec(&document)?).is_err());

        let mut document: Value = serde_json::from_slice(MANIFEST_VECTOR)?;
        document["unexpected"] = Value::Bool(true);
        assert!(parse(&serde_json::to_vec(&document)?).is_err());

        let mut document: Value = serde_json::from_slice(MANIFEST_VECTOR)?;
        document["digest_algorithm"] = Value::String("unknown".into());
        assert!(parse(&serde_json::to_vec(&document)?).is_err());
        Ok(())
    }

    #[test]
    fn state_machine_rejects_skips_repeats_and_regressions()
    -> Result<(), Box<dyn std::error::Error>> {
        let prepared = manifest(AnchorMode::Mandatory)?;
        assert!(prepared.advance(RecoveryState::VaultCommitted).is_err());
        assert!(prepared.advance(RecoveryState::Prepared).is_err());
        let sealed = prepared.advance(RecoveryState::SealedFileSynced)?;
        assert!(sealed.advance(RecoveryState::Prepared).is_err());
        let committed = sealed.advance(RecoveryState::VaultCommitted)?;
        let confirmed = committed.advance(RecoveryState::AnchorConfirmed)?;
        assert!(confirmed.advance(RecoveryState::AnchorConfirmed).is_err());
        Ok(())
    }

    #[test]
    fn manifest_store_is_private_atomic_and_generation_checked()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let path = manifest_path_for(&vault_path);
        let prepared = manifest(AnchorMode::Mandatory)?;
        let store = ManifestStore::create_for_vault(&vault_path, &prepared)?;
        assert_eq!(store.load()?, prepared);
        let sealed = store.advance(&prepared, RecoveryState::SealedFileSynced)?;
        assert_eq!(store.load()?, sealed);
        assert!(matches!(
            store.advance(&prepared, RecoveryState::SealedFileSynced),
            Err(VaultError::ConcurrentModification)
        ));
        let committed = store.advance(&sealed, RecoveryState::VaultCommitted)?;
        let confirmed = store.advance(&committed, RecoveryState::AnchorConfirmed)?;
        store.remove_confirmed(&confirmed)?;
        assert!(!path.exists());
        assert!(ManifestStore::open_for_vault(&vault_path).load().is_err());
        Ok(())
    }

    #[test]
    fn deterministic_failpoint_recovery_actions_match_the_matrix()
    -> Result<(), Box<dyn std::error::Error>> {
        let prepared = manifest(AnchorMode::Mandatory)?;
        let sealed = prepared.advance(RecoveryState::SealedFileSynced)?;
        let committed = sealed.advance(RecoveryState::VaultCommitted)?;
        let confirmed = committed.advance(RecoveryState::AnchorConfirmed)?;
        let cases = [
            (
                &prepared,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::Missing,
                    VaultEvidence::ExpectedGeneration,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::RebuildOwnedStaging,
            ),
            (
                &prepared,
                evidence(
                    ArtifactEvidence::Mismatch,
                    ArtifactEvidence::Missing,
                    VaultEvidence::ExpectedGeneration,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::RebuildOwnedStaging,
            ),
            (
                &prepared,
                evidence(
                    ArtifactEvidence::MatchesDigest,
                    ArtifactEvidence::Missing,
                    VaultEvidence::ExpectedGeneration,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::SyncAndSealStaging,
            ),
            (
                &prepared,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ExpectedGeneration,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced),
            ),
            (
                &sealed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ExpectedGeneration,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::CommitVaultDescriptor,
            ),
            (
                &sealed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::ExpectedGeneration,
                ),
                RecoveryAction::AdvanceManifest(RecoveryState::VaultCommitted),
            ),
            (
                &committed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::Unavailable,
                ),
                RecoveryAction::RetryMandatoryAnchorCas,
            ),
            (
                &committed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::Matches,
                ),
                RecoveryAction::AdvanceManifest(RecoveryState::AnchorConfirmed),
            ),
            (
                &confirmed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::Matches,
                ),
                RecoveryAction::RemoveConfirmedManifest,
            ),
        ];
        for (manifest, evidence, expected) in cases {
            assert_eq!(plan_recovery(manifest, evidence), expected);
        }
        Ok(())
    }

    #[test]
    fn inconsistent_committed_evidence_always_stops() -> Result<(), Box<dyn std::error::Error>> {
        let committed = manifest(AnchorMode::Mandatory)?
            .advance(RecoveryState::SealedFileSynced)?
            .advance(RecoveryState::VaultCommitted)?;
        for sealed in [
            ArtifactEvidence::Missing,
            ArtifactEvidence::Empty,
            ArtifactEvidence::Mismatch,
        ] {
            assert_eq!(
                plan_recovery(
                    &committed,
                    evidence(
                        ArtifactEvidence::MatchesDigest,
                        sealed,
                        VaultEvidence::ReferencesSegment,
                        AnchorEvidence::Matches,
                    ),
                ),
                RecoveryAction::StopForManualRecovery
            );
        }
        assert_eq!(
            plan_recovery(
                &committed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::Unexpected,
                    AnchorEvidence::Matches,
                ),
            ),
            RecoveryAction::StopForManualRecovery
        );
        assert_eq!(
            plan_recovery(
                &committed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::Conflict,
                ),
            ),
            RecoveryAction::StopForManualRecovery
        );
        Ok(())
    }

    #[test]
    fn optional_anchor_is_retried_without_using_the_mandatory_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let committed = manifest(AnchorMode::Optional)?
            .advance(RecoveryState::SealedFileSynced)?
            .advance(RecoveryState::VaultCommitted)?;
        assert_eq!(
            plan_recovery(
                &committed,
                evidence(
                    ArtifactEvidence::Missing,
                    ArtifactEvidence::MatchesDigest,
                    VaultEvidence::ReferencesSegment,
                    AnchorEvidence::Unavailable,
                ),
            ),
            RecoveryAction::RetryOptionalAnchorCas
        );
        Ok(())
    }

    #[test]
    fn store_refuses_tampered_manifest_before_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let path = manifest_path_for(&vault_path);
        let prepared = manifest(AnchorMode::Mandatory)?;
        let store = ManifestStore::create_for_vault(&vault_path, &prepared)?;
        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        document["committed_vault_generation"] = Value::from(99_u64);
        fs::write(&path, serde_json::to_vec(&document)?)?;
        assert!(store.load().is_err());
        Ok(())
    }

    fn fixture_payload(bytes: &[u8]) -> &[u8] {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    }
}
