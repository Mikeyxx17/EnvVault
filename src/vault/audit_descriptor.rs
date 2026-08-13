use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{crypto::EncryptedEnvelope, secure_fs};

use super::{
    VaultError,
    audit_recovery::{AuditRotationManifest, RecoveryState, VaultEvidence},
};

const FORMAT_NAME: &str = "envvault-vault-descriptor";
const FORMAT_VERSION: u32 = 3;
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const DIGEST_ALGORITHM: &str = "sha256";
const VAULT_ID_LENGTH: usize = 16;
const AUTHENTICATOR_LENGTH: usize = 16;
const DIGEST_LENGTH: usize = 32;
const MAX_DESCRIPTOR_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SEALED_SEGMENTS: usize = 16_384;
const ACTIVE_KEY_CIPHERTEXT_LENGTH: usize = 32 + 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VaultDescriptorV3 {
    vault_id: [u8; VAULT_ID_LENGTH],
    generation: u64,
    sealed_segments: Vec<SealedSegmentDescriptorV3>,
    active_segment: ActiveSegmentDescriptorV3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedSegmentDescriptorV3 {
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
    terminal_authenticator: [u8; AUTHENTICATOR_LENGTH],
    segment_digest: [u8; DIGEST_LENGTH],
    file: String,
    key_envelope: EncryptedEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSegmentDescriptorV3 {
    segment_id: u64,
    start_sequence: u64,
    next_sequence: u64,
    previous_segment_authenticator: [u8; AUTHENTICATOR_LENGTH],
    head_authenticator: [u8; AUTHENTICATOR_LENGTH],
    key_envelope: EncryptedEnvelope,
}

impl VaultDescriptorV3 {
    pub(super) fn new_empty(
        vault_id: [u8; VAULT_ID_LENGTH],
        generation: u64,
        key_envelope: EncryptedEnvelope,
    ) -> Result<Self, VaultError> {
        let descriptor = Self {
            vault_id,
            generation,
            sealed_segments: Vec::new(),
            active_segment: ActiveSegmentDescriptorV3 {
                segment_id: 1,
                start_sequence: 1,
                next_sequence: 1,
                previous_segment_authenticator: [0_u8; AUTHENTICATOR_LENGTH],
                head_authenticator: [0_u8; AUTHENTICATOR_LENGTH],
                key_envelope,
            },
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(super) fn new_active_from_segment(
        vault_id: [u8; VAULT_ID_LENGTH],
        generation: u64,
        segment: &super::audit_v2::AuditSegmentV2,
        key_envelope: EncryptedEnvelope,
    ) -> Result<Self, VaultError> {
        let next_sequence = segment
            .end_sequence()
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let descriptor = Self {
            vault_id,
            generation,
            sealed_segments: Vec::new(),
            active_segment: ActiveSegmentDescriptorV3 {
                segment_id: segment.segment_id(),
                start_sequence: segment.start_sequence(),
                next_sequence,
                previous_segment_authenticator: segment.previous_segment_authenticator(),
                head_authenticator: segment.terminal_authenticator(),
                key_envelope,
            },
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(super) const fn vault_id(&self) -> [u8; VAULT_ID_LENGTH] {
        self.vault_id
    }

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) const fn active_segment_id(&self) -> u64 {
        self.active_segment.segment_id
    }

    pub(super) fn sealed_segment_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.sealed_segments
            .iter()
            .map(|segment| segment.segment_id)
    }

    pub(super) fn active_key_context(
        &self,
    ) -> (u64, u64, [u8; AUTHENTICATOR_LENGTH], &EncryptedEnvelope) {
        (
            self.active_segment.segment_id,
            self.active_segment.start_sequence,
            self.active_segment.previous_segment_authenticator,
            &self.active_segment.key_envelope,
        )
    }

    pub(super) fn matches_active_segment(&self, segment: &super::audit_v2::AuditSegmentV2) -> bool {
        let Some(next_sequence) = segment.end_sequence().checked_add(1) else {
            return false;
        };
        self.vault_id == segment.vault_id()
            && self.active_segment.segment_id == segment.segment_id()
            && self.active_segment.start_sequence == segment.start_sequence()
            && self.active_segment.next_sequence == next_sequence
            && self.active_segment.previous_segment_authenticator
                == segment.previous_segment_authenticator()
            && self.active_segment.head_authenticator == segment.terminal_authenticator()
    }

    pub(super) const fn active_is_empty(&self) -> bool {
        self.active_segment.next_sequence == self.active_segment.start_sequence
    }

    pub(super) fn can_reconcile_active_segment(
        &self,
        segment: &super::audit_v2::AuditSegmentV2,
    ) -> bool {
        let Some(next_sequence) = segment.end_sequence().checked_add(1) else {
            return false;
        };
        self.vault_id == segment.vault_id()
            && self.active_segment.segment_id == segment.segment_id()
            && self.active_segment.start_sequence == segment.start_sequence()
            && self.active_segment.previous_segment_authenticator
                == segment.previous_segment_authenticator()
            && next_sequence >= self.active_segment.next_sequence
    }

    fn reconciled_active(
        &self,
        segment: &super::audit_v2::AuditSegmentV2,
    ) -> Result<Self, VaultError> {
        if !self.can_reconcile_active_segment(segment) {
            return Err(VaultError::ConcurrentModification);
        }
        let mut candidate = self.clone();
        candidate.active_segment.next_sequence = segment
            .end_sequence()
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        candidate.active_segment.head_authenticator = segment.terminal_authenticator();
        candidate.validate()?;
        Ok(candidate)
    }

    pub(super) fn sealed_key_context(
        &self,
        segment_id: u64,
    ) -> Option<(u64, [u8; AUTHENTICATOR_LENGTH], &EncryptedEnvelope)> {
        self.sealed_segments
            .iter()
            .find(|segment| segment.segment_id == segment_id)
            .map(|segment| {
                (
                    segment.start_sequence,
                    segment.previous_segment_authenticator,
                    &segment.key_envelope,
                )
            })
    }

    fn rotated(
        &self,
        manifest: &AuditRotationManifest,
        segment_predecessor: [u8; AUTHENTICATOR_LENGTH],
    ) -> Result<Self, VaultError> {
        if self.rotation_evidence(manifest) != VaultEvidence::ExpectedGeneration {
            return Err(VaultError::ConcurrentModification);
        }
        if self.active_segment.previous_segment_authenticator != segment_predecessor {
            return Err(VaultError::InvalidFormat);
        }
        if self.sealed_segments.len() >= MAX_SEALED_SEGMENTS {
            return Err(VaultError::ResourceLimitExceeded);
        }
        let next_segment_id = manifest
            .segment_id()
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let next_sequence = manifest
            .end_sequence()
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let sealed = SealedSegmentDescriptorV3 {
            segment_id: manifest.segment_id(),
            start_sequence: manifest.start_sequence(),
            end_sequence: manifest.end_sequence(),
            previous_segment_authenticator: self.active_segment.previous_segment_authenticator,
            terminal_authenticator: manifest.terminal_authenticator(),
            segment_digest: manifest.segment_digest(),
            file: manifest.sealed_file().to_owned(),
            key_envelope: self.active_segment.key_envelope.clone(),
        };
        let mut sealed_segments = self.sealed_segments.clone();
        sealed_segments.push(sealed);
        let candidate = Self {
            vault_id: self.vault_id,
            generation: manifest.committed_vault_generation(),
            sealed_segments,
            active_segment: ActiveSegmentDescriptorV3 {
                segment_id: next_segment_id,
                start_sequence: next_sequence,
                next_sequence,
                previous_segment_authenticator: manifest.terminal_authenticator(),
                head_authenticator: manifest.terminal_authenticator(),
                key_envelope: manifest.next_active_key_envelope().clone(),
            },
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub(super) fn rotation_evidence(&self, manifest: &AuditRotationManifest) -> VaultEvidence {
        if self.vault_id != manifest.vault_id() {
            return VaultEvidence::Unexpected;
        }
        let Some(next_sequence) = manifest.end_sequence().checked_add(1) else {
            return VaultEvidence::Unexpected;
        };
        let Some(next_segment_id) = manifest.segment_id().checked_add(1) else {
            return VaultEvidence::Unexpected;
        };
        if self.generation == manifest.expected_vault_generation()
            && self.active_segment.segment_id == manifest.segment_id()
            && self.active_segment.start_sequence == manifest.start_sequence()
            && self.active_segment.next_sequence == next_sequence
            && self.active_segment.head_authenticator == manifest.terminal_authenticator()
            && !self
                .sealed_segments
                .iter()
                .any(|segment| segment.segment_id == manifest.segment_id())
        {
            return VaultEvidence::ExpectedGeneration;
        }
        if self.generation != manifest.committed_vault_generation() {
            return VaultEvidence::Unexpected;
        }
        let Some(segment) = self.sealed_segments.last() else {
            return VaultEvidence::Unexpected;
        };
        if segment.segment_id == manifest.segment_id()
            && segment.start_sequence == manifest.start_sequence()
            && segment.end_sequence == manifest.end_sequence()
            && segment.terminal_authenticator == manifest.terminal_authenticator()
            && segment.segment_digest == manifest.segment_digest()
            && segment.file == manifest.sealed_file()
            && self.active_segment.segment_id == next_segment_id
            && self.active_segment.start_sequence == next_sequence
            && self.active_segment.next_sequence == next_sequence
            && self.active_segment.previous_segment_authenticator
                == manifest.terminal_authenticator()
            && self.active_segment.head_authenticator == manifest.terminal_authenticator()
            && self.active_segment.key_envelope == *manifest.next_active_key_envelope()
        {
            VaultEvidence::ReferencesSegment
        } else {
            VaultEvidence::Unexpected
        }
    }

    fn rotation_predecessor(
        &self,
        manifest: &AuditRotationManifest,
    ) -> Result<[u8; AUTHENTICATOR_LENGTH], VaultError> {
        match self.rotation_evidence(manifest) {
            VaultEvidence::ExpectedGeneration => {
                Ok(self.active_segment.previous_segment_authenticator)
            }
            VaultEvidence::ReferencesSegment => self
                .sealed_segments
                .last()
                .map(|segment| segment.previous_segment_authenticator)
                .ok_or(VaultError::InvalidFormat),
            VaultEvidence::Unexpected => Err(VaultError::ConcurrentModification),
        }
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.generation == 0
            || self.sealed_segments.len() > MAX_SEALED_SEGMENTS
            || self.active_segment.segment_id == 0
            || self.active_segment.start_sequence == 0
            || self.active_segment.next_sequence < self.active_segment.start_sequence
            || self.active_segment.key_envelope.ciphertext.len() != ACTIVE_KEY_CIPHERTEXT_LENGTH
        {
            return Err(VaultError::InvalidFormat);
        }
        let initial_authenticator = [0_u8; AUTHENTICATOR_LENGTH];
        if self.active_segment.next_sequence == self.active_segment.start_sequence
            && self.active_segment.head_authenticator
                != self.active_segment.previous_segment_authenticator
        {
            return Err(VaultError::InvalidFormat);
        }
        if self.sealed_segments.is_empty() {
            if (self.active_segment.segment_id == 1
                && (self.active_segment.start_sequence != 1
                    || self.active_segment.previous_segment_authenticator != initial_authenticator))
                || (self.active_segment.segment_id > 1
                    && self.active_segment.previous_segment_authenticator == initial_authenticator)
            {
                return Err(VaultError::InvalidFormat);
            }
            return Ok(());
        }

        for (index, segment) in self.sealed_segments.iter().enumerate() {
            validate_sealed_segment(segment)?;
            if index == 0 {
                if (segment.segment_id == 1
                    && (segment.start_sequence != 1
                        || segment.previous_segment_authenticator != initial_authenticator))
                    || (segment.segment_id > 1
                        && segment.previous_segment_authenticator == initial_authenticator)
                {
                    return Err(VaultError::InvalidFormat);
                }
                continue;
            }
            let previous = &self.sealed_segments[index - 1];
            if segment.segment_id != checked_next(previous.segment_id)?
                || segment.start_sequence != checked_next(previous.end_sequence)?
                || segment.previous_segment_authenticator != previous.terminal_authenticator
            {
                return Err(VaultError::InvalidFormat);
            }
        }
        let last = self
            .sealed_segments
            .last()
            .ok_or(VaultError::InvalidFormat)?;
        if self.active_segment.segment_id != checked_next(last.segment_id)?
            || self.active_segment.start_sequence != checked_next(last.end_sequence)?
            || self.active_segment.previous_segment_authenticator != last.terminal_authenticator
        {
            return Err(VaultError::InvalidFormat);
        }
        Ok(())
    }
}

fn validate_sealed_segment(segment: &SealedSegmentDescriptorV3) -> Result<(), VaultError> {
    if segment.segment_id == 0
        || segment.start_sequence == 0
        || segment.end_sequence < segment.start_sequence
        || segment.terminal_authenticator == [0_u8; AUTHENTICATOR_LENGTH]
        || segment.segment_digest == [0_u8; DIGEST_LENGTH]
        || segment.file != sealed_file_name(segment.segment_id)
        || segment.key_envelope.ciphertext.len() != ACTIVE_KEY_CIPHERTEXT_LENGTH
    {
        return Err(VaultError::InvalidFormat);
    }
    Ok(())
}

fn checked_next(value: u64) -> Result<u64, VaultError> {
    value
        .checked_add(1)
        .ok_or(VaultError::ResourceLimitExceeded)
}

pub(super) fn parse(bytes: &[u8]) -> Result<VaultDescriptorV3, VaultError> {
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_DESCRIPTOR_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let file: DescriptorFile =
        serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
    if file.format != FORMAT_NAME || file.audit.digest_algorithm != DIGEST_ALGORITHM {
        return Err(VaultError::InvalidFormat);
    }
    if file.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    let descriptor = VaultDescriptorV3 {
        vault_id: decode_array(&file.vault_id)?,
        generation: file.generation,
        sealed_segments: file
            .audit
            .sealed_segments
            .into_iter()
            .map(|segment| {
                Ok(SealedSegmentDescriptorV3 {
                    segment_id: segment.segment_id,
                    start_sequence: segment.start_sequence,
                    end_sequence: segment.end_sequence,
                    previous_segment_authenticator: decode_array(
                        &segment.previous_segment_authenticator,
                    )?,
                    terminal_authenticator: decode_array(&segment.terminal_authenticator)?,
                    segment_digest: decode_array(&segment.segment_digest)?,
                    file: segment.file,
                    key_envelope: decode_key_envelope(segment.key_envelope)?,
                })
            })
            .collect::<Result<Vec<_>, VaultError>>()?,
        active_segment: ActiveSegmentDescriptorV3 {
            segment_id: file.audit.active_segment.segment_id,
            start_sequence: file.audit.active_segment.start_sequence,
            next_sequence: file.audit.active_segment.next_sequence,
            previous_segment_authenticator: decode_array(
                &file.audit.active_segment.previous_segment_authenticator,
            )?,
            head_authenticator: decode_array(&file.audit.active_segment.head_authenticator)?,
            key_envelope: decode_key_envelope(file.audit.active_segment.key_envelope)?,
        },
    };
    descriptor.validate()?;
    Ok(descriptor)
}

pub(super) fn serialize(descriptor: &VaultDescriptorV3) -> Result<Vec<u8>, VaultError> {
    descriptor.validate()?;
    let file = DescriptorFile {
        format: FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        vault_id: STANDARD.encode(descriptor.vault_id),
        generation: descriptor.generation,
        audit: AuditFile {
            digest_algorithm: DIGEST_ALGORITHM.to_owned(),
            sealed_segments: descriptor
                .sealed_segments
                .iter()
                .map(|segment| SealedSegmentFile {
                    segment_id: segment.segment_id,
                    start_sequence: segment.start_sequence,
                    end_sequence: segment.end_sequence,
                    previous_segment_authenticator: STANDARD
                        .encode(segment.previous_segment_authenticator),
                    terminal_authenticator: STANDARD.encode(segment.terminal_authenticator),
                    segment_digest: STANDARD.encode(segment.segment_digest),
                    file: segment.file.clone(),
                    key_envelope: encode_key_envelope(&segment.key_envelope),
                })
                .collect(),
            active_segment: ActiveSegmentFile {
                segment_id: descriptor.active_segment.segment_id,
                start_sequence: descriptor.active_segment.start_sequence,
                next_sequence: descriptor.active_segment.next_sequence,
                previous_segment_authenticator: STANDARD
                    .encode(descriptor.active_segment.previous_segment_authenticator),
                head_authenticator: STANDARD.encode(descriptor.active_segment.head_authenticator),
                key_envelope: encode_key_envelope(&descriptor.active_segment.key_envelope),
            },
        },
    };
    let bytes = serde_json::to_vec(&file).map_err(|_| VaultError::InvalidFormat)?;
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_DESCRIPTOR_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

pub(super) struct DescriptorStore {
    path: PathBuf,
    vault_lock_path: PathBuf,
}

impl DescriptorStore {
    pub(super) fn exists_for_vault(vault_path: &Path) -> Result<bool, VaultError> {
        let path = descriptor_path_for(vault_path);
        secure_fs::ensure_safe_path(&path, true).map_err(map_secure_io)?;
        Ok(path.exists())
    }
    pub(super) fn create_for_vault(
        vault_path: &Path,
        descriptor: &VaultDescriptorV3,
    ) -> Result<Self, VaultError> {
        let store = Self::for_vault(vault_path);
        let lock = secure_fs::open_lock(&store.vault_lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        let bytes = serialize(descriptor)?;
        let mut file = secure_fs::create_new(&store.path).map_err(map_secure_io)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(store)
    }

    pub(super) fn for_vault(vault_path: &Path) -> Self {
        Self {
            path: descriptor_path_for(vault_path),
            vault_lock_path: lock_path_for(vault_path),
        }
    }

    pub(super) fn load(&self) -> Result<VaultDescriptorV3, VaultError> {
        read_descriptor(&self.path)
    }

    pub(super) fn update_active_under_vault_lock(
        &self,
        expected: &VaultDescriptorV3,
        segment: &super::audit_v2::AuditSegmentV2,
    ) -> Result<VaultDescriptorV3, VaultError> {
        let current = self.load()?;
        if current != *expected {
            return Err(VaultError::ConcurrentModification);
        }
        let candidate = current.reconciled_active(segment)?;
        write_descriptor_atomically(&self.path, &candidate)?;
        Ok(candidate)
    }

    pub(super) fn reconcile_active_under_vault_lock(
        &self,
        segment: &super::audit_v2::AuditSegmentV2,
    ) -> Result<VaultDescriptorV3, VaultError> {
        let current = self.load()?;
        if current.matches_active_segment(segment) {
            return Ok(current);
        }
        let candidate = current.reconciled_active(segment)?;
        write_descriptor_atomically(&self.path, &candidate)?;
        Ok(candidate)
    }

    pub(super) fn collect_evidence(
        &self,
        manifest: &AuditRotationManifest,
    ) -> Result<VaultEvidence, VaultError> {
        Ok(self.load()?.rotation_evidence(manifest))
    }

    pub(super) fn collect_predecessor(
        &self,
        manifest: &AuditRotationManifest,
    ) -> Result<[u8; AUTHENTICATOR_LENGTH], VaultError> {
        self.load()?.rotation_predecessor(manifest)
    }

    pub(super) fn commit_rotation(
        &self,
        manifest: &AuditRotationManifest,
        segment_predecessor: [u8; AUTHENTICATOR_LENGTH],
    ) -> Result<VaultDescriptorV3, VaultError> {
        let lock = secure_fs::open_lock(&self.vault_lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        self.commit_rotation_under_vault_lock(manifest, segment_predecessor)
    }

    pub(super) fn commit_rotation_under_vault_lock(
        &self,
        manifest: &AuditRotationManifest,
        segment_predecessor: [u8; AUTHENTICATOR_LENGTH],
    ) -> Result<VaultDescriptorV3, VaultError> {
        if manifest.state() != RecoveryState::SealedFileSynced {
            return Err(VaultError::InvalidFormat);
        }
        let current = self.load()?;
        let candidate = current.rotated(manifest, segment_predecessor)?;
        write_descriptor_atomically(&self.path, &candidate)?;
        Ok(candidate)
    }
}

fn read_descriptor(path: &Path) -> Result<VaultDescriptorV3, VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    let length = file.metadata()?.len();
    if length > MAX_DESCRIPTOR_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let capacity = usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_DESCRIPTOR_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let descriptor = parse(&bytes)?;
    if serialize(&descriptor)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(descriptor)
}

fn write_descriptor_atomically(
    path: &Path,
    descriptor: &VaultDescriptorV3,
) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    let bytes = serialize(descriptor)?;
    let mut file = AtomicWriteFile::open(path)?;

    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;

    file.write_all(&bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(path).map_err(map_secure_io)
}

fn sealed_file_name(segment_id: u64) -> String {
    format!("envvault-audit-segment-{segment_id:020}.json")
}

pub(super) fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn descriptor_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".audit-descriptor-v3.json");
    PathBuf::from(value)
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
struct DescriptorFile {
    format: String,
    version: u32,
    vault_id: String,
    generation: u64,
    audit: AuditFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    digest_algorithm: String,
    sealed_segments: Vec<SealedSegmentFile>,
    active_segment: ActiveSegmentFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedSegmentFile {
    segment_id: u64,
    start_sequence: u64,
    end_sequence: u64,
    previous_segment_authenticator: String,
    terminal_authenticator: String,
    segment_digest: String,
    file: String,
    key_envelope: KeyEnvelopeFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveSegmentFile {
    segment_id: u64,
    start_sequence: u64,
    next_sequence: u64,
    previous_segment_authenticator: String,
    head_authenticator: String,
    key_envelope: KeyEnvelopeFile,
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

    use super::{DescriptorStore, VaultDescriptorV3, parse, serialize};
    use crate::{
        crypto::EncryptedEnvelope,
        vault::{
            VaultError,
            audit_recovery::{
                AnchorMode, AuditRotationManifest, AuditRotationPlan, RecoveryState, VaultEvidence,
            },
            audit_segment_store::segment_digest,
        },
    };

    const DESCRIPTOR_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/vault-descriptor-v3.json"
    ));
    const SEGMENT_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/segment-v2.json"
    ));

    fn fixture_payload(bytes: &[u8]) -> &[u8] {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    }

    fn descriptor() -> Result<VaultDescriptorV3, VaultError> {
        parse(fixture_payload(DESCRIPTOR_VECTOR))
    }

    fn manifest() -> Result<AuditRotationManifest, VaultError> {
        let segment = fixture_payload(SEGMENT_VECTOR);
        AuditRotationManifest::new(AuditRotationPlan {
            vault_id: [0x11; 16],
            operation_id: [0x22; 16],
            expected_vault_generation: 9,
            segment_id: 7,
            start_sequence: 42,
            end_sequence: 42,
            terminal_authenticator: [0x55; 16],
            segment_digest: segment_digest(segment),
            next_active_key_envelope: test_key_envelope(),
            anchor_mode: AnchorMode::Mandatory,
            expected_anchor_generation: 2,
        })
    }

    fn test_key_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            nonce: [0x44; EncryptedEnvelope::NONCE_LENGTH],
            ciphertext: vec![0x66; 32 + EncryptedEnvelope::TAG_LENGTH],
        }
    }

    #[test]
    fn descriptor_vector_is_canonical_and_strict() -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = descriptor()?;
        assert_eq!(serialize(&descriptor)?, fixture_payload(DESCRIPTOR_VECTOR));
        assert_eq!(parse(&serialize(&descriptor)?)?, descriptor);

        let mut document: Value = serde_json::from_slice(DESCRIPTOR_VECTOR)?;
        document["unknown"] = Value::Bool(true);
        assert!(parse(&serde_json::to_vec(&document)?).is_err());
        document.as_object_mut().ok_or("object")?.remove("unknown");
        document["version"] = Value::from(99_u64);
        assert!(matches!(
            parse(&serde_json::to_vec(&document)?),
            Err(VaultError::UnsupportedVersion)
        ));
        Ok(())
    }

    #[test]
    fn rotation_appends_an_exact_reference_and_advances_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = descriptor()?;
        let manifest = manifest()?.advance(RecoveryState::SealedFileSynced)?;
        assert_eq!(
            expected.rotation_evidence(&manifest),
            VaultEvidence::ExpectedGeneration
        );
        let committed = expected.rotated(&manifest, [0x22; 16])?;
        assert_eq!(
            committed.rotation_evidence(&manifest),
            VaultEvidence::ReferencesSegment
        );
        assert_eq!(
            serialize(&parse(&serialize(&committed)?)?)?,
            serialize(&committed)?
        );
        Ok(())
    }

    #[test]
    fn store_commit_is_private_atomic_and_generation_checked()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let expected = descriptor()?;
        let store = DescriptorStore::create_for_vault(&vault_path, &expected)?;
        let sealed = manifest()?.advance(RecoveryState::SealedFileSynced)?;
        let committed = store.commit_rotation(&sealed, [0x22; 16])?;
        assert_eq!(store.load()?, committed);
        assert!(matches!(
            store.commit_rotation(&sealed, [0x22; 16]),
            Err(VaultError::ConcurrentModification)
        ));
        assert_eq!(store.load()?, committed);
        Ok(())
    }

    #[test]
    fn tampered_or_noncanonical_descriptor_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let store = DescriptorStore::create_for_vault(&vault_path, &descriptor()?)?;
        let mut document: Value = serde_json::from_slice(DESCRIPTOR_VECTOR)?;
        document["generation"] = Value::from(8_u64);
        fs::write(&store.path, serde_json::to_vec_pretty(&document)?)?;
        assert!(store.load().is_err());
        assert!(store.collect_evidence(&manifest()?).is_err());
        Ok(())
    }
}
