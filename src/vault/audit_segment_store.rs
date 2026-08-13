use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use crate::{crypto::sha256, secure_fs};

use super::{
    VaultError,
    audit_recovery::{ArtifactEvidence, AuditRotationManifest},
    audit_v2::{MAX_SEGMENT_FILE_BYTES, parse_segment, serialize_segment},
};

pub(super) struct SegmentStore {
    directory: PathBuf,
}

impl SegmentStore {
    pub(super) fn for_vault(vault_path: &Path) -> Result<Self, VaultError> {
        let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
        secure_fs::ensure_safe_path(parent, false).map_err(map_secure_io)?;
        let directory = parent.canonicalize().map_err(VaultError::from)?;
        Ok(Self { directory })
    }

    pub(super) fn collect_evidence(
        &self,
        manifest: &AuditRotationManifest,
    ) -> Result<SegmentEvidence, VaultError> {
        Ok(SegmentEvidence {
            staging: inspect(&self.staging_path(manifest), manifest)?,
            sealed: inspect(&self.sealed_path(manifest), manifest)?,
        })
    }

    pub(super) fn read_sealed(
        &self,
        manifest: &AuditRotationManifest,
    ) -> Result<Vec<u8>, VaultError> {
        read_canonical_segment(&self.sealed_path(manifest))
    }

    pub(super) fn collect_predecessor(
        &self,
        manifest: &AuditRotationManifest,
        evidence: SegmentEvidence,
    ) -> Result<Option<[u8; 16]>, VaultError> {
        if evidence.sealed == ArtifactEvidence::MatchesDigest {
            return read_segment_predecessor(&self.sealed_path(manifest)).map(Some);
        }
        if evidence.staging == ArtifactEvidence::MatchesDigest {
            return read_segment_predecessor(&self.staging_path(manifest)).map(Some);
        }
        Ok(None)
    }

    pub(super) fn rebuild_staging(
        &self,
        manifest: &AuditRotationManifest,
        canonical_segment: &[u8],
    ) -> Result<(), VaultError> {
        if !matches_manifest(canonical_segment, manifest)? {
            return Err(VaultError::InvalidFormat);
        }
        let evidence = self.collect_evidence(manifest)?;
        if evidence.sealed != ArtifactEvidence::Missing {
            return Err(VaultError::InvalidFormat);
        }
        let staging = self.staging_path(manifest);
        match evidence.staging {
            ArtifactEvidence::MatchesDigest => return Ok(()),
            ArtifactEvidence::Missing => {}
            ArtifactEvidence::Empty | ArtifactEvidence::Mismatch => {
                remove_owned_staging(&staging)?;
            }
        }
        write_private_new(&staging, canonical_segment)?;
        if inspect(&staging, manifest)? != ArtifactEvidence::MatchesDigest {
            return Err(VaultError::InvalidFormat);
        }
        Ok(())
    }

    pub(super) fn seal_staging(&self, manifest: &AuditRotationManifest) -> Result<(), VaultError> {
        let evidence = self.collect_evidence(manifest)?;
        let staging = self.staging_path(manifest);
        let sealed = self.sealed_path(manifest);
        match evidence.sealed {
            ArtifactEvidence::MatchesDigest => {
                remove_owned_staging_if_present(&staging)?;
                return Ok(());
            }
            ArtifactEvidence::Empty | ArtifactEvidence::Mismatch => {
                return Err(VaultError::InvalidFormat);
            }
            ArtifactEvidence::Missing => {}
        }
        if evidence.staging != ArtifactEvidence::MatchesDigest {
            return Err(VaultError::InvalidFormat);
        }
        secure_fs::ensure_safe_path(&staging, false).map_err(map_secure_io)?;
        secure_fs::ensure_safe_path(&sealed, true).map_err(map_secure_io)?;
        fs::hard_link(&staging, &sealed)?;
        if inspect(&sealed, manifest)? != ArtifactEvidence::MatchesDigest {
            return Err(VaultError::InvalidFormat);
        }
        remove_owned_staging(&staging)
    }

    fn staging_path(&self, manifest: &AuditRotationManifest) -> PathBuf {
        self.directory.join(manifest.staging_file())
    }

    fn sealed_path(&self, manifest: &AuditRotationManifest) -> PathBuf {
        self.directory.join(manifest.sealed_file())
    }
}

pub(super) fn read_canonical_segment(path: &Path) -> Result<Vec<u8>, VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    let length = file.metadata()?.len();
    if length > u64::try_from(MAX_SEGMENT_FILE_BYTES).unwrap_or(u64::MAX) {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?);
    file.take(
        u64::try_from(MAX_SEGMENT_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)?;
    let segment = parse_segment(&bytes)?;
    if serialize_segment(&segment)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(bytes)
}

pub(super) fn active_segment_path(vault_path: &Path, segment_id: u64) -> PathBuf {
    let mut value = std::ffi::OsString::from(vault_path.as_os_str());
    value.push(format!(".audit-active-v2-{segment_id:020}.json"));
    PathBuf::from(value)
}

pub(super) fn sealed_segment_path(
    vault_path: &Path,
    segment_id: u64,
) -> Result<PathBuf, VaultError> {
    if segment_id == 0 {
        return Err(VaultError::InvalidFormat);
    }
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    secure_fs::ensure_safe_path(parent, false).map_err(map_secure_io)?;
    Ok(parent.join(format!("envvault-audit-segment-{segment_id:020}.json")))
}

pub(super) fn write_active_new(
    vault_path: &Path,
    segment_id: u64,
    bytes: &[u8],
) -> Result<(), VaultError> {
    let path = active_segment_path(vault_path, segment_id);
    let mut file = secure_fs::create_new(&path).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn write_active_atomically(
    vault_path: &Path,
    segment_id: u64,
    bytes: &[u8],
) -> Result<(), VaultError> {
    let path = active_segment_path(vault_path, segment_id);
    secure_fs::ensure_safe_path(&path, false).map_err(map_secure_io)?;
    let mut file = atomic_write_file::AtomicWriteFile::open(&path)?;
    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(&path).map_err(map_secure_io)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SegmentEvidence {
    pub(super) staging: ArtifactEvidence,
    pub(super) sealed: ArtifactEvidence,
}

pub(super) fn segment_digest(canonical_segment: &[u8]) -> [u8; 32] {
    sha256(canonical_segment)
}

pub(super) fn segment_predecessor(canonical_segment: &[u8]) -> Result<[u8; 16], VaultError> {
    let segment = parse_segment(canonical_segment)?;
    if serialize_segment(&segment)? != canonical_segment {
        return Err(VaultError::InvalidFormat);
    }
    Ok(segment.previous_segment_authenticator())
}

fn read_segment_predecessor(path: &Path) -> Result<[u8; 16], VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    let length = file.metadata()?.len();
    if length > u64::try_from(MAX_SEGMENT_FILE_BYTES).unwrap_or(u64::MAX) {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let capacity = usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(
        u64::try_from(MAX_SEGMENT_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)?;
    segment_predecessor(&bytes)
}

fn inspect(path: &Path, manifest: &AuditRotationManifest) -> Result<ArtifactEvidence, VaultError> {
    let file = match secure_fs::open_existing(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ArtifactEvidence::Missing);
        }
        Err(error) => return Err(map_secure_io(error)),
    };
    let length = file.metadata()?.len();
    if length == 0 {
        return Ok(ArtifactEvidence::Empty);
    }
    if length > u64::try_from(MAX_SEGMENT_FILE_BYTES).unwrap_or(u64::MAX) {
        return Ok(ArtifactEvidence::Mismatch);
    }
    let capacity = usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(
        u64::try_from(MAX_SEGMENT_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)?;
    if matches_manifest(&bytes, manifest).unwrap_or(false) {
        Ok(ArtifactEvidence::MatchesDigest)
    } else {
        Ok(ArtifactEvidence::Mismatch)
    }
}

fn matches_manifest(bytes: &[u8], manifest: &AuditRotationManifest) -> Result<bool, VaultError> {
    let Ok(segment) = parse_segment(bytes) else {
        return Ok(false);
    };
    if serialize_segment(&segment)? != bytes {
        return Ok(false);
    }
    Ok(segment.vault_id() == manifest.vault_id()
        && segment.segment_id() == manifest.segment_id()
        && segment.start_sequence() == manifest.start_sequence()
        && segment.end_sequence() == manifest.end_sequence()
        && segment.terminal_authenticator() == manifest.terminal_authenticator()
        && segment_digest(bytes) == manifest.segment_digest())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let mut file = secure_fs::create_new(path).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_owned_staging_if_present(path: &Path) -> Result<(), VaultError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => remove_owned_staging(path),
    }
}

fn remove_owned_staging(path: &Path) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    fs::remove_file(path)?;
    Ok(())
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
    use std::{fs, io::Write as _};

    use tempfile::tempdir;

    use super::{SegmentStore, segment_digest};
    use crate::{
        crypto::EncryptedEnvelope,
        secure_fs,
        vault::{
            VaultError,
            audit_recovery::{
                AnchorEvidence, AnchorMode, ArtifactEvidence, AuditRotationManifest,
                AuditRotationPlan, RecoveryAction, RecoveryEvidence, RecoveryState, VaultEvidence,
                plan_recovery,
            },
        },
    };

    const SEGMENT_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/audit_v2/segment-v2.json"
    ));

    fn canonical_segment() -> &'static [u8] {
        SEGMENT_VECTOR.strip_suffix(b"\n").unwrap_or(SEGMENT_VECTOR)
    }

    fn manifest() -> Result<AuditRotationManifest, VaultError> {
        AuditRotationManifest::new(AuditRotationPlan {
            vault_id: [0x11; 16],
            operation_id: [0x22; 16],
            expected_vault_generation: 9,
            segment_id: 7,
            start_sequence: 42,
            end_sequence: 42,
            terminal_authenticator: [0x55; 16],
            segment_digest: segment_digest(canonical_segment()),
            next_active_key_envelope: test_key_envelope(),
            anchor_mode: AnchorMode::Mandatory,
            expected_anchor_generation: 2,
        })
    }

    #[test]
    fn sha256_matches_the_published_segment_vector() {
        assert_eq!(
            segment_digest(canonical_segment()),
            [
                0xc4, 0xf1, 0x6e, 0x20, 0x39, 0x30, 0x89, 0x1a, 0x55, 0xfb, 0x3e, 0xc3, 0x28, 0xa3,
                0x34, 0x89, 0x30, 0x41, 0xca, 0x5d, 0x18, 0x9a, 0x01, 0x0a, 0xad, 0x81, 0xd5, 0x43,
                0xe9, 0x2e, 0x93, 0x9e,
            ]
        );
    }

    #[test]
    fn file_failpoints_rebuild_and_seal_without_overwrite() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let manifest = manifest()?;
        let store = SegmentStore::for_vault(&vault_path)?;

        let evidence = store.collect_evidence(&manifest)?;
        assert_eq!(evidence.staging, ArtifactEvidence::Missing);
        assert_eq!(evidence.sealed, ArtifactEvidence::Missing);

        drop(secure_fs::create_new(&store.staging_path(&manifest))?);
        assert_eq!(
            store.collect_evidence(&manifest)?.staging,
            ArtifactEvidence::Empty
        );

        let mut partial = secure_fs::open_existing_read_write(&store.staging_path(&manifest))?;
        partial.write_all(&canonical_segment()[..32])?;
        partial.sync_all()?;
        drop(partial);
        assert_eq!(
            store.collect_evidence(&manifest)?.staging,
            ArtifactEvidence::Mismatch
        );

        store.rebuild_staging(&manifest, canonical_segment())?;
        assert_eq!(
            store.collect_evidence(&manifest)?.staging,
            ArtifactEvidence::MatchesDigest
        );
        store.seal_staging(&manifest)?;
        let evidence = store.collect_evidence(&manifest)?;
        assert_eq!(evidence.staging, ArtifactEvidence::Missing);
        assert_eq!(evidence.sealed, ArtifactEvidence::MatchesDigest);
        store.seal_staging(&manifest)?;

        assert_eq!(
            plan_recovery(
                &manifest,
                RecoveryEvidence {
                    staging: ArtifactEvidence::Missing,
                    sealed: evidence.sealed,
                    vault: VaultEvidence::ExpectedGeneration,
                    anchor: AnchorEvidence::ExpectedGeneration,
                },
            ),
            RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced)
        );
        Ok(())
    }

    #[test]
    fn existing_mismatched_final_file_is_never_overwritten()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let manifest = manifest()?;
        let store = SegmentStore::for_vault(&vault_path)?;
        store.rebuild_staging(&manifest, canonical_segment())?;
        let sealed_path = store.sealed_path(&manifest);
        let mut sealed = secure_fs::create_new(&sealed_path)?;
        sealed.write_all(b"unrelated-final-evidence")?;
        sealed.sync_all()?;
        drop(sealed);
        let before = fs::read(&sealed_path)?;

        assert!(matches!(
            store.seal_staging(&manifest),
            Err(VaultError::InvalidFormat)
        ));
        assert_eq!(fs::read(&sealed_path)?, before);
        assert_eq!(
            store.collect_evidence(&manifest)?.sealed,
            ArtifactEvidence::Mismatch
        );
        Ok(())
    }

    #[test]
    fn tampered_sealed_file_stops_committed_recovery() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let manifest = manifest()?;
        let store = SegmentStore::for_vault(&vault_path)?;
        store.rebuild_staging(&manifest, canonical_segment())?;
        store.seal_staging(&manifest)?;
        fs::write(store.sealed_path(&manifest), b"tampered")?;
        let evidence = store.collect_evidence(&manifest)?;
        let committed = manifest
            .advance(RecoveryState::SealedFileSynced)?
            .advance(RecoveryState::VaultCommitted)?;

        assert_eq!(evidence.sealed, ArtifactEvidence::Mismatch);
        assert_eq!(
            plan_recovery(
                &committed,
                RecoveryEvidence {
                    staging: evidence.staging,
                    sealed: evidence.sealed,
                    vault: VaultEvidence::ReferencesSegment,
                    anchor: AnchorEvidence::Matches,
                },
            ),
            RecoveryAction::StopForManualRecovery
        );
        Ok(())
    }

    #[test]
    fn digest_match_cannot_hide_segment_identity_mismatch() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let wrong_manifest = AuditRotationManifest::new(AuditRotationPlan {
            vault_id: [0x11; 16],
            operation_id: [0x33; 16],
            expected_vault_generation: 9,
            segment_id: 8,
            start_sequence: 42,
            end_sequence: 42,
            terminal_authenticator: [0x55; 16],
            segment_digest: segment_digest(canonical_segment()),
            next_active_key_envelope: test_key_envelope(),
            anchor_mode: AnchorMode::Mandatory,
            expected_anchor_generation: 2,
        })?;
        let store = SegmentStore::for_vault(&vault_path)?;

        assert!(matches!(
            store.rebuild_staging(&wrong_manifest, canonical_segment()),
            Err(VaultError::InvalidFormat)
        ));
        assert_eq!(
            store.collect_evidence(&wrong_manifest)?.staging,
            ArtifactEvidence::Missing
        );
        Ok(())
    }

    fn test_key_envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            nonce: [0x44; EncryptedEnvelope::NONCE_LENGTH],
            ciphertext: vec![0x66; 32 + EncryptedEnvelope::TAG_LENGTH],
        }
    }
}
