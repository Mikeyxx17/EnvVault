use std::{
    ffi::OsString,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;

use crate::{crypto::sha256, secure_fs};

use super::{
    VaultError,
    audit_recovery::{AnchorEvidence, AuditRotationManifest},
    audit_v2::{AuditAnchorV2, MAX_ANCHOR_FILE_BYTES, parse_anchor, serialize_anchor},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AnchorCasResult {
    Applied,
    AlreadyApplied,
    Conflict,
}

pub(super) trait AnchorSink: Send {
    fn load(&mut self) -> Result<Option<Vec<u8>>, VaultError>;

    fn compare_and_set(
        &mut self,
        expected_generation: u64,
        canonical_anchor: &[u8],
    ) -> Result<AnchorCasResult, VaultError>;
}

pub(super) struct LocalMirrorAnchorSink {
    path: PathBuf,
    lock_path: PathBuf,
}

impl LocalMirrorAnchorSink {
    pub(super) fn for_vault(vault_path: &Path) -> Self {
        let path = anchor_path_for(vault_path);
        let lock_path = sidecar_lock_path(&path);
        Self { path, lock_path }
    }
}

impl AnchorSink for LocalMirrorAnchorSink {
    fn load(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        read_optional_canonical(&self.path)
    }

    fn compare_and_set(
        &mut self,
        expected_generation: u64,
        canonical_anchor: &[u8],
    ) -> Result<AnchorCasResult, VaultError> {
        let proposed = parse_anchor(canonical_anchor)?;
        if serialize_anchor(&proposed)? != canonical_anchor
            || proposed.anchor_generation()
                != expected_generation
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)?
        {
            return Err(VaultError::InvalidFormat);
        }
        let lock = secure_fs::open_lock(&self.lock_path).map_err(map_secure_io)?;
        lock.lock()?;
        let current = read_optional_canonical(&self.path)?;
        if current.as_deref() == Some(canonical_anchor) {
            return Ok(AnchorCasResult::AlreadyApplied);
        }
        match current {
            None if expected_generation == 0 => write_new(&self.path, canonical_anchor)?,
            Some(bytes) => {
                let observed = parse_anchor(&bytes)?;
                if observed.anchor_generation() != expected_generation
                    || proposed.vault_id() != observed.vault_id()
                    || proposed.previous_anchor_digest() != sha256(&bytes)
                    || proposed.segment_id() <= observed.segment_id()
                    || proposed.sequence() <= observed.sequence()
                {
                    return Ok(AnchorCasResult::Conflict);
                }
                write_atomically(&self.path, canonical_anchor)?;
            }
            None => return Ok(AnchorCasResult::Conflict),
        }
        Ok(AnchorCasResult::Applied)
    }
}

pub(super) fn desired_anchor(
    manifest: &AuditRotationManifest,
    current: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
    let previous_anchor_digest = match current {
        Some(bytes) => {
            let anchor = parse_anchor(bytes)?;
            if serialize_anchor(&anchor)? != bytes
                || anchor.vault_id() != manifest.vault_id()
                || anchor.anchor_generation() != manifest.expected_anchor_generation()
            {
                return Err(VaultError::InvalidFormat);
            }
            sha256(bytes)
        }
        None if manifest.expected_anchor_generation() == 0 => [0_u8; 32],
        None => return Err(VaultError::InvalidFormat),
    };
    serialize_anchor(&AuditAnchorV2::new(
        manifest.vault_id(),
        manifest.committed_anchor_generation(),
        manifest.segment_id(),
        manifest.end_sequence(),
        manifest.terminal_authenticator(),
        previous_anchor_digest,
        0,
    )?)
}

pub(super) fn collect_anchor_evidence(
    sink: &mut dyn AnchorSink,
    manifest: &AuditRotationManifest,
) -> (AnchorEvidence, Vec<u8>) {
    let Ok(current) = sink.load() else {
        return (AnchorEvidence::Unavailable, Vec::new());
    };
    if let Some(bytes) = current.as_deref() {
        let observed = match parse_anchor(bytes) {
            Ok(anchor) if serialize_anchor(&anchor).ok().as_deref() == Some(bytes) => anchor,
            _ => return (AnchorEvidence::Conflict, Vec::new()),
        };
        if observed.vault_id() == manifest.vault_id()
            && observed.anchor_generation() == manifest.committed_anchor_generation()
            && observed.segment_id() == manifest.segment_id()
            && observed.sequence() == manifest.end_sequence()
            && observed.terminal_authenticator() == manifest.terminal_authenticator()
        {
            return (AnchorEvidence::Matches, bytes.to_vec());
        }
    }
    let Ok(desired) = desired_anchor(manifest, current.as_deref()) else {
        return (AnchorEvidence::Conflict, Vec::new());
    };
    (AnchorEvidence::ExpectedGeneration, desired)
}

fn read_optional_canonical(path: &Path) -> Result<Option<Vec<u8>>, VaultError> {
    let file = match secure_fs::open_existing(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(map_secure_io(error)),
    };
    let length = file.metadata()?.len();
    if length > u64::try_from(MAX_ANCHOR_FILE_BYTES).unwrap_or(u64::MAX) {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?);
    file.take(
        u64::try_from(MAX_ANCHOR_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1),
    )
    .read_to_end(&mut bytes)?;
    let anchor = parse_anchor(&bytes)?;
    if serialize_anchor(&anchor)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(Some(bytes))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let mut file = secure_fs::create_new(path).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    let mut file = AtomicWriteFile::open(path)?;
    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(path).map_err(map_secure_io)
}

pub(super) fn anchor_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".audit-anchor-v2.json");
    PathBuf::from(value)
}

fn sidecar_lock_path(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
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
    use tempfile::tempdir;

    use super::{AnchorCasResult, AnchorSink, LocalMirrorAnchorSink};
    use crate::{
        crypto::sha256,
        vault::audit_v2::{AuditAnchorV2, serialize_anchor},
    };

    fn anchor(
        generation: u64,
        terminal: [u8; 16],
        previous: [u8; 32],
    ) -> Result<Vec<u8>, crate::vault::VaultError> {
        serialize_anchor(&AuditAnchorV2::new(
            [0x11; 16], generation, generation, generation, terminal, previous, 0,
        )?)
    }

    #[test]
    fn local_mirror_uses_exact_generation_cas_and_idempotent_retry()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let mut sink = LocalMirrorAnchorSink::for_vault(&vault);
        let first = anchor(1, [0x22; 16], [0_u8; 32])?;
        assert_eq!(sink.compare_and_set(0, &first)?, AnchorCasResult::Applied);
        assert_eq!(
            sink.compare_and_set(0, &first)?,
            AnchorCasResult::AlreadyApplied
        );
        assert_eq!(
            sink.compare_and_set(0, &anchor(1, [0x22; 16], [0_u8; 32])?)?,
            AnchorCasResult::AlreadyApplied
        );
        assert_eq!(
            sink.compare_and_set(0, &anchor(1, [0x33; 16], [0_u8; 32])?)?,
            AnchorCasResult::Conflict
        );
        let second = anchor(2, [0x44; 16], sha256(&first))?;
        assert_eq!(sink.compare_and_set(1, &second)?, AnchorCasResult::Applied);
        assert_eq!(
            sink.compare_and_set(1, &anchor(2, [0x55; 16], [0x77; 32])?)?,
            AnchorCasResult::Conflict
        );
        Ok(())
    }
}
