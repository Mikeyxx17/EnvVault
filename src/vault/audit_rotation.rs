use std::path::Path;

use crate::{crypto::MasterKey, secure_fs};

use super::{
    VaultError,
    audit_descriptor::{DescriptorStore, lock_path_for},
    audit_recovery::{
        AnchorEvidence, ManifestStore, RecoveryAction, RecoveryEvidence, plan_recovery,
    },
    audit_segment_builder::unwrap_active_key,
    audit_segment_store::{SegmentStore, segment_predecessor},
};

/// Coordinates one idempotent local recovery step under the Vault lock.
pub(super) struct AuditRotationCoordinator {
    manifest_store: ManifestStore,
    segment_store: SegmentStore,
    descriptor_store: DescriptorStore,
    vault_lock_path: std::path::PathBuf,
}

impl AuditRotationCoordinator {
    pub(super) fn for_vault(vault_path: &Path) -> Result<Self, VaultError> {
        Ok(Self {
            manifest_store: ManifestStore::open_for_vault(vault_path),
            segment_store: SegmentStore::for_vault(vault_path)?,
            descriptor_store: DescriptorStore::for_vault(vault_path),
            vault_lock_path: lock_path_for(vault_path),
        })
    }

    /// Executes a local file action or returns the exact external/manual action required.
    pub(super) fn step(
        &self,
        master_key: &MasterKey,
        canonical_segment: Option<&[u8]>,
        anchor: AnchorEvidence,
    ) -> Result<RecoveryAction, VaultError> {
        self.step_internal(Some(master_key), canonical_segment, anchor)
    }

    #[cfg(test)]
    fn step_metadata_only(
        &self,
        canonical_segment: Option<&[u8]>,
        anchor: AnchorEvidence,
    ) -> Result<RecoveryAction, VaultError> {
        self.step_internal(None, canonical_segment, anchor)
    }

    fn step_internal(
        &self,
        master_key: Option<&MasterKey>,
        canonical_segment: Option<&[u8]>,
        anchor: AnchorEvidence,
    ) -> Result<RecoveryAction, VaultError> {
        let vault_lock = secure_fs::open_lock(&self.vault_lock_path).map_err(map_secure_io)?;
        vault_lock.lock()?;
        let manifest = self.manifest_store.load()?;
        let segment = self.segment_store.collect_evidence(&manifest)?;
        let descriptor = self.descriptor_store.load()?;
        let mut vault = descriptor.rotation_evidence(&manifest);
        if let Some(master_key) = master_key {
            validate_key_envelopes(master_key, &descriptor, &manifest, vault)?;
        }
        let descriptor_predecessor = if vault == super::audit_recovery::VaultEvidence::Unexpected {
            None
        } else {
            Some(self.descriptor_store.collect_predecessor(&manifest)?)
        };
        if let Some(expected_predecessor) = descriptor_predecessor {
            let observed_predecessor =
                match self.segment_store.collect_predecessor(&manifest, segment)? {
                    Some(predecessor) => Some(predecessor),
                    None => canonical_segment.map(segment_predecessor).transpose()?,
                };
            if observed_predecessor.is_some_and(|value| value != expected_predecessor) {
                vault = super::audit_recovery::VaultEvidence::Unexpected;
            }
        }
        let action = plan_recovery(
            &manifest,
            RecoveryEvidence {
                staging: segment.staging,
                sealed: segment.sealed,
                vault,
                anchor,
            },
        );
        match action {
            RecoveryAction::RebuildOwnedStaging => self
                .segment_store
                .rebuild_staging(&manifest, canonical_segment.ok_or(VaultError::NotFound)?)?,
            RecoveryAction::SyncAndSealStaging => {
                self.segment_store.seal_staging(&manifest)?;
            }
            RecoveryAction::AdvanceManifest(next) => {
                self.manifest_store.advance(&manifest, next)?;
            }
            RecoveryAction::CommitVaultDescriptor => {
                self.descriptor_store.commit_rotation_under_vault_lock(
                    &manifest,
                    descriptor_predecessor.ok_or(VaultError::InvalidFormat)?,
                )?;
            }
            RecoveryAction::RemoveConfirmedManifest => {
                self.manifest_store.remove_confirmed(&manifest)?;
            }
            RecoveryAction::RetryMandatoryAnchorCas
            | RecoveryAction::RetryOptionalAnchorCas
            | RecoveryAction::StopForManualRecovery => {}
        }
        Ok(action)
    }
}

fn validate_key_envelopes(
    master_key: &MasterKey,
    descriptor: &super::audit_descriptor::VaultDescriptorV3,
    manifest: &super::audit_recovery::AuditRotationManifest,
    evidence: super::audit_recovery::VaultEvidence,
) -> Result<(), VaultError> {
    if evidence == super::audit_recovery::VaultEvidence::Unexpected {
        return Ok(());
    }
    let (segment_id, start_sequence, predecessor, current_envelope) = match evidence {
        super::audit_recovery::VaultEvidence::ExpectedGeneration => descriptor.active_key_context(),
        super::audit_recovery::VaultEvidence::ReferencesSegment => {
            let (start_sequence, predecessor, envelope) = descriptor
                .sealed_key_context(manifest.segment_id())
                .ok_or(VaultError::InvalidFormat)?;
            (manifest.segment_id(), start_sequence, predecessor, envelope)
        }
        super::audit_recovery::VaultEvidence::Unexpected => unreachable!(),
    };
    let _current_key = unwrap_active_key(
        master_key,
        descriptor.vault_id(),
        segment_id,
        start_sequence,
        predecessor,
        current_envelope,
    )?;
    let next_segment_id = manifest
        .segment_id()
        .checked_add(1)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let next_start_sequence = manifest
        .end_sequence()
        .checked_add(1)
        .ok_or(VaultError::ResourceLimitExceeded)?;
    let _next_key = unwrap_active_key(
        master_key,
        manifest.vault_id(),
        next_segment_id,
        next_start_sequence,
        manifest.terminal_authenticator(),
        manifest.next_active_key_envelope(),
    )?;
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
    use serde_json::Value;
    use tempfile::tempdir;

    use super::AuditRotationCoordinator;
    use crate::{
        crypto::EncryptedEnvelope,
        vault::{
            VaultError,
            audit_descriptor::{DescriptorStore, parse as parse_descriptor},
            audit_recovery::{
                AnchorEvidence, AnchorMode, AuditRotationManifest, AuditRotationPlan,
                ManifestStore, RecoveryAction, RecoveryState, VaultEvidence,
            },
            audit_segment_store::{SegmentStore, segment_digest},
            audit_v2::{parse_segment, serialize_segment},
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

    fn payload(bytes: &[u8]) -> &[u8] {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    }

    fn manifest() -> Result<AuditRotationManifest, VaultError> {
        manifest_for(payload(SEGMENT_VECTOR))
    }

    fn manifest_for(segment: &[u8]) -> Result<AuditRotationManifest, VaultError> {
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
    fn local_recovery_is_idempotently_orchestrated_through_vault_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let prepared = manifest()?;
        ManifestStore::create_for_vault(&vault_path, &prepared)?;
        DescriptorStore::create_for_vault(
            &vault_path,
            &parse_descriptor(payload(DESCRIPTOR_VECTOR))?,
        )?;
        let coordinator = AuditRotationCoordinator::for_vault(&vault_path)?;
        let segment = Some(payload(SEGMENT_VECTOR));

        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::RebuildOwnedStaging
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::SyncAndSealStaging
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::AdvanceManifest(RecoveryState::SealedFileSynced)
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::CommitVaultDescriptor
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::AdvanceManifest(RecoveryState::VaultCommitted)
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::Unavailable)?,
            RecoveryAction::RetryMandatoryAnchorCas
        );
        let committed_manifest = ManifestStore::open_for_vault(&vault_path).load()?;
        assert_eq!(committed_manifest.state(), RecoveryState::VaultCommitted);
        assert_eq!(
            DescriptorStore::for_vault(&vault_path).collect_evidence(&committed_manifest)?,
            VaultEvidence::ReferencesSegment
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::Matches)?,
            RecoveryAction::AdvanceManifest(RecoveryState::AnchorConfirmed)
        );
        assert_eq!(
            coordinator.step_metadata_only(segment, AnchorEvidence::Matches)?,
            RecoveryAction::RemoveConfirmedManifest
        );
        assert!(ManifestStore::open_for_vault(&vault_path).load().is_err());
        Ok(())
    }

    #[test]
    fn unexpected_descriptor_stops_before_creating_staging()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let prepared = manifest()?;
        ManifestStore::create_for_vault(&vault_path, &prepared)?;
        let mut document: Value = serde_json::from_slice(DESCRIPTOR_VECTOR)?;
        document["generation"] = Value::from(8_u64);
        DescriptorStore::create_for_vault(
            &vault_path,
            &parse_descriptor(&serde_json::to_vec(&document)?)?,
        )?;
        let coordinator = AuditRotationCoordinator::for_vault(&vault_path)?;

        assert_eq!(
            coordinator.step_metadata_only(
                Some(payload(SEGMENT_VECTOR)),
                AnchorEvidence::ExpectedGeneration
            )?,
            RecoveryAction::StopForManualRecovery
        );
        let evidence = SegmentStore::for_vault(&vault_path)?.collect_evidence(&prepared)?;
        assert_eq!(
            evidence.staging,
            crate::vault::audit_recovery::ArtifactEvidence::Missing
        );
        Ok(())
    }

    #[test]
    fn segment_predecessor_mismatch_stops_before_staging_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault_path = directory.path().join("vault.json");
        let mut document: Value = serde_json::from_slice(SEGMENT_VECTOR)?;
        document["previous_segment_authenticator"] = Value::from("MzMzMzMzMzMzMzMzMzMzMw==");
        let altered = serialize_segment(&parse_segment(&serde_json::to_vec(&document)?)?)?;
        let prepared = manifest_for(&altered)?;
        ManifestStore::create_for_vault(&vault_path, &prepared)?;
        DescriptorStore::create_for_vault(
            &vault_path,
            &parse_descriptor(payload(DESCRIPTOR_VECTOR))?,
        )?;
        let coordinator = AuditRotationCoordinator::for_vault(&vault_path)?;

        assert_eq!(
            coordinator.step_metadata_only(Some(&altered), AnchorEvidence::ExpectedGeneration)?,
            RecoveryAction::StopForManualRecovery
        );
        let evidence = SegmentStore::for_vault(&vault_path)?.collect_evidence(&prepared)?;
        assert_eq!(
            evidence.staging,
            crate::vault::audit_recovery::ArtifactEvidence::Missing
        );
        Ok(())
    }
}
