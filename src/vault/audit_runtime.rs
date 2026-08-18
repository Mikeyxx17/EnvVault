use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    audit::AuditEvent,
    crypto::{AuditKey, MasterKey, generate_array, sha256},
    secure_fs,
};

use super::{
    VaultError,
    anchor_http::HttpAnchorTransport,
    anchor_protocol::ProtocolAnchorClient,
    anchor_store::{ConfirmedAnchorFile, load_anchor_client_config, load_anchor_token},
    audit_anchor::{AnchorCasResult, AnchorSink, LocalMirrorAnchorSink, collect_anchor_evidence},
    audit_descriptor::{DescriptorStore, lock_path_for},
    audit_recovery::{AnchorEvidence, AnchorMode, ManifestStore, RecoveryAction, RecoveryState},
    audit_rotation::AuditRotationCoordinator,
    audit_segment_builder::{
        AuditSegmentBuilderV2, prepare_rotation_for_vault, unwrap_active_key,
        verify_and_decode_segment, wrap_active_key,
    },
    audit_segment_store::{
        active_segment_path, read_canonical_segment, write_active_atomically, write_active_new,
    },
    audit_v2::parse_segment,
};

pub(super) const DEFAULT_ROTATION_EVENTS: usize = 1_024;
const DEFAULT_ROTATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECOVERY_STEPS: usize = 16;
const MIGRATION_FORMAT: &str = "envvault-audit-v2-migration";
const MIGRATION_VERSION: u32 = 1;
const MAX_MIGRATION_MARKER_BYTES: u64 = 4 * 1024;

pub(crate) struct AuditRuntimeV2 {
    anchor_mode: AnchorMode,
    rotation_events: usize,
    anchor_sink: Box<dyn AnchorSink>,
}

impl AuditRuntimeV2 {
    pub(crate) fn local_mirror() -> Self {
        Self {
            anchor_mode: AnchorMode::LocalMirror,
            rotation_events: DEFAULT_ROTATION_EVENTS,
            anchor_sink: Box::new(UnconfiguredSink),
        }
    }

    /// Use a configured mandatory remote sink, or the local mirror default.
    pub(crate) fn for_vault(vault_path: &Path, vault_id: [u8; 16]) -> Result<Self, VaultError> {
        let Some(config) = load_anchor_client_config(vault_path)? else {
            return Ok(Self::local_mirror());
        };
        let token = load_anchor_token(&config.token_file)?;
        let confirmed = ConfirmedAnchorFile::for_vault(vault_path, vault_id);
        let last_confirmed = confirmed.load()?;
        let transport =
            HttpAnchorTransport::new(&config.endpoint, token, config.tls_ca.as_deref())?;
        let mut client = ProtocolAnchorClient::new(vault_id, transport, sleep_before_retry);
        client.restore_last_confirmed(last_confirmed);
        client.set_persistence(Box::new(confirmed));
        Ok(Self::mandatory(Box::new(client)))
    }

    #[cfg(any(test, feature = "fault-injection"))]
    pub(crate) fn local_mirror_with_rotation_events(rotation_events: usize) -> Self {
        Self {
            anchor_mode: AnchorMode::LocalMirror,
            rotation_events,
            anchor_sink: Box::new(UnconfiguredSink),
        }
    }

    #[cfg(test)]
    fn with_rotation_events(mut self, rotation_events: usize) -> Self {
        self.rotation_events = rotation_events;
        self
    }

    pub(super) fn mandatory(anchor_sink: Box<dyn AnchorSink>) -> Self {
        Self {
            anchor_mode: AnchorMode::Mandatory,
            rotation_events: DEFAULT_ROTATION_EVENTS,
            anchor_sink,
        }
    }

    pub(crate) fn initialize_new(
        vault_path: &Path,
        vault_id: [u8; 16],
        master_key: &MasterKey,
    ) -> Result<(), VaultError> {
        let key_bytes = Zeroizing::new(
            generate_array::<{ AuditKey::LENGTH }>()
                .map_err(|_| VaultError::RandomSourceUnavailable)?,
        );
        let envelope = wrap_active_key(master_key, vault_id, 1, 1, [0_u8; 16], &key_bytes)?;
        let descriptor =
            super::audit_descriptor::VaultDescriptorV3::new_empty(vault_id, 1, envelope)?;
        DescriptorStore::create_for_vault(vault_path, &descriptor)?;
        Ok(())
    }

    pub(crate) fn exists(vault_path: &Path) -> Result<bool, VaultError> {
        Ok(DescriptorStore::exists_for_vault(vault_path)?
            && !migration_marker_path(vault_path).exists())
    }

    pub(crate) fn migration_in_progress(vault_path: &Path) -> Result<bool, VaultError> {
        let path = migration_marker_path(vault_path);
        secure_fs::ensure_safe_path(&path, true).map_err(map_secure_io)?;
        Ok(path.exists())
    }

    pub(crate) fn migrate_v1(
        vault_path: &Path,
        vault_id: [u8; 16],
        master_key: &MasterKey,
        events: &[AuditEvent],
    ) -> Result<(), VaultError> {
        let marker_path = migration_marker_path(vault_path);
        let expected_marker = MigrationMarker::new(vault_id, events)?;
        if marker_path.exists() {
            if read_migration_marker(&marker_path)? != expected_marker {
                return Err(VaultError::ConcurrentModification);
            }
        } else if DescriptorStore::for_vault(vault_path).load().is_ok() {
            return Err(VaultError::AlreadyExists);
        } else {
            write_migration_marker(&marker_path, &expected_marker)?;
            fault_injection_pause();
        }
        if !DescriptorStore::exists_for_vault(vault_path)? {
            Self::initialize_new(vault_path, vault_id, master_key)?;
            fault_injection_pause();
        }
        let mut runtime = Self::local_mirror();
        let copied = runtime.read_all(vault_path, master_key)?;
        if copied.len() > events.len() || copied.as_slice() != &events[..copied.len()] {
            return Err(VaultError::CorruptedAudit);
        }
        for event in &events[copied.len()..] {
            runtime.append(vault_path, master_key, *event)?;
        }
        if runtime.read_all(vault_path, master_key)? != events {
            return Err(VaultError::CorruptedAudit);
        }
        remove_migration_marker(&marker_path)?;
        Ok(())
    }

    pub(crate) fn append(
        &mut self,
        vault_path: &Path,
        master_key: &MasterKey,
        event: AuditEvent,
    ) -> Result<(), VaultError> {
        self.attach_local_sink_if_needed(vault_path);
        self.recover(vault_path, master_key)?;
        if ManifestStore::exists_for_vault(vault_path)? && self.anchor_mode == AnchorMode::Mandatory
        {
            return Err(VaultError::AuditAnchorDegraded);
        }
        let vault_lock = secure_fs::open_lock(&lock_path_for(vault_path)).map_err(map_secure_io)?;
        vault_lock.lock()?;
        let store = DescriptorStore::for_vault(vault_path);
        let descriptor = store.load()?;
        let (segment_id, start_sequence, predecessor, envelope) = descriptor.active_key_context();
        let key = unwrap_active_key(
            master_key,
            descriptor.vault_id(),
            segment_id,
            start_sequence,
            predecessor,
            envelope,
        )?;
        let path = active_segment_path(vault_path, segment_id);
        let mut builder = if path.exists() {
            let bytes = read_canonical_segment(&path)?;
            let segment = parse_segment(&bytes)?;
            verify_and_decode_segment(&key, &bytes)?;
            let descriptor = store.reconcile_active_under_vault_lock(&segment)?;
            if !descriptor.matches_active_segment(&segment) {
                return Err(VaultError::ConcurrentModification);
            }
            AuditSegmentBuilderV2::resume(segment, key)?
        } else if descriptor.active_is_empty() {
            AuditSegmentBuilderV2::new(
                descriptor.vault_id(),
                segment_id,
                start_sequence,
                current_unix_time_millis(),
                predecessor,
                key,
            )?
        } else {
            return Err(VaultError::CorruptedAudit);
        };
        builder.append(event)?;
        let bytes = builder.seal()?;
        let segment = parse_segment(&bytes)?;
        if path.exists() {
            write_active_atomically(vault_path, segment_id, &bytes)?;
        } else {
            write_active_new(vault_path, segment_id, &bytes)?;
        }
        store.update_active_under_vault_lock(&descriptor, &segment)?;
        drop(vault_lock);

        if segment.encrypted_events().count() >= self.rotation_events
            || bytes.len() >= DEFAULT_ROTATION_BYTES
        {
            self.rotate(vault_path, master_key, &bytes)?;
        }
        Ok(())
    }

    pub(crate) fn read_all(
        &mut self,
        vault_path: &Path,
        master_key: &MasterKey,
    ) -> Result<Vec<AuditEvent>, VaultError> {
        self.attach_local_sink_if_needed(vault_path);
        self.recover(vault_path, master_key)?;
        let descriptor = DescriptorStore::for_vault(vault_path).load()?;
        let mut events = Vec::new();
        for segment_id in descriptor.sealed_segment_ids() {
            let (start, predecessor, envelope) = descriptor
                .sealed_key_context(segment_id)
                .ok_or(VaultError::CorruptedAudit)?;
            let key = unwrap_active_key(
                master_key,
                descriptor.vault_id(),
                segment_id,
                start,
                predecessor,
                envelope,
            )?;
            let path = super::audit_segment_store::sealed_segment_path(vault_path, segment_id)?;
            events.extend(verify_and_decode_segment(
                &key,
                &read_canonical_segment(&path)?,
            )?);
        }
        if !descriptor.active_is_empty() {
            let (segment_id, start, predecessor, envelope) = descriptor.active_key_context();
            let key = unwrap_active_key(
                master_key,
                descriptor.vault_id(),
                segment_id,
                start,
                predecessor,
                envelope,
            )?;
            let bytes = read_canonical_segment(&active_segment_path(vault_path, segment_id))?;
            let segment = parse_segment(&bytes)?;
            if !descriptor.matches_active_segment(&segment) {
                return Err(VaultError::CorruptedAudit);
            }
            events.extend(verify_and_decode_segment(&key, &bytes)?);
        }
        Ok(events)
    }

    pub(super) fn recover(
        &mut self,
        vault_path: &Path,
        master_key: &MasterKey,
    ) -> Result<(), VaultError> {
        if !ManifestStore::exists_for_vault(vault_path)? {
            return Ok(());
        }
        for _ in 0..MAX_RECOVERY_STEPS {
            let manifest = ManifestStore::open_for_vault(vault_path).load()?;
            if manifest.anchor_mode() != self.anchor_mode {
                return Err(if manifest.anchor_mode() == AnchorMode::Mandatory {
                    VaultError::AuditAnchorDegraded
                } else {
                    VaultError::CorruptedAudit
                });
            }
            let segment_bytes = if manifest.state() == RecoveryState::Prepared {
                Some(read_canonical_segment(&active_segment_path(
                    vault_path,
                    manifest.segment_id(),
                ))?)
            } else {
                None
            };
            let (evidence, desired) = collect_anchor_evidence(&mut *self.anchor_sink, &manifest);
            let coordinator = AuditRotationCoordinator::for_vault(vault_path)?;
            let action = coordinator.step(master_key, segment_bytes.as_deref(), evidence)?;
            match action {
                RecoveryAction::RetryMandatoryAnchorCas
                | RecoveryAction::RetryOptionalAnchorCas => {
                    if evidence == AnchorEvidence::ExpectedGeneration {
                        let result = self
                            .anchor_sink
                            .compare_and_set(manifest.expected_anchor_generation(), &desired);
                        let result = match result {
                            Ok(value) => value,
                            Err(_) if manifest.anchor_mode() == AnchorMode::Mandatory => {
                                return Err(VaultError::AuditAnchorDegraded);
                            }
                            Err(error) => return Err(error),
                        };
                        match result {
                            AnchorCasResult::Applied | AnchorCasResult::AlreadyApplied => {}
                            AnchorCasResult::Conflict => return Err(VaultError::CorruptedAudit),
                        }
                    } else if manifest.anchor_mode() == AnchorMode::Mandatory {
                        return Err(VaultError::AuditAnchorDegraded);
                    } else {
                        return Ok(());
                    }
                }
                RecoveryAction::StopForManualRecovery => {
                    return Err(if manifest.anchor_mode() == AnchorMode::Mandatory {
                        VaultError::AuditAnchorDegraded
                    } else {
                        VaultError::CorruptedAudit
                    });
                }
                RecoveryAction::RemoveConfirmedManifest => {
                    Self::remove_rotated_active(vault_path, &manifest)?;
                    Self::create_empty_active_after_rotation(vault_path, master_key)?;
                    return Ok(());
                }
                _ => {}
            }
            if !ManifestStore::exists_for_vault(vault_path)? {
                Self::create_empty_active_after_rotation(vault_path, master_key)?;
                return Ok(());
            }
            fault_injection_pause();
        }
        Err(VaultError::CorruptedAudit)
    }

    fn rotate(
        &mut self,
        vault_path: &Path,
        master_key: &MasterKey,
        segment: &[u8],
    ) -> Result<(), VaultError> {
        let expected_anchor_generation = self
            .anchor_sink
            .load()?
            .as_deref()
            .map(parse_anchor_generation)
            .transpose()?
            .unwrap_or(0);
        prepare_rotation_for_vault(
            vault_path,
            master_key,
            segment,
            generate_array().map_err(|_| VaultError::RandomSourceUnavailable)?,
            self.anchor_mode,
            expected_anchor_generation,
        )?;
        fault_injection_hold_at("prepared-manifest");
        self.recover(vault_path, master_key)
    }

    fn create_empty_active_after_rotation(
        vault_path: &Path,
        _master_key: &MasterKey,
    ) -> Result<(), VaultError> {
        let descriptor = DescriptorStore::for_vault(vault_path).load()?;
        if !descriptor.active_is_empty() {
            return Ok(());
        }
        let path = active_segment_path(vault_path, descriptor.active_segment_id());
        if path.exists() {
            return Err(VaultError::ConcurrentModification);
        }
        Ok(())
    }

    fn remove_rotated_active(
        vault_path: &Path,
        manifest: &super::audit_recovery::AuditRotationManifest,
    ) -> Result<(), VaultError> {
        let path = active_segment_path(vault_path, manifest.segment_id());
        if !path.exists() {
            return Ok(());
        }
        let bytes = read_canonical_segment(&path)?;
        if super::audit_segment_store::segment_digest(&bytes) != manifest.segment_digest() {
            return Err(VaultError::CorruptedAudit);
        }
        secure_fs::ensure_safe_path(&path, false).map_err(map_secure_io)?;
        std::fs::remove_file(path)?;
        Ok(())
    }

    fn attach_local_sink_if_needed(&mut self, vault_path: &Path) {
        if self.anchor_mode == AnchorMode::LocalMirror {
            self.anchor_sink = Box::new(LocalMirrorAnchorSink::for_vault(vault_path));
        }
    }
}

struct UnconfiguredSink;

impl AnchorSink for UnconfiguredSink {
    fn load(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        Err(VaultError::NotFound)
    }

    fn compare_and_set(
        &mut self,
        _expected_generation: u64,
        _canonical_anchor: &[u8],
    ) -> Result<AnchorCasResult, VaultError> {
        Err(VaultError::NotFound)
    }
}

fn fault_injection_pause() {
    #[cfg(feature = "fault-injection")]
    {
        if let Ok(raw) = std::env::var("ENVVAULT_FAULT_PAUSE_MS")
            && let Ok(ms) = raw.parse::<u64>()
            && (1..=5_000).contains(&ms)
        {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
}

fn fault_injection_hold_at(name: &str) {
    #[cfg(feature = "fault-injection")]
    {
        if std::env::var("FAULT_HOLD_AT_CHECKPOINT").ok().as_deref() == Some(name) {
            std::thread::sleep(std::time::Duration::from_mins(10));
            return;
        }
    }
    let _ = name;
    fault_injection_pause();
}

fn parse_anchor_generation(bytes: &[u8]) -> Result<u64, VaultError> {
    let anchor = super::audit_v2::parse_anchor(bytes)?;
    if super::audit_v2::serialize_anchor(&anchor)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(anchor.anchor_generation())
}

fn sleep_before_retry(attempt: u32) -> Duration {
    let shift = u32::min(attempt, 4);
    let base = 100_u64.saturating_mul(1_u64 << shift);
    let jitter = crate::crypto::generate_array::<1>()
        .map_or(0, |bytes| u64::from(bytes[0]) % (base / 2 + 1));
    let duration = Duration::from_millis(base.saturating_add(jitter).min(1_600));
    std::thread::sleep(duration);
    duration
}

fn current_unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn map_secure_io(error: std::io::Error) -> VaultError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        VaultError::UnsafePath
    } else {
        error.into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrationMarker {
    format: String,
    version: u32,
    vault_id: String,
    event_count: u64,
    source_digest: String,
}

impl MigrationMarker {
    fn new(vault_id: [u8; 16], events: &[AuditEvent]) -> Result<Self, VaultError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let mut source = Vec::new();
        for event in events {
            let bytes = event.encode().map_err(|_| VaultError::CorruptedAudit)?;
            let length =
                u32::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?;
            source.extend_from_slice(&length.to_be_bytes());
            source.extend_from_slice(&bytes);
        }
        Ok(Self {
            format: MIGRATION_FORMAT.to_owned(),
            version: MIGRATION_VERSION,
            vault_id: STANDARD.encode(vault_id),
            event_count: u64::try_from(events.len())
                .map_err(|_| VaultError::ResourceLimitExceeded)?,
            source_digest: STANDARD.encode(sha256(&source)),
        })
    }

    fn validate(&self) -> Result<(), VaultError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        if self.format != MIGRATION_FORMAT
            || self.version != MIGRATION_VERSION
            || self.event_count > 100_000
            || STANDARD
                .decode(&self.vault_id)
                .map_or(true, |value| value.len() != 16)
            || STANDARD
                .decode(&self.source_digest)
                .map_or(true, |value| value.len() != 32)
        {
            return Err(VaultError::InvalidFormat);
        }
        Ok(())
    }
}

fn migration_marker_path(vault_path: &Path) -> std::path::PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".audit-migration-v2.json");
    value.into()
}

fn write_migration_marker(path: &Path, marker: &MigrationMarker) -> Result<(), VaultError> {
    marker.validate()?;
    let bytes = serde_json::to_vec(marker).map_err(|_| VaultError::InvalidFormat)?;
    let mut file = secure_fs::create_new(path).map_err(map_secure_io)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_migration_marker(path: &Path) -> Result<MigrationMarker, VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    if file.metadata()?.len() > MAX_MIGRATION_MARKER_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let mut bytes = Vec::new();
    file.take(MAX_MIGRATION_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let marker: MigrationMarker =
        serde_json::from_slice(&bytes).map_err(|_| VaultError::InvalidFormat)?;
    marker.validate()?;
    if serde_json::to_vec(&marker).map_err(|_| VaultError::InvalidFormat)? != bytes {
        return Err(VaultError::InvalidFormat);
    }
    Ok(marker)
}

fn remove_migration_marker(path: &Path) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, false).map_err(map_secure_io)?;
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::AuditRuntimeV2;
    use crate::{
        audit::AuditEvent,
        crypto::MasterPassword,
        identity::{AuthenticationMethod, Caller, CallerId, CallerKind},
        policy::{Operation, PolicyDecision},
        secret::SecretId,
        vault::{
            FileVault, VaultError,
            audit_anchor::{AnchorCasResult, AnchorSink},
        },
    };

    fn event(index: u8) -> AuditEvent {
        AuditEvent::now(
            Caller::new(CallerId::from_bytes([0x11; 16]), CallerKind::Application),
            AuthenticationMethod::ApplicationCredential,
            SecretId::from_bytes([index; 16]),
            Operation::Use,
            PolicyDecision::Allow,
        )
    }

    #[test]
    fn automatic_rotation_remains_readable_after_runtime_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let password = MasterPassword::new(b"audit-runtime-test".to_vec());
        let vault = FileVault::create(&path, &password, b"identity", b"policy")?;
        AuditRuntimeV2::initialize_new(&path, vault.vault_id(), vault.master_key())?;
        let mut runtime = AuditRuntimeV2::local_mirror_with_rotation_events(2);
        let first = event(1);
        let second = event(2);
        let third = event(3);
        runtime.append(&path, vault.master_key(), first)?;
        runtime.append(&path, vault.master_key(), second)?;
        runtime.append(&path, vault.master_key(), third)?;
        let mut reopened = AuditRuntimeV2::local_mirror_with_rotation_events(2);
        let events = reopened.read_all(&path, vault.master_key())?;
        assert_eq!(events, vec![first, second, third]);
        Ok(())
    }

    struct UnavailableAnchor;

    impl AnchorSink for UnavailableAnchor {
        fn load(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
            Ok(None)
        }

        fn compare_and_set(
            &mut self,
            _expected_generation: u64,
            _canonical_anchor: &[u8],
        ) -> Result<AnchorCasResult, VaultError> {
            Err(VaultError::NotFound)
        }
    }

    #[test]
    fn mandatory_http_cas_confirms_rotation_and_persists_last_confirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let password = MasterPassword::new(b"http-anchor-runtime".to_vec());
        let vault = FileVault::create(&path, &password, b"identity", b"policy")?;
        AuditRuntimeV2::initialize_new(&path, vault.vault_id(), vault.master_key())?;
        let data_dir = directory.path().join("anchor-data");
        let bound = crate::vault::AnchorHttpServer::bind(&data_dir, "127.0.0.1:0", None)?;
        let addr = bound.server.local_addr()?;
        let token_path = bound.token_path.clone();
        let mut server = bound.server;
        let _worker = std::thread::spawn(move || {
            let _ = server.serve_forever();
        });
        crate::vault::configure_anchor_client(
            &path,
            &format!("http://{addr}"),
            &token_path,
            None,
            true,
        )?;
        let mut runtime =
            AuditRuntimeV2::for_vault(&path, vault.vault_id())?.with_rotation_events(1);
        runtime.append(&path, vault.master_key(), event(1))?;
        let status = crate::vault::load_anchor_status(&path, Some(vault.vault_id()))?;
        assert_eq!(status.last_confirmed_generation, Some(1));
        assert!(status.last_confirmed_digest.is_some());
        let mut reopened =
            AuditRuntimeV2::for_vault(&path, vault.vault_id())?.with_rotation_events(1);
        assert_eq!(reopened.read_all(&path, vault.master_key())?.len(), 1);
        Ok(())
    }

    #[test]
    fn mandatory_anchor_failure_persists_degraded_state_and_blocks_next_append()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let password = MasterPassword::new(b"mandatory-anchor-test".to_vec());
        let vault = FileVault::create(&path, &password, b"identity", b"policy")?;
        AuditRuntimeV2::initialize_new(&path, vault.vault_id(), vault.master_key())?;
        let mut runtime = AuditRuntimeV2 {
            anchor_mode: super::AnchorMode::Mandatory,
            rotation_events: 1,
            anchor_sink: Box::new(UnavailableAnchor),
        };
        assert_eq!(
            runtime.append(&path, vault.master_key(), event(1)),
            Err(VaultError::AuditAnchorDegraded)
        );
        assert_eq!(
            runtime.append(&path, vault.master_key(), event(2)),
            Err(VaultError::AuditAnchorDegraded)
        );
        Ok(())
    }
}
