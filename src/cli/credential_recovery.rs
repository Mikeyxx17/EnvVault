use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    broker::service::{PreparedCallerRegistration, PreparedCallerRotation},
    identity::{Caller, CallerCredential, CallerId, CallerKind, IssuedCallerCredential},
    secure_fs,
};

use super::{
    application::CliApplication,
    credential_file::{
        PendingCredentialFile, ensure_available, read as read_credential, remove_if_empty,
    },
    error::CliError,
};

const FORMAT_NAME: &str = "envvault-credential-delivery-recovery";
const FORMAT_VERSION: u32 = 1;
const MAX_RECOVERY_BYTES: u64 = 32 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryDocument {
    format: String,
    version: u32,
    caller_id: String,
    caller_kind: String,
    credential_file: PathBuf,
    credential: String,
}

impl Drop for RecoveryDocument {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}

pub(super) struct CredentialDelivery {
    recovery_path: PathBuf,
}

impl CredentialDelivery {
    pub(super) fn begin(
        vault: &Path,
        destination: &Path,
        prepared: &PreparedCallerRegistration,
    ) -> Result<Self, CliError> {
        Self::begin_issued(vault, destination, prepared.issued())
    }

    pub(super) fn begin_rotation(
        vault: &Path,
        destination: &Path,
        prepared: &PreparedCallerRotation,
    ) -> Result<Self, CliError> {
        Self::begin_issued(vault, destination, prepared.issued())
    }

    fn begin_issued(
        vault: &Path,
        destination: &Path,
        issued: &IssuedCallerCredential,
    ) -> Result<Self, CliError> {
        let destination = resolve_destination(destination)?;
        ensure_available(&destination)?;
        let recovery_path = recovery_path_for(vault);
        ensure_available(&recovery_path).map_err(|_| CliError::CredentialRecoveryRequired)?;
        let credential = Zeroizing::new(STANDARD.encode(issued.credential().expose_secret()));
        let document = RecoveryDocument {
            format: FORMAT_NAME.to_owned(),
            version: FORMAT_VERSION,
            caller_id: issued.caller().id().to_string(),
            caller_kind: issued.caller().kind().as_str().to_owned(),
            credential_file: destination,
            credential: credential.to_string(),
        };
        let mut encoded = Zeroizing::new(
            serde_json::to_vec_pretty(&document)
                .map_err(|_| CliError::CredentialRecoveryRequired)?,
        );
        encoded.push(b'\n');
        let mut file = secure_fs::create_new(&recovery_path)
            .map_err(|_| CliError::CredentialRecoveryRequired)?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_| CliError::CredentialRecoveryRequired)?;
        Ok(Self { recovery_path })
    }

    pub(super) fn destination(&self) -> Result<PathBuf, CliError> {
        Ok(read_document(&self.recovery_path)?.credential_file.clone())
    }

    pub(super) fn finish(self) -> Result<(), CliError> {
        remove_recovery_file(&self.recovery_path)
    }
}

pub(super) fn recover(vault: &Path, application: &mut CliApplication) -> Result<(), CliError> {
    let recovery_path = recovery_path_for(vault);
    match fs::symlink_metadata(&recovery_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CliError::CredentialRecoveryRequired),
        Ok(_) => {}
    }
    let document = read_document(&recovery_path)?;
    let issued = issued_from_document(&document)?;
    if application.caller_credential_is_current(&issued)? {
        complete_registered_delivery(&document.credential_file, &issued)?;
    } else {
        remove_if_empty(&document.credential_file)?;
    }
    remove_recovery_file(&recovery_path)
}

fn complete_registered_delivery(
    destination: &Path,
    issued: &IssuedCallerCredential,
) -> Result<(), CliError> {
    match fs::symlink_metadata(destination) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PendingCredentialFile::create(destination)?.write(issued)
        }
        Err(_) => Err(CliError::CredentialRecoveryRequired),
        Ok(metadata) if metadata.len() == 0 => {
            PendingCredentialFile::resume_empty(destination)?.write(issued)
        }
        Ok(_) => {
            let existing =
                read_credential(destination).map_err(|_| CliError::CredentialRecoveryRequired)?;
            let same_identity = existing.caller_id == issued.caller().id()
                && existing.caller_kind == issued.caller().kind();
            let same_credential = bool::from(
                existing
                    .credential
                    .expose_secret()
                    .ct_eq(issued.credential().expose_secret()),
            );
            if same_identity && same_credential {
                Ok(())
            } else {
                Err(CliError::CredentialRecoveryRequired)
            }
        }
    }
}

fn read_document(path: &Path) -> Result<RecoveryDocument, CliError> {
    let file = secure_fs::open_existing(path).map_err(|_| CliError::CredentialRecoveryRequired)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_RECOVERY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::CredentialRecoveryRequired)?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > MAX_RECOVERY_BYTES) {
        return Err(CliError::CredentialRecoveryRequired);
    }
    let document: RecoveryDocument =
        serde_json::from_slice(&bytes).map_err(|_| CliError::CredentialRecoveryRequired)?;
    if document.format != FORMAT_NAME || document.version != FORMAT_VERSION {
        return Err(CliError::CredentialRecoveryRequired);
    }
    Ok(document)
}

fn issued_from_document(document: &RecoveryDocument) -> Result<IssuedCallerCredential, CliError> {
    let caller_id: CallerId = document
        .caller_id
        .parse()
        .map_err(|_| CliError::CredentialRecoveryRequired)?;
    let caller_kind: CallerKind = document
        .caller_kind
        .parse()
        .map_err(|_| CliError::CredentialRecoveryRequired)?;
    if caller_kind == CallerKind::Human {
        return Err(CliError::CredentialRecoveryRequired);
    }
    let mut bytes = Zeroizing::new([0_u8; CallerCredential::LENGTH]);
    let decoded = STANDARD
        .decode_slice(&document.credential, bytes.as_mut_slice())
        .map_err(|_| CliError::CredentialRecoveryRequired)?;
    if decoded != CallerCredential::LENGTH {
        return Err(CliError::CredentialRecoveryRequired);
    }
    Ok(IssuedCallerCredential::new(
        Caller::new(caller_id, caller_kind),
        CallerCredential::from_bytes(*bytes),
    ))
}

fn resolve_destination(path: &Path) -> Result<PathBuf, CliError> {
    let file_name = path
        .file_name()
        .ok_or(CliError::CredentialFileUnavailable)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| CliError::CredentialFileUnavailable)?;
    let resolved = parent.join(file_name);
    secure_fs::ensure_safe_path(&resolved, true)
        .map_err(|_| CliError::CredentialFileUnavailable)?;
    Ok(resolved)
}

fn recovery_path_for(vault: &Path) -> PathBuf {
    let mut value = OsString::from(vault.as_os_str());
    value.push(".credential-delivery.json");
    PathBuf::from(value)
}

fn remove_recovery_file(path: &Path) -> Result<(), CliError> {
    secure_fs::ensure_safe_path(path, false).map_err(|_| CliError::CredentialRecoveryRequired)?;
    fs::remove_file(path).map_err(|_| CliError::CredentialRecoveryRequired)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{CredentialDelivery, recovery_path_for};
    use crate::{
        cli::{application::CliApplication, credential_file::read},
        crypto::MasterPassword,
        identity::CallerKind,
        secure_fs,
    };

    fn password() -> MasterPassword {
        MasterPassword::new(b"credential recovery test password".to_vec())
    }

    #[test]
    fn recovery_removes_an_uncommitted_empty_destination() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let destination = directory.path().join("application.credential.json");
        CliApplication::init(&vault, &password())?;
        let mut application = CliApplication::open_owner(&vault, &password())?;
        let prepared = application.prepare_caller_registration(
            CallerKind::Application,
            "crash-before-commit".to_owned(),
        )?;
        let delivery = CredentialDelivery::begin(&vault, &destination, &prepared)?;
        drop(secure_fs::create_new(&delivery.destination()?)?);
        drop(delivery);
        drop(prepared);
        drop(application);

        let _reopened = CliApplication::open_owner(&vault, &password())?;
        assert!(!destination.exists());
        assert!(!recovery_path_for(&vault).exists());
        Ok(())
    }

    #[test]
    fn recovery_finishes_delivery_after_registry_commit() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let destination = directory.path().join("agent.credential.json");
        CliApplication::init(&vault, &password())?;
        let mut application = CliApplication::open_owner(&vault, &password())?;
        let prepared = application
            .prepare_caller_registration(CallerKind::AiAgent, "crash-after-commit".to_owned())?;
        let caller = prepared.issued().caller();
        let delivery = CredentialDelivery::begin(&vault, &destination, &prepared)?;
        drop(secure_fs::create_new(&delivery.destination()?)?);
        let issued = application.commit_caller_registration(prepared)?;
        assert_eq!(issued.caller(), caller);
        drop(delivery);
        drop(issued);
        drop(application);

        let _reopened = CliApplication::open_owner(&vault, &password())?;
        let evidence = read(&destination)?;
        assert_eq!(evidence.caller_id, caller.id());
        assert_eq!(evidence.caller_kind, caller.kind());
        assert!(fs::metadata(&destination)?.len() > 0);
        assert!(!recovery_path_for(&vault).exists());
        Ok(())
    }

    #[test]
    fn rotation_recovery_removes_uncommitted_destination() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let vault = directory.path().join("rotation-before.vault.json");
        let destination = directory.path().join("rotated.credential.json");
        CliApplication::init(&vault, &password())?;
        let mut application = CliApplication::open_owner(&vault, &password())?;
        let registered = application
            .prepare_caller_registration(CallerKind::Application, "rotation-before".to_owned())?;
        let caller = registered.issued().caller();
        application.commit_caller_registration(registered)?;
        let prepared = application.prepare_caller_rotation(caller.id())?;
        let delivery = CredentialDelivery::begin_rotation(&vault, &destination, &prepared)?;
        drop(secure_fs::create_new(&delivery.destination()?)?);
        drop(delivery);
        drop(prepared);
        drop(application);

        let _reopened = CliApplication::open_owner(&vault, &password())?;
        assert!(!destination.exists());
        assert!(!recovery_path_for(&vault).exists());
        Ok(())
    }

    #[test]
    fn rotation_recovery_delivers_only_the_committed_new_credential()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("rotation-after.vault.json");
        let destination = directory.path().join("rotated.credential.json");
        CliApplication::init(&vault, &password())?;
        let mut application = CliApplication::open_owner(&vault, &password())?;
        let registered = application
            .prepare_caller_registration(CallerKind::AiAgent, "rotation-after".to_owned())?;
        let caller = registered.issued().caller();
        application.commit_caller_registration(registered)?;
        let prepared = application.prepare_caller_rotation(caller.id())?;
        let delivery = CredentialDelivery::begin_rotation(&vault, &destination, &prepared)?;
        drop(secure_fs::create_new(&delivery.destination()?)?);
        let issued = application.commit_caller_rotation(prepared)?;
        assert_eq!(issued.caller(), caller);
        drop(delivery);
        drop(issued);
        drop(application);

        let mut reopened = CliApplication::open_owner(&vault, &password())?;
        let evidence = read(&destination)?;
        assert_eq!(evidence.caller_id, caller.id());
        assert_eq!(evidence.caller_kind, caller.kind());
        let recovered = crate::identity::IssuedCallerCredential::new(caller, evidence.credential);
        assert!(reopened.caller_credential_is_current(&recovered)?);
        assert!(!recovery_path_for(&vault).exists());
        Ok(())
    }
}
