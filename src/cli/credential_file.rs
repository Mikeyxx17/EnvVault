use std::{
    fs::{self, File},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::identity::{CallerCredential, CallerId, CallerKind, IssuedCallerCredential};
use crate::secure_fs;

use super::error::CliError;

const FORMAT_NAME: &str = "envvault-caller-credential";
const FORMAT_VERSION: u32 = 1;
const MAX_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;

#[derive(Serialize)]
struct CredentialDocument<'a> {
    format: &'static str,
    version: u32,
    caller_id: String,
    caller_kind: &'static str,
    credential: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadCredentialDocument<'a> {
    format: &'a str,
    version: u32,
    caller_id: &'a str,
    caller_kind: &'a str,
    credential: &'a str,
}

pub(super) struct CallerEvidence {
    pub(super) caller_id: CallerId,
    pub(super) caller_kind: CallerKind,
    pub(super) credential: CallerCredential,
}

pub(super) fn read(path: &Path) -> Result<CallerEvidence, CliError> {
    let file = secure_fs::open_existing(path).map_err(|_| CliError::CredentialFileUnavailable)?;
    let mut encoded = Zeroizing::new(Vec::new());
    file.take(MAX_CREDENTIAL_FILE_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| CliError::CredentialFileUnavailable)?;
    if u64::try_from(encoded.len()).map_or(true, |length| length > MAX_CREDENTIAL_FILE_BYTES) {
        return Err(CliError::CredentialFileInvalid);
    }
    let document: ReadCredentialDocument<'_> =
        serde_json::from_slice(&encoded).map_err(|_| CliError::CredentialFileInvalid)?;
    if document.format != FORMAT_NAME || document.version != FORMAT_VERSION {
        return Err(CliError::CredentialFileInvalid);
    }
    let caller_id = document
        .caller_id
        .parse()
        .map_err(|_| CliError::CredentialFileInvalid)?;
    let caller_kind: CallerKind = document
        .caller_kind
        .parse()
        .map_err(|_| CliError::CredentialFileInvalid)?;
    if caller_kind == CallerKind::Human {
        return Err(CliError::CredentialFileInvalid);
    }
    let mut credential_bytes = Zeroizing::new([0_u8; CallerCredential::LENGTH]);
    let decoded = STANDARD
        .decode_slice(document.credential, credential_bytes.as_mut_slice())
        .map_err(|_| CliError::CredentialFileInvalid)?;
    if decoded != CallerCredential::LENGTH {
        return Err(CliError::CredentialFileInvalid);
    }
    Ok(CallerEvidence {
        caller_id,
        caller_kind,
        credential: CallerCredential::from_bytes(*credential_bytes),
    })
}

pub(super) struct PendingCredentialFile {
    path: PathBuf,
    file: File,
    committed: bool,
}

impl PendingCredentialFile {
    pub(super) fn create(path: &Path) -> Result<Self, CliError> {
        let file = secure_fs::create_new(path).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::CredentialFileExists
            } else {
                CliError::CredentialFileUnavailable
            }
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            committed: false,
        })
    }

    pub(super) fn resume_empty(path: &Path) -> Result<Self, CliError> {
        let file = secure_fs::open_existing_read_write(path)
            .map_err(|_| CliError::CredentialFileUnavailable)?;
        if file
            .metadata()
            .map_err(|_| CliError::CredentialFileUnavailable)?
            .len()
            != 0
        {
            return Err(CliError::CredentialRecoveryRequired);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            committed: false,
        })
    }

    pub(super) fn write(mut self, issued: &IssuedCallerCredential) -> Result<(), CliError> {
        let credential = Zeroizing::new(STANDARD.encode(issued.credential().expose_secret()));
        let document = CredentialDocument {
            format: FORMAT_NAME,
            version: FORMAT_VERSION,
            caller_id: issued.caller().id().to_string(),
            caller_kind: issued.caller().kind().as_str(),
            credential: credential.as_str(),
        };
        let mut encoded = Zeroizing::new(
            serde_json::to_vec_pretty(&document)
                .map_err(|_| CliError::CredentialFileUnavailable)?,
        );
        encoded.push(b'\n');
        self.file
            .write_all(&encoded)
            .and_then(|()| self.file.sync_all())
            .map_err(|_| CliError::CredentialFileUnavailable)?;
        self.committed = true;
        Ok(())
    }
}

pub(super) fn ensure_available(path: &Path) -> Result<(), CliError> {
    secure_fs::ensure_safe_path(path, true).map_err(|_| CliError::CredentialFileUnavailable)?;
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CliError::CredentialFileExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliError::CredentialFileUnavailable),
    }
}

pub(super) fn remove_if_empty(path: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CliError::CredentialRecoveryRequired),
        Ok(_) => {}
    }
    let file = secure_fs::open_existing(path).map_err(|_| CliError::CredentialRecoveryRequired)?;
    if file
        .metadata()
        .map_err(|_| CliError::CredentialRecoveryRequired)?
        .len()
        != 0
    {
        return Err(CliError::CredentialRecoveryRequired);
    }
    drop(file);
    secure_fs::ensure_safe_path(path, false).map_err(|_| CliError::CredentialRecoveryRequired)?;
    fs::remove_file(path).map_err(|_| CliError::CredentialRecoveryRequired)
}

impl Drop for PendingCredentialFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{PendingCredentialFile, read};
    use crate::identity::{Caller, CallerCredential, CallerId, CallerKind, IssuedCallerCredential};

    fn issued() -> IssuedCallerCredential {
        IssuedCallerCredential::new(
            Caller::new(CallerId::from_bytes([0x11; 16]), CallerKind::Application),
            CallerCredential::from_bytes([0x22; 32]),
        )
    }

    #[test]
    fn writes_a_versioned_credential_and_refuses_overwrite()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("caller.json");

        PendingCredentialFile::create(&path)?.write(&issued())?;
        let first = fs::read(&path)?;
        assert!(
            first
                .windows(26)
                .any(|value| value == b"envvault-caller-credential")
        );
        assert!(PendingCredentialFile::create(&path).is_err());
        assert_eq!(fs::read(&path)?, first);
        let evidence = read(&path)?;
        assert_eq!(evidence.caller_id, issued().caller().id());
        assert_eq!(evidence.caller_kind, CallerKind::Application);
        assert_eq!(evidence.credential.expose_secret(), &[0x22; 32]);
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_wrong_length_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("invalid.json");
        fs::write(
            &path,
            br#"{"format":"envvault-caller-credential","version":1,"caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"application","credential":"AQ==","extra":true}"#,
        )?;

        assert!(read(&path).is_err());
        Ok(())
    }
}
