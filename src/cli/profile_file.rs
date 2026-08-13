use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::Path,
};

use crate::profile::{MAX_PROFILE_BYTES, Profile};

use super::error::CliError;

pub(super) fn read(path: &Path) -> Result<Profile, CliError> {
    let file = File::open(path).map_err(|_| CliError::ProfileFileUnavailable)?;
    let limit = u64::try_from(MAX_PROFILE_BYTES).map_err(|_| CliError::ProfileFileInvalid)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::ProfileFileUnavailable)?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(CliError::ProfileFileInvalid);
    }
    Profile::decode(&bytes).map_err(Into::into)
}

pub(super) fn write_new(path: &Path, profile: &Profile) -> Result<(), CliError> {
    let encoded = profile.encode()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CliError::ProfileFileExists
            } else {
                CliError::ProfileFileUnavailable
            }
        })?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|_| CliError::ProfileFileUnavailable)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{read, write_new};
    use crate::{
        profile::{Profile, ProfileBinding},
        secret::SecretId,
    };

    #[test]
    fn writes_new_and_reads_strict_profile() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("backend.profile.json");
        let profile = Profile::new(vec![ProfileBinding::new(
            "DATABASE_URL",
            SecretId::from_bytes([0x11; 16]),
        )?])?;

        write_new(&path, &profile)?;
        assert_eq!(read(&path)?, profile);
        assert!(write_new(&path, &profile).is_err());
        Ok(())
    }
}
