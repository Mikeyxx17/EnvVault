use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use super::error::CliError;

pub(super) fn write_new(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let mut pending = PendingExampleFile::create(path)?;
    pending
        .file
        .write_all(contents)
        .and_then(|()| pending.file.sync_all())
        .map_err(|_| CliError::ExampleFileUnavailable)?;
    pending.committed = true;
    Ok(())
}

struct PendingExampleFile {
    path: PathBuf,
    file: File,
    committed: bool,
}

impl PendingExampleFile {
    fn create(path: &Path) -> Result<Self, CliError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    CliError::ExampleFileExists
                } else {
                    CliError::ExampleFileUnavailable
                }
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            committed: false,
        })
    }
}

impl Drop for PendingExampleFile {
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

    use super::write_new;

    #[test]
    fn refuses_to_overwrite_an_existing_example() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join(".env.example");
        fs::write(&path, b"EXISTING=\n")?;

        assert!(write_new(&path, b"REPLACEMENT=\n").is_err());
        assert_eq!(fs::read(&path)?, b"EXISTING=\n");
        Ok(())
    }
}
