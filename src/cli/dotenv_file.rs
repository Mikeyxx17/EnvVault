use std::{
    fs::File,
    io::{Read as _, Take},
    path::Path,
};

use zeroize::Zeroizing;

use crate::dotenv::MAX_DOTENV_BYTES;

use super::error::CliError;

pub(super) fn read_source(path: &Path) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let file = File::open(path).map_err(|_| CliError::DotenvSourceUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| CliError::DotenvSourceUnavailable)?;
    if !metadata.is_file() || metadata.len() > MAX_DOTENV_BYTES as u64 {
        return Err(CliError::DotenvSourceUnavailable);
    }
    let limit = u64::try_from(MAX_DOTENV_BYTES)
        .map_err(|_| CliError::DotenvSourceUnavailable)?
        .saturating_add(1);
    let mut reader: Take<File> = file.take(limit);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).map_err(|_| CliError::DotenvSourceUnavailable)?,
    ));
    reader
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::DotenvSourceUnavailable)?;
    if bytes.len() > MAX_DOTENV_BYTES {
        return Err(CliError::DotenvSourceUnavailable);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::read_source;
    use crate::dotenv::MAX_DOTENV_BYTES;

    #[test]
    fn bounded_reader_rejects_oversized_and_non_file_sources()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let oversized = directory.path().join("oversized.env");
        fs::write(&oversized, vec![b'A'; MAX_DOTENV_BYTES + 1])?;

        assert!(read_source(&oversized).is_err());
        assert!(read_source(directory.path()).is_err());
        Ok(())
    }
}
