//! Program and project removal. Never prints Secret Values.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use super::{application::CliApplication, error::CliError, password::SensitiveInput};
use crate::config::Project;

// Keystore cleanup is best-effort and value-free.

const UNINSTALL_PHRASE: &str = "uninstall";
const PURGE_PHRASE: &str = "purge";

pub(super) fn execute(
    purge_project: bool,
    project: Option<&Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let binaries = installed_binaries();
    let purge_targets = if purge_project {
        Some(project_purge_targets(project)?)
    } else {
        None
    };

    writeln!(output, "This will remove:")?;
    if binaries.is_empty() {
        writeln!(output, "- no installed envvault binary in ~/.local/bin")?;
    } else {
        for path in &binaries {
            writeln!(output, "- program: {}", path.display())?;
        }
    }
    if let Some(targets) = &purge_targets {
        for path in targets {
            writeln!(output, "- project data: {}", path.display())?;
        }
    } else {
        writeln!(output, "- project Vault files: kept")?;
    }
    writeln!(output, "Source checkouts under EnvVault/ are not deleted.")?;

    sensitive_input.confirm_phrase(UNINSTALL_PHRASE)?;
    if purge_project {
        sensitive_input.confirm_phrase(PURGE_PHRASE)?;
        if let Some(project) = project {
            try_disable_keystore(project, sensitive_input, output);
        }
        for path in purge_targets.unwrap_or_default() {
            remove_path(&path)?;
            writeln!(output, "removed: {}", path.display())?;
        }
    }

    for path in binaries {
        remove_path(&path)?;
        writeln!(output, "removed: {}", path.display())?;
    }
    writeln!(output, "Uninstall finished")?;
    Ok(())
}

fn installed_binaries() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = env::var_os("HOME") {
        let candidate = PathBuf::from(home).join(".local/bin/envvault");
        if candidate.is_file() {
            paths.push(candidate);
        }
    }
    paths
}

fn project_purge_targets(project: Option<&Project>) -> Result<Vec<PathBuf>, CliError> {
    let project = project.ok_or(CliError::VaultPathRequired)?;
    let vault_dir = project.root().join(".envvault");
    if !vault_dir.is_dir() {
        return Err(CliError::UninstallUnavailable);
    }
    let mut targets = vec![vault_dir];
    let project_file = project.file_path();
    if project_file.is_file() {
        targets.push(project_file);
    }
    Ok(targets)
}

fn remove_path(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CliError::UninstallUnavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(CliError::UninstallUnavailable);
    }
    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(|_| CliError::UninstallUnavailable)?;
    } else {
        fs::remove_file(path).map_err(|_| CliError::UninstallUnavailable)?;
    }
    Ok(())
}

fn try_disable_keystore(
    project: &Project,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) {
    let password = match sensitive_input.read_existing() {
        Ok(password) => password,
        Err(_) => {
            let _ignored = writeln!(
                output,
                "keystore disable skipped: master password was not available"
            );
            return;
        }
    };
    match CliApplication::open_owner(project.vault(), &password)
        .and_then(|mut application| application.disable_machine_unlock())
    {
        Ok(_) => {
            let _ignored = writeln!(output, "keystore disabled");
        }
        Err(_) => {
            let _ignored = writeln!(
                output,
                "keystore disable skipped: machine unlock was not enabled or failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{project_purge_targets, remove_path};
    use crate::config::{self, default_layout, write_new};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn purge_targets_are_only_the_project_envvault_dir_and_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let project = default_layout(root.path());
        fs::create_dir_all(project.root().join(".envvault"))?;
        write_new(&project)?;
        let targets = project_purge_targets(Some(&project))?;
        assert_eq!(targets[0], project.root().join(".envvault"));
        assert_eq!(targets[1], project.file_path());
        Ok(())
    }

    #[test]
    fn purge_without_a_project_fails_closed() {
        assert!(project_purge_targets(None).is_err());
    }

    #[test]
    fn remove_path_deletes_a_regular_file_but_not_a_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let file = root.path().join("envvault");
        fs::write(&file, b"binary")?;
        remove_path(&file)?;
        assert!(!file.exists());

        let target = root.path().join("real");
        let link = root.path().join("link");
        fs::write(&target, b"x")?;
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(remove_path(&link).is_err());
        assert!(link.exists());
        Ok(())
    }

    #[test]
    fn discover_still_required_for_purge() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        assert!(config::discover(root.path())?.is_none());
        Ok(())
    }
}
