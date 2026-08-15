//! Value-free project configuration, discovered like `Cargo.toml`.
//!
//! The file never stores Secret Values, passwords, or caller credentials.

use std::{
    env, fmt, fs,
    io::{self, Read as _, Write as _},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::identity::CallerId;

const FORMAT_NAME: &str = "envvault-project";
const FORMAT_VERSION: u32 = 1;
const MAX_PROJECT_BYTES: usize = 16 * 1024;
const PROJECT_FILE_NAME: &str = "envvault.json";
const DEFAULT_VAULT: &str = ".envvault/vault";
const DEFAULT_PROFILE: &str = ".envvault/app.profile.json";
const DEFAULT_CREDENTIAL: &str = ".envvault/app.credential.json";

/// A discovered project: `envvault.json` plus resolved default paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Project {
    root: PathBuf,
    vault: PathBuf,
    profile: PathBuf,
    credential_file: PathBuf,
    caller_id: Option<CallerId>,
}

impl Project {
    /// Directory that contains `envvault.json`.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute Vault path.
    #[must_use]
    pub fn vault(&self) -> &Path {
        &self.vault
    }

    /// Absolute default Profile path.
    #[must_use]
    pub fn profile(&self) -> &Path {
        &self.profile
    }

    /// Absolute default credential-file path.
    #[must_use]
    pub fn credential_file(&self) -> &Path {
        &self.credential_file
    }

    /// Optional default Application / Agent caller.
    #[must_use]
    pub const fn caller_id(&self) -> Option<CallerId> {
        self.caller_id
    }

    /// Path of the project file.
    #[must_use]
    pub fn file_path(&self) -> PathBuf {
        self.root.join(PROJECT_FILE_NAME)
    }

    /// Record a registered caller as the project default. Value-free.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Unavailable`] when the file cannot be replaced.
    pub fn set_default_caller(
        &mut self,
        caller_id: CallerId,
        credential_file: &Path,
    ) -> Result<(), ProjectError> {
        self.caller_id = Some(caller_id);
        self.credential_file = credential_file.to_path_buf();
        self.write()
    }

    /// Record the default Profile path after `profile create`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::Unavailable`] when the file cannot be replaced.
    pub fn set_default_profile(&mut self, profile: &Path) -> Result<(), ProjectError> {
        self.profile = profile.to_path_buf();
        self.write()
    }

    fn write(&self) -> Result<(), ProjectError> {
        let document = ProjectDocument {
            format: FORMAT_NAME,
            version: FORMAT_VERSION,
            vault: relative_display(&self.root, &self.vault),
            profile: Some(relative_display(&self.root, &self.profile)),
            credential_file: Some(relative_display(&self.root, &self.credential_file)),
            caller_id: self.caller_id.map(|id| id.to_string()),
        };
        write_document(&self.file_path(), &document)
    }
}

/// Walks from `start` toward the filesystem root looking for `envvault.json`.
///
/// # Errors
///
/// Returns an error when a project file exists but is invalid.
pub fn discover(start: &Path) -> Result<Option<Project>, ProjectError> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(PROJECT_FILE_NAME);
        if candidate.is_file() {
            return Ok(Some(load(&candidate)?));
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

/// Discovers a project starting at the process working directory.
///
/// # Errors
///
/// Returns [`ProjectError::Unavailable`] when the working directory cannot be
/// read, or a parse error when `envvault.json` is present but invalid.
pub fn discover_from_cwd() -> Result<Option<Project>, ProjectError> {
    let cwd = env::current_dir().map_err(|_| ProjectError::Unavailable)?;
    discover(&cwd)
}

/// Default layout written by `envvault init` when `--vault` is omitted.
#[must_use]
pub fn default_layout(root: &Path) -> Project {
    Project {
        root: root.to_path_buf(),
        vault: root.join(DEFAULT_VAULT),
        profile: root.join(DEFAULT_PROFILE),
        credential_file: root.join(DEFAULT_CREDENTIAL),
        caller_id: None,
    }
}

/// Creates `.envvault` with owner-only access when possible.
///
/// # Errors
///
/// Returns [`ProjectError::Unavailable`] when the directory cannot be created.
pub fn ensure_vault_dir(dir: &Path) -> Result<(), ProjectError> {
    if dir.exists() {
        if dir.is_dir() {
            return Ok(());
        }
        return Err(ProjectError::Unavailable);
    }
    create_private_dir(dir).map_err(|_| ProjectError::Unavailable)
}

/// Writes `envvault.json` only when it does not already exist.
///
/// # Errors
///
/// Returns [`ProjectError::AlreadyExists`] or [`ProjectError::Unavailable`].
pub fn write_new(project: &Project) -> Result<(), ProjectError> {
    if project.file_path().exists() {
        return Err(ProjectError::AlreadyExists);
    }
    project.write()
}

/// Safe project-file failure category. Never includes Secret Values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectError {
    /// The working directory or project file could not be accessed.
    Unavailable,
    /// The document is malformed or contains a disallowed path.
    InvalidFormat,
    /// The document uses an unsupported version.
    UnsupportedVersion,
    /// The document exceeds the size limit.
    ResourceLimitExceeded,
    /// `envvault.json` already exists.
    AlreadyExists,
}

impl fmt::Display for ProjectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "project file could not be accessed",
            Self::InvalidFormat => "envvault.json is invalid",
            Self::UnsupportedVersion => "envvault.json version is unsupported",
            Self::ResourceLimitExceeded => "envvault.json exceeds resource limits",
            Self::AlreadyExists => "envvault.json already exists; refusing to overwrite it",
        })
    }
}

impl std::error::Error for ProjectError {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectDocument<'a> {
    format: &'a str,
    version: u32,
    vault: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_id: Option<String>,
}

fn load(path: &Path) -> Result<Project, ProjectError> {
    let root = path
        .parent()
        .ok_or(ProjectError::InvalidFormat)?
        .to_path_buf();
    let file = fs::File::open(path).map_err(|_| ProjectError::Unavailable)?;
    let limit =
        u64::try_from(MAX_PROJECT_BYTES).map_err(|_| ProjectError::ResourceLimitExceeded)?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ProjectError::Unavailable)?;
    if bytes.len() > MAX_PROJECT_BYTES {
        return Err(ProjectError::ResourceLimitExceeded);
    }
    let document: ProjectDocument<'_> =
        serde_json::from_slice(&bytes).map_err(|_| ProjectError::InvalidFormat)?;
    if document.format != FORMAT_NAME {
        return Err(ProjectError::InvalidFormat);
    }
    if document.version != FORMAT_VERSION {
        return Err(ProjectError::UnsupportedVersion);
    }
    let vault = resolve_member(&root, &document.vault)?;
    let profile = match document.profile.as_deref() {
        Some(value) => resolve_member(&root, value)?,
        None => root.join(DEFAULT_PROFILE),
    };
    let credential_file = match document.credential_file.as_deref() {
        Some(value) => resolve_member(&root, value)?,
        None => root.join(DEFAULT_CREDENTIAL),
    };
    let caller_id = document
        .caller_id
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| ProjectError::InvalidFormat)?;
    Ok(Project {
        root,
        vault,
        profile,
        credential_file,
        caller_id,
    })
}

fn resolve_member(root: &Path, raw: &str) -> Result<PathBuf, ProjectError> {
    let path = Path::new(raw);
    if path.is_absolute() || raw.is_empty() {
        return Err(ProjectError::InvalidFormat);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(ProjectError::InvalidFormat);
    }
    Ok(root.join(path))
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map_or_else(
            |_| path.display().to_string(),
            |value| value.display().to_string(),
        )
        .replace('\\', "/")
}

fn write_document(path: &Path, document: &ProjectDocument<'_>) -> Result<(), ProjectError> {
    let mut bytes = serde_json::to_vec_pretty(document).map_err(|_| ProjectError::InvalidFormat)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_PROJECT_BYTES {
        return Err(ProjectError::ResourceLimitExceeded);
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp).map_err(|_| ProjectError::Unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ProjectError::Unavailable)?;
    }
    fs::rename(&tmp, path).map_err(|_| ProjectError::Unavailable)
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::{
        FORMAT_NAME, FORMAT_VERSION, ProjectError, default_layout, discover, load, write_new,
    };
    use crate::identity::CallerId;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn writes_and_discovers_a_strict_project_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let nested = root.path().join("src").join("bin");
        fs::create_dir_all(&nested)?;
        let project = default_layout(root.path());
        write_new(&project)?;

        let found = discover(&nested)?.expect("project");
        assert_eq!(found.vault(), root.path().join(".envvault/vault"));
        assert_eq!(
            found.profile(),
            root.path().join(".envvault/app.profile.json")
        );
        assert!(found.caller_id().is_none());
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_parent_paths_and_absolute_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let path = root.path().join("envvault.json");
        fs::write(
            &path,
            r#"{"format":"envvault-project","version":1,"vault":".envvault/vault","extra":true}"#,
        )?;
        assert_eq!(load(&path).unwrap_err(), ProjectError::InvalidFormat);

        fs::write(
            &path,
            r#"{"format":"envvault-project","version":1,"vault":"../other.vault"}"#,
        )?;
        assert_eq!(load(&path).unwrap_err(), ProjectError::InvalidFormat);

        fs::write(
            &path,
            r#"{"format":"envvault-project","version":1,"vault":"/tmp/x.vault"}"#,
        )?;
        assert_eq!(load(&path).unwrap_err(), ProjectError::InvalidFormat);
        Ok(())
    }

    #[test]
    fn set_default_caller_rewrites_only_value_free_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempdir()?;
        let mut project = default_layout(root.path());
        write_new(&project)?;
        let caller = CallerId::from_bytes([0xab; 16]);
        let cred = root.path().join(".envvault/rust-demo.credential.json");
        project.set_default_caller(caller, &cred)?;
        let reloaded = load(&project.file_path())?;
        assert_eq!(reloaded.caller_id(), Some(caller));
        let text = fs::read_to_string(project.file_path())?;
        assert!(text.contains("abababab-abab-abab-abab-abababababab"));
        assert!(!text.contains("credential\":"));
        assert_eq!(reloaded.vault(), project.vault());
        Ok(())
    }

    #[test]
    fn default_document_round_trips_canonical_version() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let project = default_layout(root.path());
        write_new(&project)?;
        let text = fs::read_to_string(project.file_path())?;
        assert!(text.contains(FORMAT_NAME));
        assert!(text.contains(&FORMAT_VERSION.to_string()));
        assert!(write_new(&project).is_err());
        Ok(())
    }
}
