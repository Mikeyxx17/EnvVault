//! Fail-closed filesystem operations for files carrying secret material.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};

/// Opens a new sensitive file without following a link at the destination.
pub(crate) fn create_new(path: &Path) -> io::Result<File> {
    ensure_safe_path(path, true)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    configure_no_follow_and_private_create(&mut options);
    configure_dacl_access(&mut options);
    let mut file = options.open(path)?;
    reject_reparse_handle(&file)?;
    protect_file(&mut file)?;
    verify_private_file(&file)?;
    Ok(file)
}

/// Opens an existing sensitive regular file without following a destination link.
pub(crate) fn open_existing(path: &Path) -> io::Result<File> {
    ensure_safe_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options.open(path)?;
    reject_reparse_handle(&file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    verify_private_file(&file)?;
    Ok(file)
}

/// Opens an existing sensitive regular file for recovery without relaxing permissions.
pub(crate) fn open_existing_read_write(path: &Path) -> io::Result<File> {
    ensure_safe_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_no_follow(&mut options);
    configure_dacl_access(&mut options);
    let file = options.open(path)?;
    reject_reparse_handle(&file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    verify_private_file(&file)?;
    Ok(file)
}

/// Applies and verifies private permissions after an atomic replacement.
pub(crate) fn protect_existing(path: &Path) -> io::Result<()> {
    ensure_safe_path(path, false)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_no_follow(&mut options);
    configure_dacl_access(&mut options);
    let mut file = options.open(path)?;
    reject_reparse_handle(&file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    protect_file(&mut file)?;
    verify_private_file(&file)
}

/// Applies and verifies private permissions on an already-open regular file.
#[cfg(unix)]
pub(crate) fn protect_open_file(file: &mut File) -> io::Result<()> {
    reject_reparse_handle(file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    protect_file(file)?;
    verify_private_file(file)
}

/// Opens or creates a non-secret lock file without traversing links or reparse points.
pub(crate) fn open_lock(path: &Path) -> io::Result<File> {
    ensure_safe_path(path, true)?;
    match open_existing_lock(path) {
        Ok(file) => return Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open_existing_lock(path)?,
        Err(error) => return Err(error),
    };
    reject_reparse_handle(&file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    Ok(file)
}

fn open_existing_lock(path: &Path) -> io::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) =>
        {
            return Err(unsafe_path());
        }
        Ok(_) => {}
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    configure_no_follow(&mut options);
    let file = options.open(path)?;
    reject_reparse_handle(&file)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_path());
    }
    Ok(file)
}

/// Rejects links and Windows reparse points in every existing path component.
pub(crate) fn ensure_safe_path(path: &Path, leaf_may_be_missing: bool) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(unsafe_path());
    }

    let mut current = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                current.push(component.as_os_str());
                continue;
            }
            Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir => continue,
            Component::ParentDir => return Err(unsafe_path()),
        }
        let is_leaf = index + 1 == components.len();
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                    return Err(unsafe_path());
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::NotFound && is_leaf && leaf_may_be_missing => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn unsafe_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unsafe filesystem path")
}

#[cfg(unix)]
fn configure_no_follow_and_private_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    options.mode(0o600);
    configure_no_follow(options);
}

#[cfg(windows)]
fn configure_no_follow_and_private_create(options: &mut OpenOptions) {
    let _ = options;
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow_and_private_create(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;
    const O_NOFOLLOW: i32 = 0x20_000;
    options.custom_flags(O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

#[cfg(windows)]
fn configure_dacl_access(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    options.access_mode(GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC);
}

#[cfg(not(windows))]
fn configure_dacl_access(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn protect_file(file: &mut File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn protect_file(file: &mut File) -> io::Result<()> {
    windows::protect_file(file)
}

#[cfg(not(any(unix, windows)))]
fn protect_file(_file: &mut File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private file permissions are unsupported on this platform",
    ))
}

#[cfg(unix)]
fn verify_private_file(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sensitive file is accessible by group or others",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_private_file(file: &File) -> io::Result<()> {
    windows::verify_private_file(file)
}

#[cfg(not(any(unix, windows)))]
fn verify_private_file(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private file permissions are unsupported on this platform",
    ))
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
fn reject_reparse_handle(file: &File) -> io::Result<()> {
    if metadata_is_reparse_point(&file.metadata()?) {
        return Err(unsafe_path());
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn reject_reparse_handle(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::{fs::File, io};

    use windows_permissions::{
        LocalBox, SecurityDescriptor,
        constants::{AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation},
        wrappers::{
            ConvertSecurityDescriptorToStringSecurityDescriptor, GetSecurityInfo, SetSecurityInfo,
        },
    };

    pub(super) fn protect_file(file: &mut File) -> io::Result<()> {
        let existing = GetSecurityInfo(
            file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner,
        )?;
        let owner = existing.owner().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "file has no owner SID")
        })?;
        let descriptor: LocalBox<SecurityDescriptor> = private_sddl(&owner.to_string()).parse()?;
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "private DACL is missing"))?;
        SetSecurityInfo(
            file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(dacl),
            None,
        )
    }

    pub(super) fn verify_private_file(file: &File) -> io::Result<()> {
        let descriptor = GetSecurityInfo(
            file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner | SecurityInformation::Dacl,
        )?;
        let owner = descriptor.owner().ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "file has no owner SID")
        })?;
        let owner_sid = owner.to_string();
        let dacl = descriptor
            .dacl()
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "file has no DACL"))?;
        if dacl.len() != 3 {
            return Err(insecure_dacl());
        }

        let mut seen_owner = false;
        let mut seen_system = false;
        let mut seen_administrators = false;
        for index in 0..dacl.len() {
            let ace = dacl.get_ace(index).ok_or_else(insecure_dacl)?;
            if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
                || ace.mask() != AccessRights::FileAllAccess
                || ace.flags().contains(AceFlags::Inherited)
            {
                return Err(insecure_dacl());
            }
            match ace.sid().map(ToString::to_string).as_deref() {
                Some(sid) if sid == owner_sid => seen_owner = true,
                Some("S-1-5-18") => seen_system = true,
                Some("S-1-5-32-544") => seen_administrators = true,
                _ => return Err(insecure_dacl()),
            }
        }
        if !(seen_owner && seen_system && seen_administrators) {
            return Err(insecure_dacl());
        }

        let sddl = ConvertSecurityDescriptorToStringSecurityDescriptor(
            &descriptor,
            SecurityInformation::Dacl,
        )?;
        if !sddl.to_string_lossy().starts_with("D:P") {
            return Err(insecure_dacl());
        }
        Ok(())
    }

    fn private_sddl(owner_sid: &str) -> String {
        format!("D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY)(A;;FA;;;BA)")
    }

    fn insecure_dacl() -> io::Error {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sensitive file DACL is not private",
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use atomic_write_file::AtomicWriteFile;
    use tempfile::tempdir;

    use super::{create_new, open_existing, open_lock, protect_existing};

    #[test]
    fn creates_and_reopens_private_regular_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("secret.bin");
        drop(create_new(&path)?);
        drop(open_existing(&path)?);
        Ok(())
    }

    #[test]
    fn protects_an_atomic_replacement() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("atomic.bin");
        let lock_path = directory.path().join("atomic.bin.lock");
        let initial_lock = open_lock(&lock_path)?;
        initial_lock.lock()?;
        let mut file = AtomicWriteFile::open(&path)?;
        file.write_all(b"secret")?;
        file.sync_all()?;
        file.commit()?;
        protect_existing(&path)?;
        drop(open_existing(&path)?);
        drop(initial_lock);
        let lock = open_lock(&lock_path)?;
        lock.lock()?;
        let mut replacement = AtomicWriteFile::open(&path)?;
        replacement.write_all(b"replacement")?;
        replacement.sync_all()?;
        replacement.commit()?;
        protect_existing(&path)?;
        drop(open_existing(&path)?);
        Ok(())
    }

    #[test]
    fn opens_and_locks_a_regular_lock_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.lock");
        let file = open_lock(&path)?;
        file.lock()?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_leaf() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let target = directory.path().join("target");
        fs::write(&target, b"secret")?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        assert!(open_existing(&link).is_err());
        Ok(())
    }
}
