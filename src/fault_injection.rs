//! Throwaway-vault process target for the crash harness.
//!
//! This module is compiled only with `--features fault-injection`. It exists
//! so the existing kill/restart harness can exercise real Vault rotation and
//! recovery without a TTY and without accepting a password from the
//! environment. The fixed password is not a secret and must never be used to
//! protect real Secret Values.

use std::{
    ffi::OsString,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use crate::{
    audit::AuditEvent,
    crypto::MasterPassword,
    identity::{AuthenticationMethod, Caller, CallerId, CallerKind, IdentityRegistryDocument},
    policy::{
        Operation, PolicyDecision, PolicyDocument, PolicyEffect, PolicySet, VaultOperation,
        VaultPolicyRule, VaultPolicySet,
    },
    secret::SecretId,
    vault::{AuditRuntimeV2, FileVault, VaultError},
};

const TEST_PASSWORD: &[u8] = b"envvault-fault-injection-only";
/// Throwaway password for interactive `audit migrate-v2` TTY kills.
/// Typed at the console only; never passed in argv or the environment.
const INIT_V1_PASSWORD: &[u8] = b"test";
const INIT_FORMAT: &str = "envvault-fault-init";
const INIT_VERSION: u32 = 1;

/// Parse process arguments and run one throwaway-vault command.
///
/// # Errors
///
/// Returns a process exit code. `0` is success for `init`/`init-v1`/`rotate`
/// and `recovered` for `recover`; `2` is `fail_closed`; `3` is `data_loss`.
#[must_use]
pub fn main_from_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    match run(args) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr(), "fault-target: {error}");
            1
        }
    }
}

fn run<I, T>(args: I) -> Result<i32, String>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut command = None;
    let mut work_root = None;
    let mut checkpoints = None;
    let mut index = 1;
    while index < args.len() {
        let arg = args[index].to_string_lossy();
        match arg.as_ref() {
            "init" | "init-v1" | "rotate" | "recover" => {
                command = Some(arg.into_owned());
                index += 1;
            }
            "--work-root" => {
                work_root = Some(PathBuf::from(require_value(&args, &mut index)?));
            }
            "--checkpoints" => {
                checkpoints = Some(PathBuf::from(require_value(&args, &mut index)?));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let work = work_root.ok_or_else(|| "missing --work-root".to_owned())?;
    match command.as_deref() {
        Some("init") => {
            init(&work)?;
            Ok(0)
        }
        Some("init-v1") => {
            init_v1(&work)?;
            Ok(0)
        }
        Some("rotate") => {
            let checkpoints = checkpoints.ok_or_else(|| "missing --checkpoints".to_owned())?;
            rotate(&work, &checkpoints)?;
            Ok(0)
        }
        Some("recover") => Ok(recover(&work)),
        _ => Err("expected init, init-v1, rotate, or recover".to_owned()),
    }
}

fn require_value(args: &[OsString], index: &mut usize) -> Result<OsString, String> {
    let flag = args[*index].to_string_lossy().into_owned();
    *index += 1;
    if *index >= args.len() {
        return Err(format!("{flag} requires a value"));
    }
    let value = args[*index].clone();
    *index += 1;
    Ok(value)
}

fn vault_path(work: &Path) -> PathBuf {
    work.join("vault.json")
}

fn init_marker(work: &Path) -> PathBuf {
    work.join("init.json")
}

fn init(work: &Path) -> Result<(), String> {
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let vault = vault_path(work);
    if vault.exists() {
        return Err("vault.json already exists".to_owned());
    }
    let password = MasterPassword::new(TEST_PASSWORD.to_vec());
    let file = FileVault::create(&vault, &password, b"identity", b"policy")
        .map_err(|error| error.to_string())?;
    AuditRuntimeV2::initialize_new(&vault, file.vault_id(), file.master_key())
        .map_err(|error| error.to_string())?;
    let bytes = fs::metadata(&vault).map_or(0, |meta| meta.len());
    let document = format!(
        "{{\"format\":\"{INIT_FORMAT}\",\"version\":{INIT_VERSION},\"vault_bytes\":{bytes}}}\n"
    );
    fs::write(init_marker(work), document).map_err(|error| error.to_string())?;
    Ok(())
}

fn init_v1(work: &Path) -> Result<(), String> {
    fs::create_dir_all(work).map_err(|error| error.to_string())?;
    let vault = vault_path(work);
    if vault.exists() {
        return Err("vault.json already exists".to_owned());
    }
    let password = MasterPassword::new(INIT_V1_PASSWORD.to_vec());
    let owner_id = CallerId::from_bytes([0x91; 16]);
    let identity = IdentityRegistryDocument::new(1, owner_id)
        .encode()
        .map_err(|error| error.to_string())?;
    let owner = Caller::new(owner_id, CallerKind::Human);
    let mut vault_policy = VaultPolicySet::new();
    for operation in [
        VaultOperation::CreateSecret,
        VaultOperation::ManagePolicy,
        VaultOperation::ManageIdentity,
        VaultOperation::ReadAudit,
        VaultOperation::ManageKeystore,
    ] {
        if !vault_policy.insert(VaultPolicyRule::new(owner, operation, PolicyEffect::Allow)) {
            return Err("duplicate vault policy rule".to_owned());
        }
    }
    let policy = PolicyDocument::new_with_vault_policy(1, PolicySet::new(), vault_policy)
        .and_then(|document| document.encode())
        .map_err(|error| error.to_string())?;
    let mut file = FileVault::create(&vault, &password, &identity, &policy)
        .map_err(|error| error.to_string())?;
    let event = AuditEvent::now_vault(
        owner,
        AuthenticationMethod::MasterPassword,
        VaultOperation::ReadAudit,
        PolicyDecision::Allow,
    );
    file.append_audit_payload(
        &event
            .encode()
            .map_err(|_| "audit event encode failed".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let bytes = fs::metadata(&vault).map_or(0, |meta| meta.len());
    let document = format!(
        "{{\"format\":\"{INIT_FORMAT}\",\"version\":{INIT_VERSION},\"audit\":\"v1\",\"vault_bytes\":{bytes}}}\n"
    );
    fs::write(init_marker(work), document).map_err(|error| error.to_string())?;
    Ok(())
}

fn rotate(work: &Path, checkpoints: &Path) -> Result<(), String> {
    fs::create_dir_all(checkpoints).map_err(|error| error.to_string())?;
    let vault = vault_path(work);
    let password = MasterPassword::new(TEST_PASSWORD.to_vec());
    let file = FileVault::open(&vault, &password).map_err(|error| error.to_string())?;
    let descriptor_mtime = sidecar_modified(&vault, ".audit-descriptor-v3.json");
    let stop = spawn_watcher(work, checkpoints, descriptor_mtime);
    let mut runtime = AuditRuntimeV2::local_mirror_with_rotation_events(1);
    let event = AuditEvent::now(
        Caller::new(CallerId::from_bytes([0x11; 16]), CallerKind::Application),
        AuthenticationMethod::ApplicationCredential,
        SecretId::from_bytes([0x22; 16]),
        Operation::Use,
        PolicyDecision::Allow,
    );
    let result = runtime.append(&vault, file.master_key(), event);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    result.map_err(|error| error.to_string())
}

fn recover(work: &Path) -> i32 {
    let vault = vault_path(work);
    if !vault.exists() {
        return if init_marker(work).exists() {
            emit("data_loss", "init completed but the Vault file is gone", 3)
        } else {
            emit(
                "fail_closed",
                "no Vault file; nothing durable was committed",
                2,
            )
        };
    }
    let password = MasterPassword::new(TEST_PASSWORD.to_vec());
    let file = match FileVault::open(&vault, &password) {
        Ok(file) => file,
        Err(error) => {
            return emit("fail_closed", &format!("vault would not open: {error}"), 2);
        }
    };
    let mut runtime = AuditRuntimeV2::local_mirror();
    match runtime.read_all(&vault, file.master_key()) {
        Ok(events) => emit(
            "recovered",
            &format!("audit chain readable; events={}", events.len()),
            0,
        ),
        Err(VaultError::AuditAnchorDegraded | VaultError::CorruptedAudit) => emit(
            "fail_closed",
            "audit recovery failed closed after restart",
            2,
        ),
        Err(error) => emit(
            "fail_closed",
            &format!("audit could not be read: {error}"),
            2,
        ),
    }
}

fn emit(verdict: &str, detail: &str, code: i32) -> i32 {
    let escaped = detail.replace('\\', "\\\\").replace('"', "\\\"");
    let _ = writeln!(
        io::stdout(),
        "{{\"verdict\":\"{verdict}\",\"detail\":\"{escaped}\"}}"
    );
    code
}

fn spawn_watcher(
    work: &Path,
    checkpoints: &Path,
    descriptor_mtime_before: Option<std::time::SystemTime>,
) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let work = work.to_path_buf();
    let checkpoints = checkpoints.to_path_buf();
    thread::spawn(move || {
        let vault = vault_path(&work);
        let mut seen_manifest = false;
        let mut seen_sealed = false;
        let mut seen_commit = false;
        let mut seen_anchor = false;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !flag.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
            if !seen_manifest && sidecar_exists(&vault, ".audit-rotation-recovery.json") {
                mark(&checkpoints, "prepared-manifest");
                seen_manifest = true;
            }
            if !seen_sealed && sealed_segment_exists(&work) {
                mark(&checkpoints, "sealed-segment");
                seen_sealed = true;
            }
            if !seen_commit {
                let current = sidecar_modified(&vault, ".audit-descriptor-v3.json");
                if current != descriptor_mtime_before && current.is_some() {
                    mark(&checkpoints, "vault-committed");
                    seen_commit = true;
                }
            }
            if !seen_anchor
                && (sidecar_exists(&vault, ".audit-anchor-v2.json")
                    || sidecar_exists(&vault, ".audit-anchor-confirmed.json"))
            {
                mark(&checkpoints, "anchor-confirmed");
                seen_anchor = true;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    stop
}

fn sidecar_path(vault: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(vault.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

fn sidecar_exists(vault: &Path, suffix: &str) -> bool {
    sidecar_path(vault, suffix).exists()
}

fn sidecar_modified(vault: &Path, suffix: &str) -> Option<std::time::SystemTime> {
    fs::metadata(sidecar_path(vault, suffix))
        .and_then(|meta| meta.modified())
        .ok()
}

fn sealed_segment_exists(work: &Path) -> bool {
    let Ok(entries) = fs::read_dir(work) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .starts_with("envvault-audit-segment-")
    })
}

fn mark(checkpoints: &Path, name: &str) {
    let _ = fs::write(checkpoints.join(name), []);
}

#[cfg(test)]
mod tests {
    use super::{init, init_v1, recover, rotate, vault_path};
    use crate::vault::AuditRuntimeV2;
    use tempfile::tempdir;

    #[test]
    fn init_rotate_recover_without_kill_reads_the_audit_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let work = root.path();
        let checkpoints = work.join("checkpoints");
        init(work)?;
        rotate(work, &checkpoints)?;
        assert_eq!(recover(work), 0);
        Ok(())
    }

    #[test]
    fn init_v1_creates_a_legacy_vault_without_v2_sidecars() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempdir()?;
        let work = root.path();
        init_v1(work)?;
        assert!(vault_path(work).exists());
        assert!(!AuditRuntimeV2::exists(vault_path(work).as_path())?);
        Ok(())
    }
}
