//! CLI command handlers.
//!
//! Handlers will translate user intent into broker or administrative requests;
//! they must not bypass authorization or vault boundaries.

use std::{
    env,
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::ExitStatus,
};

use crate::cli::{
    application::CliApplication,
    args::{
        AuditCommand, Cli, Command, IdentityCommand, KeystoreCommand, PolicyCommand,
        ProfileCommand, SessionCommand,
    },
    credential_file::{PendingCredentialFile, read as read_credential},
    credential_recovery::CredentialDelivery,
    dotenv_file::read_source,
    error::CliError,
    example_file::write_new,
    password::SensitiveInput,
    profile_file::{read as read_profile, write_new as write_new_profile},
};
use crate::{
    config::{self, Project},
    dotenv, process,
    secret::{SecretName, SecretRecord},
};

pub(super) enum ExecutionOutcome {
    Success,
    Child(ExitStatus),
}

pub(super) fn execute(
    cli: Cli,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<ExecutionOutcome, CliError> {
    let mut project = config::discover_from_cwd()?;
    if let Command::Uninstall { purge_project } = cli.command {
        super::uninstall::execute(purge_project, project.as_ref(), sensitive_input, output)?;
        return Ok(ExecutionOutcome::Success);
    }
    if let Command::Audit {
        command:
            AuditCommand::ServeAnchor {
                data_dir,
                listen,
                token_file,
                tls_cert,
                tls_key,
                allow_plaintext,
            },
    } = cli.command
    {
        execute_serve_anchor(
            &data_dir,
            listen.as_deref(),
            token_file.as_deref(),
            tls_cert.as_deref(),
            tls_key.as_deref(),
            allow_plaintext,
            output,
        )?;
        return Ok(ExecutionOutcome::Success);
    }
    let vault = resolve_vault(cli.vault.as_deref(), project.as_ref(), &cli.command)?;
    dispatch(cli, &vault, project.as_mut(), sensitive_input, output)
}

fn dispatch(
    cli: Cli,
    vault: &Path,
    mut project: Option<&mut Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<ExecutionOutcome, CliError> {
    match cli.command {
        Command::Init => execute_init(vault, cli.vault.is_none(), sensitive_input, output)?,
        Command::Set { name } => execute_set(vault, name, sensitive_input, output)?,
        Command::Verify { name } => execute_verify(vault, name, sensitive_input, output)?,
        Command::List => execute_list(vault, sensitive_input, output)?,
        Command::Exists { name } => execute_exists(vault, name, sensitive_input, output)?,
        Command::Remove { name } => execute_remove(vault, name, sensitive_input, output)?,
        Command::Import { source } => execute_import(vault, &source, sensitive_input, output)?,
        Command::Example { output: path } => {
            execute_example(vault, &path, sensitive_input, output)?;
        }
        Command::Identity { command } => {
            execute_identity(
                vault,
                command,
                project.as_deref_mut(),
                sensitive_input,
                output,
            )?;
        }
        Command::Profile { command } => {
            execute_profile(
                vault,
                command,
                project.as_deref_mut(),
                sensitive_input,
                output,
            )?;
        }
        Command::Policy { command } => {
            execute_policy(vault, command, project.as_deref(), sensitive_input, output)?;
        }
        Command::Audit { command } => execute_audit(vault, command, sensitive_input, output)?,
        Command::Keystore { command } => {
            execute_keystore(vault, command, sensitive_input, output)?;
        }
        Command::Session {
            credential_file,
            machine_unlock,
            command,
        } => {
            let credential_file = resolve_credential(credential_file, project.as_deref())?;
            execute_session(
                vault,
                &credential_file,
                machine_unlock,
                command,
                sensitive_input,
                output,
            )?;
        }
        Command::Run {
            profile,
            credential_file,
            machine_unlock,
            command,
        } => {
            let profile = resolve_profile(profile, project.as_deref())?;
            let credential_file = resolve_credential(credential_file, project.as_deref())?;
            return execute_run(
                vault,
                &profile,
                &credential_file,
                &command,
                machine_unlock,
                sensitive_input,
            )
            .map(ExecutionOutcome::Child);
        }
        Command::Uninstall { purge_project } => {
            super::uninstall::execute(purge_project, project.as_deref(), sensitive_input, output)?;
        }
    }
    Ok(ExecutionOutcome::Success)
}

fn execute_set(
    vault: &Path,
    name: String,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let value = sensitive_input.read_secret_value()?;
    let record = application.set_secret(name, &value)?;
    writeln!(output, "Secret stored")?;
    writeln!(output, "secret_id: {}", record.id())?;
    Ok(())
}

fn execute_list(
    vault: &Path,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    for record in application.list_secrets()? {
        writeln!(output, "{}", record.name())?;
    }
    Ok(())
}

fn execute_exists(
    vault: &Path,
    name: String,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    writeln!(output, "{}", application.secret_exists(&name)?)?;
    Ok(())
}

fn execute_remove(
    vault: &Path,
    name: String,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    application.remove_secret(&name)?;
    writeln!(output, "Secret removed")?;
    Ok(())
}

fn execute_import(
    vault: &Path,
    source: &Path,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let source_bytes = read_source(source)?;
    let entries = dotenv::parse(&source_bytes)?;
    drop(source_bytes);
    let imported = application.import_secrets(entries)?;
    writeln!(output, "Imported {} Secrets", imported.len())?;
    writeln!(output, "source_preserved: yes")?;
    Ok(())
}

fn execute_example(
    vault: &Path,
    path: &Path,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let records = application.list_secrets()?;
    let example = dotenv::render_example(records.iter().map(SecretRecord::name))?;
    write_new(path, &example)?;
    writeln!(output, "Example generated")?;
    writeln!(output, "example_file_created: yes")?;
    Ok(())
}

fn execute_verify(
    vault: &Path,
    name: String,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let expected = sensitive_input.read_expected_secret_value()?;
    let matches = application.verify_secret(&name, &expected)?;
    writeln!(output, "{}", if matches { "match" } else { "mismatch" })?;
    Ok(())
}

fn execute_init(
    vault: &Path,
    write_project_file: bool,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    if let Some(parent) = vault.parent() {
        config::ensure_vault_dir(parent)?;
    }
    let password = sensitive_input.read_new()?;
    let owner = CliApplication::init(vault, &password)?;
    writeln!(output, "Vault initialized")?;
    writeln!(output, "owner_id: {}", owner.id())?;
    if write_project_file {
        let cwd = env::current_dir().map_err(|_| CliError::OutputUnavailable)?;
        let project = config::default_layout(&cwd);
        match config::write_new(&project) {
            Ok(()) => {
                writeln!(output, "project_file: {}", project.file_path().display())?;
            }
            Err(config::ProjectError::AlreadyExists) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn execute_policy(
    vault: &Path,
    command: PolicyCommand,
    project: Option<&Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        PolicyCommand::GrantUse { caller_id, profile } => {
            let caller_id = caller_id
                .or_else(|| project.and_then(Project::caller_id))
                .ok_or(CliError::ProjectDefaultMissing)?;
            let profile = resolve_profile(profile, project)?;
            let profile = read_profile(&profile)?;
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let generation = application.grant_profile_use(caller_id, &profile)?;
            writeln!(output, "Profile use granted")?;
            writeln!(output, "bindings: {}", profile.bindings().len())?;
            writeln!(output, "policy_generation: {generation}")?;
        }
    }
    Ok(())
}

fn execute_keystore(
    vault: &Path,
    command: KeystoreCommand,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let status = match command {
        KeystoreCommand::Enable => application.enable_machine_unlock()?,
        KeystoreCommand::Status => application.machine_unlock_status()?,
        KeystoreCommand::Rotate => application.rotate_machine_unlock()?,
        KeystoreCommand::Disable => application.disable_machine_unlock()?,
    };
    writeln!(output, "enabled: {}", status.enabled())?;
    writeln!(output, "backend: {}", status.backend())?;
    writeln!(output, "credential_generation: {}", status.generation())?;
    writeln!(output, "cleanup_pending: {}", status.cleanup_pending())?;
    Ok(())
}

fn execute_audit(
    vault: &Path,
    command: AuditCommand,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        AuditCommand::List => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            for event in application.audit_events()? {
                write_audit_event(output, event)?;
            }
        }
        AuditCommand::MigrateV2 => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner_for_audit_migration(vault, &password)?;
            let migrated = application.migrate_audit_v2()?;
            writeln!(output, "Audit V2 migration completed")?;
            writeln!(output, "migrated_events: {migrated}")?;
        }
        AuditCommand::ServeAnchor { .. } => {
            return Err(CliError::AnchorUnavailable);
        }
        AuditCommand::ConfigureAnchor {
            endpoint,
            token_file,
            tls_ca,
            allow_plaintext,
        } => {
            let password = sensitive_input.read_existing()?;
            let _application = CliApplication::open_owner(vault, &password)?;
            crate::vault::configure_anchor_client(
                vault,
                &endpoint,
                &token_file,
                tls_ca.as_deref(),
                allow_plaintext,
            )?;
            writeln!(output, "mandatory Audit anchor configured")?;
            writeln!(output, "mode: mandatory")?;
            writeln!(output, "endpoint: {endpoint}")?;
            writeln!(output, "token_file: {}", token_file.display())?;
            if let Some(ca) = tls_ca {
                writeln!(output, "tls_ca: {}", ca.display())?;
            }
            writeln!(output, "allow_plaintext: {allow_plaintext}")?;
        }
        AuditCommand::AnchorStatus => {
            write_anchor_status(vault, output)?;
        }
    }
    Ok(())
}

fn execute_serve_anchor(
    data_dir: &Path,
    listen: Option<&str>,
    token_file: Option<&Path>,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    allow_plaintext: bool,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let listen = listen.unwrap_or_else(|| crate::vault::default_listen_addr());
    let mut bound = match (tls_cert, tls_key, allow_plaintext) {
        (Some(cert), Some(key), false) => {
            crate::vault::AnchorHttpServer::bind_tls(data_dir, listen, token_file, cert, key)?
        }
        (None, None, true) => crate::vault::AnchorHttpServer::bind(data_dir, listen, token_file)?,
        _ => return Err(CliError::AnchorInvalid),
    };
    let addr = bound.server.local_addr()?;
    writeln!(output, "Audit anchor CAS listening")?;
    writeln!(output, "listen: {addr}")?;
    writeln!(output, "data_dir: {}", data_dir.display())?;
    writeln!(output, "token_file: {}", bound.token_path.display())?;
    writeln!(
        output,
        "tls: {}",
        if bound.server.tls_enabled() {
            "rustls"
        } else {
            "none (explicit plaintext)"
        }
    )?;
    output.flush()?;
    bound.server.serve_forever()?;
    Ok(())
}

fn write_anchor_status(vault: &Path, output: &mut dyn Write) -> Result<(), CliError> {
    let status = crate::vault::load_anchor_status(vault, None)?;
    writeln!(output, "configured: {}", status.configured)?;
    if let Some(mode) = status.mode {
        let _ = mode;
        writeln!(output, "mode: mandatory")?;
    }
    if let Some(endpoint) = status.endpoint {
        writeln!(output, "endpoint: {endpoint}")?;
    }
    if let Some(token_file) = status.token_file {
        writeln!(output, "token_file: {}", token_file.display())?;
    }
    if let Some(ca) = status.tls_ca {
        writeln!(output, "tls_ca: {}", ca.display())?;
    }
    writeln!(
        output,
        "tls: {}",
        if status.allow_plaintext {
            "none (explicit plaintext)"
        } else if status.configured {
            "rustls"
        } else {
            "none"
        }
    )?;
    match status.last_confirmed_generation {
        Some(generation) => writeln!(output, "last_confirmed_generation: {generation}")?,
        None => writeln!(output, "last_confirmed_generation: none")?,
    }
    match status.last_confirmed_digest {
        Some(digest) => writeln!(output, "last_confirmed_digest: {}", hex_digest(&digest))?,
        None => writeln!(output, "last_confirmed_digest: none")?,
    }
    writeln!(
        output,
        "rollback_evidence: {}",
        if status.rollback_evidence {
            "yes"
        } else {
            "no"
        }
    )?;
    if let Some(generation) = status.rollback_expected_generation {
        writeln!(output, "rollback_expected_generation: {generation}")?;
    }
    if let Some(generation) = status.rollback_observed_generation {
        writeln!(output, "rollback_observed_generation: {generation}")?;
    }
    Ok(())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn write_audit_event(
    output: &mut dyn Write,
    event: crate::audit::AuditEvent,
) -> Result<(), CliError> {
    let target = event.secret_id().map_or_else(
        || {
            if event.is_authentication_attempt() {
                "authentication".to_owned()
            } else {
                event.vault_operation().map_or_else(
                    || "invalid".to_owned(),
                    |operation| format!("vault:{operation}"),
                )
            }
        },
        |secret_id| {
            let operation = event
                .operation()
                .map_or_else(|| "invalid".to_owned(), |value| value.to_string());
            format!("secret:{secret_id}:{operation}")
        },
    );
    writeln!(
        output,
        "{}\t{}:{}\t{}\t{}\t{:?}",
        event.unix_time_millis(),
        event.caller().kind(),
        event.caller().id(),
        event.authentication_method().as_str(),
        target,
        event.decision()
    )?;
    Ok(())
}

fn execute_profile(
    vault: &Path,
    command: ProfileCommand,
    project: Option<&mut Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        ProfileCommand::Create {
            output: path,
            secrets,
        } => {
            let names = secrets
                .into_iter()
                .map(SecretName::new)
                .collect::<Result<Vec<_>, _>>()?;
            let path = resolve_profile(path, project.as_deref())?;
            if let Some(parent) = path.parent() {
                config::ensure_vault_dir(parent)?;
            }
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let profile = application.create_profile(names)?;
            write_new_profile(&path, &profile)?;
            if let Some(project) = project {
                project.set_default_profile(&path)?;
            }
            writeln!(output, "Profile created")?;
            writeln!(output, "bindings: {}", profile.bindings().len())?;
            writeln!(output, "profile_file_created: yes")?;
        }
    }
    Ok(())
}

fn execute_run(
    vault: &Path,
    profile_path: &Path,
    credential_file: &Path,
    command: &[OsString],
    machine_unlock: bool,
    sensitive_input: &mut dyn SensitiveInput,
) -> Result<ExitStatus, CliError> {
    let profile = read_profile(profile_path)?;
    let mut application =
        open_machine_caller(vault, credential_file, machine_unlock, sensitive_input)?;
    let secrets = application.use_profile(&profile)?;
    process::run(command, &secrets).map_err(Into::into)
}

fn execute_session(
    vault: &Path,
    credential_file: &Path,
    machine_unlock: bool,
    command: SessionCommand,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let application = open_machine_caller(vault, credential_file, machine_unlock, sensitive_input)?;
    match command {
        SessionCommand::Whoami => {
            let caller = application.authenticated_caller();
            writeln!(output, "caller_id: {}", caller.id())?;
            writeln!(output, "caller_kind: {}", caller.kind())?;
            writeln!(
                output,
                "authentication_method: {}",
                application.authentication_method().as_str()
            )?;
        }
    }
    Ok(())
}

fn open_machine_caller(
    vault: &Path,
    credential_file: &Path,
    machine_unlock: bool,
    sensitive_input: &mut dyn SensitiveInput,
) -> Result<CliApplication, CliError> {
    let evidence = read_credential(credential_file)?;
    let application = if machine_unlock {
        CliApplication::open_caller_with_machine_unlock(
            vault,
            evidence.caller_id,
            evidence.caller_kind,
            &evidence.credential,
        )?
    } else {
        let password = sensitive_input.read_existing()?;
        CliApplication::open_caller(
            vault,
            &password,
            evidence.caller_id,
            evidence.caller_kind,
            &evidence.credential,
        )?
    };
    Ok(application)
}

fn execute_identity(
    vault: &Path,
    command: IdentityCommand,
    mut project: Option<&mut Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        IdentityCommand::Register {
            kind,
            name,
            credential_file,
        } => {
            let credential_file = match credential_file {
                Some(path) => path,
                None => default_credential_path(project.as_deref(), &name)?,
            };
            if let Some(parent) = credential_file.parent() {
                config::ensure_vault_dir(parent)?;
            }
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let prepared = application.prepare_caller_registration(kind.into(), name)?;
            let delivery = CredentialDelivery::begin(vault, &credential_file, &prepared)?;
            let destination = PendingCredentialFile::create(&delivery.destination()?)?;
            let issued = application.commit_caller_registration(prepared)?;
            destination.write(&issued)?;
            delivery.finish()?;
            if let Some(project) = project.as_mut() {
                project.set_default_caller(issued.caller().id(), &credential_file)?;
            }
            writeln!(output, "Caller registered")?;
            writeln!(output, "caller_id: {}", issued.caller().id())?;
            writeln!(output, "caller_kind: {}", issued.caller().kind())?;
            writeln!(output, "credential_file_created: yes")?;
        }
        IdentityCommand::List => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            for registered in application.registered_callers()? {
                let expiry = registered
                    .credential_expires_unix_time_millis()
                    .map_or_else(|| "legacy-unbounded".to_owned(), |value| value.to_string());
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}",
                    registered.caller().id(),
                    registered.caller().kind(),
                    registered.name().as_str(),
                    expiry,
                )?;
            }
        }
        IdentityCommand::Revoke { caller_id } => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let generation = application.revoke_caller(caller_id)?;
            writeln!(output, "Caller revoked")?;
            writeln!(output, "identity_generation: {generation}")?;
        }
        IdentityCommand::Rotate {
            caller_id,
            credential_file,
        } => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let prepared = application.prepare_caller_rotation(caller_id)?;
            let delivery = CredentialDelivery::begin_rotation(vault, &credential_file, &prepared)?;
            let destination = PendingCredentialFile::create(&delivery.destination()?)?;
            let issued = application.commit_caller_rotation(prepared)?;
            destination.write(&issued)?;
            delivery.finish()?;
            writeln!(output, "Caller credential rotated")?;
            writeln!(output, "caller_id: {}", issued.caller().id())?;
            writeln!(output, "caller_kind: {}", issued.caller().kind())?;
            writeln!(output, "credential_file_created: yes")?;
        }
    }
    Ok(())
}

fn resolve_vault(
    explicit: Option<&Path>,
    project: Option<&Project>,
    command: &Command,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if matches!(command, Command::Init | Command::Uninstall { .. }) {
        let cwd = env::current_dir().map_err(|_| CliError::OutputUnavailable)?;
        return Ok(config::default_layout(&cwd).vault().to_path_buf());
    }
    project
        .map(|value| value.vault().to_path_buf())
        .ok_or(CliError::VaultPathRequired)
}

fn resolve_profile(
    explicit: Option<PathBuf>,
    project: Option<&Project>,
) -> Result<PathBuf, CliError> {
    explicit
        .or_else(|| project.map(|value| value.profile().to_path_buf()))
        .ok_or(CliError::ProjectDefaultMissing)
}

fn resolve_credential(
    explicit: Option<PathBuf>,
    project: Option<&Project>,
) -> Result<PathBuf, CliError> {
    explicit
        .or_else(|| project.map(|value| value.credential_file().to_path_buf()))
        .ok_or(CliError::ProjectDefaultMissing)
}

fn default_credential_path(project: Option<&Project>, name: &str) -> Result<PathBuf, CliError> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || name.is_empty()
    {
        return Err(CliError::InvalidCallerName);
    }
    let root = match project {
        Some(project) => project.root().to_path_buf(),
        None => env::current_dir().map_err(|_| CliError::OutputUnavailable)?,
    };
    Ok(root
        .join(".envvault")
        .join(format!("{name}.credential.json")))
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, env, ffi::OsString, fs, path::PathBuf, str::FromStr as _};

    use serde_json::Value;
    use tempfile::tempdir;

    use super::{ExecutionOutcome, execute};
    use crate::{
        cli::{
            args::{
                AuditCommand, CallerKindArg, Cli, Command, IdentityCommand, PolicyCommand,
                ProfileCommand, SessionCommand,
            },
            error::CliError,
            password::{ConfirmReader, PasswordReader, SecretValueReader},
        },
        crypto::MasterPassword,
        identity::CallerId,
        secret::SecretValue,
    };

    struct FixedSensitiveInput {
        passwords: VecDeque<Vec<u8>>,
        secret_values: VecDeque<Vec<u8>>,
    }

    impl FixedSensitiveInput {
        fn repeated(value: &[u8], count: usize) -> Self {
            Self {
                passwords: (0..count).map(|_| value.to_vec()).collect(),
                secret_values: VecDeque::new(),
            }
        }

        fn with_secret_values(mut self, values: &[&[u8]]) -> Self {
            self.secret_values = values.iter().map(|value| value.to_vec()).collect();
            self
        }

        fn next(&mut self) -> Result<MasterPassword, CliError> {
            self.passwords
                .pop_front()
                .map(MasterPassword::new)
                .ok_or(CliError::PasswordInputUnavailable)
        }
    }

    impl PasswordReader for FixedSensitiveInput {
        fn read_new(&mut self) -> Result<MasterPassword, CliError> {
            self.next()
        }

        fn read_existing(&mut self) -> Result<MasterPassword, CliError> {
            self.next()
        }
    }

    impl SecretValueReader for FixedSensitiveInput {
        fn read_secret_value(&mut self) -> Result<SecretValue, CliError> {
            self.secret_values
                .pop_front()
                .map(SecretValue::new)
                .ok_or(CliError::SecretInputUnavailable)
        }
    }

    impl ConfirmReader for FixedSensitiveInput {
        fn confirm_phrase(&mut self, _expected: &str) -> Result<(), CliError> {
            Err(CliError::ConfirmationUnavailable)
        }
    }

    #[test]
    fn verify_reports_only_match_state_and_never_the_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("verify.vault.json");
        let password = b"verify-test-password";
        let secret = b"verify-test-secret-value";
        let wrong = b"wrong-expected-value";
        let mut input =
            FixedSensitiveInput::repeated(password, 4).with_secret_values(&[secret, secret, wrong]);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "TEST_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        output.clear();
        execute(
            cli(
                vault.clone(),
                Command::Verify {
                    name: "TEST_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        assert_eq!(String::from_utf8(output.clone())?, "match\n");

        output.clear();
        execute(
            cli(
                vault,
                Command::Verify {
                    name: "TEST_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        assert_eq!(String::from_utf8(output.clone())?, "mismatch\n");
        let rendered = String::from_utf8(output)?;
        assert!(!rendered.contains(std::str::from_utf8(secret)?));
        assert!(!rendered.contains(std::str::from_utf8(wrong)?));
        Ok(())
    }

    fn cli(vault: PathBuf, command: Command) -> Cli {
        Cli {
            vault: Some(vault),
            masked_input: false,
            command,
        }
    }

    #[test]
    fn owner_cli_identity_lifecycle_never_prints_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("test.vault.json");
        let credential_file = directory.path().join("test-app.credential.json");
        let rotated_credential_file = directory.path().join("test-app.rotated.json");
        let password = b"cli-lifecycle-test-password";
        let mut passwords = FixedSensitiveInput::repeated(password, 5);
        let mut output = Vec::new();

        execute(
            cli(vault.clone(), Command::Init),
            &mut passwords,
            &mut output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Register {
                        kind: CallerKindArg::Application,
                        name: "test-app".to_owned(),
                        credential_file: Some(credential_file.clone()),
                    },
                },
            ),
            &mut passwords,
            &mut output,
        )?;

        let credential_bytes = fs::read(&credential_file)?;
        let credential_document: Value = serde_json::from_slice(&credential_bytes)?;
        let credential = credential_document["credential"]
            .as_str()
            .ok_or("missing credential")?;
        let caller_id = CallerId::from_str(
            credential_document["caller_id"]
                .as_str()
                .ok_or("missing caller id")?,
        )?;
        let output_text = String::from_utf8(output.clone())?;
        assert!(!output_text.contains(credential));
        assert!(!output_text.contains(std::str::from_utf8(password)?));

        let list_output_start = output.len();
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::List,
                },
            ),
            &mut passwords,
            &mut output,
        )?;
        let list_output = std::str::from_utf8(&output[list_output_start..])?;
        let fields = list_output.trim().split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[2], "test-app");
        assert_ne!(fields[3], "legacy-unbounded");
        let _expires_unix_time_millis = fields[3].parse::<u64>()?;

        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Rotate {
                        caller_id,
                        credential_file: rotated_credential_file.clone(),
                    },
                },
            ),
            &mut passwords,
            &mut output,
        )?;
        let rotated_document: Value = serde_json::from_slice(&fs::read(&rotated_credential_file)?)?;
        let rotated_credential = rotated_document["credential"]
            .as_str()
            .ok_or("missing rotated credential")?;
        assert_ne!(rotated_credential, credential);
        let rotation_output = String::from_utf8(output.clone())?;
        assert!(rotation_output.contains("Caller credential rotated"));
        assert!(!rotation_output.contains(rotated_credential));

        execute(
            cli(
                vault,
                Command::Identity {
                    command: IdentityCommand::Revoke { caller_id },
                },
            ),
            &mut passwords,
            &mut output,
        )?;
        let final_output = String::from_utf8(output)?;
        assert!(final_output.contains("Caller revoked"));
        assert!(!final_output.contains(credential));
        assert!(!final_output.contains(rotated_credential));
        Ok(())
    }

    #[test]
    fn machine_identity_session_prints_only_verified_identity_and_is_audited()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("session.vault.json");
        let credential_file = directory.path().join("session-agent.credential.json");
        let password = b"session-test-password";
        let mut input = FixedSensitiveInput::repeated(password, 4);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Register {
                        kind: CallerKindArg::AiAgent,
                        name: "session-agent".to_owned(),
                        credential_file: Some(credential_file.clone()),
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let credential_document: Value = serde_json::from_slice(&fs::read(&credential_file)?)?;
        let credential = credential_document["credential"]
            .as_str()
            .ok_or("missing credential")?;
        let caller_id = credential_document["caller_id"]
            .as_str()
            .ok_or("missing caller id")?;
        output.clear();

        execute(
            cli(
                vault.clone(),
                Command::Session {
                    credential_file: Some(credential_file),
                    machine_unlock: false,
                    command: SessionCommand::Whoami,
                },
            ),
            &mut input,
            &mut output,
        )?;
        let whoami = String::from_utf8(output.clone())?;
        assert!(whoami.contains(caller_id));
        assert!(whoami.contains("caller_kind: ai_agent"));
        assert!(whoami.contains("authentication_method: agent_credential"));
        assert!(!whoami.contains(credential));
        assert!(!whoami.contains(std::str::from_utf8(password)?));

        output.clear();
        execute(
            cli(
                vault,
                Command::Audit {
                    command: AuditCommand::List,
                },
            ),
            &mut input,
            &mut output,
        )?;
        let audit = String::from_utf8(output)?;
        assert!(audit.contains("authentication"));
        assert!(audit.contains(caller_id));
        assert!(!audit.contains(credential));
        Ok(())
    }

    #[test]
    fn owner_cli_secret_lifecycle_never_prints_values() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("secrets.vault.json");
        let password = b"secret-cli-test-password";
        let first_value = b"first-secret-value";
        let second_value = b"second-secret-value";
        let mut input = FixedSensitiveInput::repeated(password, 7)
            .with_secret_values(&[first_value, second_value]);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(cli(vault.clone(), Command::List), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Exists {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Remove {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault,
                Command::Exists {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;

        let output = String::from_utf8(output)?;
        assert!(output.contains("API_TOKEN"));
        assert!(output.contains("true"));
        assert!(output.contains("false"));
        assert!(output.contains("Secret removed"));
        assert!(!output.contains(std::str::from_utf8(password)?));
        assert!(!output.contains(std::str::from_utf8(first_value)?));
        assert!(!output.contains(std::str::from_utf8(second_value)?));
        Ok(())
    }

    #[test]
    fn dotenv_import_and_example_never_emit_values_or_delete_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("dotenv.vault.json");
        let source = directory.path().join("source.env");
        let example = directory.path().join("generated.env.example");
        let password = b"dotenv-cli-test-password";
        let database = b"postgres://dotenv-test";
        let token = b"dotenv-secret-token";
        fs::write(
            &source,
            format!(
                "DATABASE_URL={}\nAPI_TOKEN='{}'\n",
                std::str::from_utf8(database)?,
                std::str::from_utf8(token)?
            ),
        )?;
        let original_source = fs::read(&source)?;
        let mut input = FixedSensitiveInput::repeated(password, 3);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Import {
                    source: source.clone(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault,
                Command::Example {
                    output: example.clone(),
                },
            ),
            &mut input,
            &mut output,
        )?;

        assert_eq!(fs::read(&source)?, original_source);
        assert_eq!(fs::read(&example)?, b"API_TOKEN=\nDATABASE_URL=\n");
        let output = String::from_utf8(output)?;
        assert!(output.contains("Imported 2 Secrets"));
        assert!(output.contains("source_preserved"));
        assert!(!output.contains(std::str::from_utf8(database)?));
        assert!(!output.contains(std::str::from_utf8(token)?));
        assert!(
            !fs::read(&example)?
                .windows(token.len())
                .any(|window| window == token)
        );
        Ok(())
    }

    #[test]
    fn invalid_dotenv_import_commits_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("invalid.vault.json");
        let source = directory.path().join("invalid.env");
        fs::write(&source, b"VALID_KEY=value\nVALID_KEY=duplicate\n")?;
        let password = b"invalid-dotenv-test-password";
        let mut input = FixedSensitiveInput::repeated(password, 3);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        assert!(
            execute(
                cli(vault.clone(), Command::Import { source }),
                &mut input,
                &mut output,
            )
            .is_err()
        );
        output.clear();
        execute(cli(vault, Command::List), &mut input, &mut output)?;
        assert!(output.is_empty());
        Ok(())
    }

    #[test]
    fn audit_cli_lists_value_free_v2_events_and_refuses_repeat_migration()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("audit.vault.json");
        let password = b"audit-cli-test-password";
        let secret = b"AUDIT_CLI_SECRET_SENTINEL";
        let mut input = FixedSensitiveInput::repeated(password, 4).with_secret_values(&[secret]);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "API_TOKEN".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        output.clear();
        execute(
            cli(
                vault.clone(),
                Command::Audit {
                    command: AuditCommand::List,
                },
            ),
            &mut input,
            &mut output,
        )?;
        let rendered = String::from_utf8(output.clone())?;
        assert!(rendered.contains("read_audit"));
        assert!(!rendered.contains(std::str::from_utf8(secret)?));

        assert!(
            execute(
                cli(
                    vault,
                    Command::Audit {
                        command: AuditCommand::MigrateV2,
                    },
                ),
                &mut input,
                &mut output,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn profile_run_denies_before_grant_then_injects_only_after_exact_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        if env::var("ENVVAULT_CLI_RUN_TEST_MODE").as_deref() == Ok("child") {
            assert!(env::var_os("CARGO_MANIFEST_DIR").is_none());
            return Ok(());
        }

        let directory = tempdir()?;
        let vault = directory.path().join("runtime.vault.json");
        let credential_file = directory.path().join("backend.credential.json");
        let profile_file = directory.path().join("backend.profile.json");
        let password = b"profile-runtime-test-password";
        let secret = b"child";
        let mut input = FixedSensitiveInput::repeated(password, 7).with_secret_values(&[secret]);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "ENVVAULT_CLI_RUN_TEST_MODE".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Register {
                        kind: CallerKindArg::Application,
                        name: "runtime-backend".to_owned(),
                        credential_file: Some(credential_file.clone()),
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let credential_document: Value = serde_json::from_slice(&fs::read(&credential_file)?)?;
        let caller_id = CallerId::from_str(
            credential_document["caller_id"]
                .as_str()
                .ok_or("missing caller id")?,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Profile {
                    command: ProfileCommand::Create {
                        output: Some(profile_file.clone()),
                        secrets: vec!["ENVVAULT_CLI_RUN_TEST_MODE".to_owned()],
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let child_command = vec![
            env::current_exe()?.into_os_string(),
            OsString::from("--exact"),
            OsString::from(
                "cli::commands::tests::profile_run_denies_before_grant_then_injects_only_after_exact_grant",
            ),
        ];
        let runtime_command = || Command::Run {
            profile: Some(profile_file.clone()),
            credential_file: Some(credential_file.clone()),
            machine_unlock: false,
            command: child_command.clone(),
        };
        assert!(
            execute(
                cli(vault.clone(), runtime_command()),
                &mut input,
                &mut output,
            )
            .is_err()
        );

        execute(
            cli(
                vault.clone(),
                Command::Policy {
                    command: PolicyCommand::GrantUse {
                        caller_id: Some(caller_id),
                        profile: Some(profile_file.clone()),
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let outcome = execute(cli(vault, runtime_command()), &mut input, &mut output)?;
        assert!(matches!(outcome, ExecutionOutcome::Child(status) if status.success()));

        let output = String::from_utf8(output)?;
        assert!(!output.contains(std::str::from_utf8(secret)?));
        Ok(())
    }

    #[test]
    fn configure_anchor_is_value_free_and_status_hides_the_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("anchor.vault.json");
        let token = directory.path().join("token.json");
        crate::vault::issue_anchor_token_file(&token)?;
        let token_bytes = fs::read_to_string(&token)?;
        let password = b"anchor-cli-test-password";
        let mut input = FixedSensitiveInput::repeated(password, 2);
        let mut output = Vec::new();
        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        output.clear();
        execute(
            cli(
                vault.clone(),
                Command::Audit {
                    command: AuditCommand::ConfigureAnchor {
                        endpoint: "http://127.0.0.1:7432".to_owned(),
                        token_file: token.clone(),
                        tls_ca: None,
                        allow_plaintext: true,
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let rendered = String::from_utf8(output.clone())?;
        assert!(rendered.contains("mode: mandatory"));
        assert!(rendered.contains("http://127.0.0.1:7432"));
        assert!(!rendered.contains(&token_bytes));
        output.clear();
        execute(
            cli(
                vault,
                Command::Audit {
                    command: AuditCommand::AnchorStatus,
                },
            ),
            &mut input,
            &mut output,
        )?;
        let status = String::from_utf8(output)?;
        assert!(status.contains("configured: true"));
        assert!(status.contains("last_confirmed_generation: none"));
        assert!(status.contains("rollback_evidence: no"));
        assert!(!status.contains(&token_bytes));
        Ok(())
    }
}
