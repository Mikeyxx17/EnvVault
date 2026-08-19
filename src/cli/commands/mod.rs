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
    time::{SystemTime, UNIX_EPOCH},
};

use crate::cli::{
    application::CliApplication,
    args::{
        AuditCommand, Cli, Command, IdentityCommand, KeystoreCommand, OutputFormat, PolicyCommand,
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
    dotenv,
    identity::CallerId,
    process,
    secret::SecretName,
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
    if cli.target.is_some() && !command_accepts_as(&cli.command) {
        return Err(CliError::NamedTargetUnused);
    }
    let mut project = config::discover_from_cwd()?;
    if let Command::Completions { shell } = cli.command {
        write!(output, "{}", super::completions::render(shell))?;
        return Ok(ExecutionOutcome::Success);
    }
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

fn command_accepts_as(command: &Command) -> bool {
    matches!(
        command,
        Command::Identity {
            command: IdentityCommand::Register { .. },
        } | Command::Profile { .. }
            | Command::Policy {
                command: PolicyCommand::GrantUse { .. }
                    | PolicyCommand::GrantInspect { .. }
                    | PolicyCommand::RevokeUse { .. },
            }
            | Command::Example { .. }
            | Command::Run { .. }
            | Command::Session { .. }
    )
}

#[allow(clippy::too_many_lines)]
fn dispatch(
    cli: Cli,
    vault: &Path,
    mut project: Option<&mut Project>,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<ExecutionOutcome, CliError> {
    let as_target = cli.target.as_deref();
    let format = cli.format;
    match cli.command {
        Command::Init => execute_init(vault, cli.vault.is_none(), format, sensitive_input, output)?,
        Command::Set { name } => execute_set(vault, name, format, sensitive_input, output)?,
        Command::Verify { name } => execute_verify(vault, name, format, sensitive_input, output)?,
        Command::List { verbose } => {
            execute_list(vault, verbose, format, sensitive_input, output)?;
        }
        Command::Rename { current, new } => {
            execute_rename(vault, current, new, sensitive_input, output)?;
        }
        Command::ChangePassword => execute_change_password(vault, sensitive_input, output)?,
        Command::Exists { name } => execute_exists(vault, name, format, sensitive_input, output)?,
        Command::Remove { name } => execute_remove(vault, name, sensitive_input, output)?,
        Command::Import { source, dry_run } => {
            execute_import(vault, &source, dry_run, format, sensitive_input, output)?;
        }
        Command::Example {
            output: path,
            profile,
        } => {
            execute_example(
                vault,
                &path,
                profile,
                project.as_deref(),
                as_target,
                format,
                sensitive_input,
                output,
            )?;
        }
        Command::Identity { command } => {
            execute_identity(
                vault,
                command,
                project.as_deref_mut(),
                as_target,
                format,
                sensitive_input,
                output,
            )?;
        }
        Command::Profile { command } => {
            execute_profile(
                vault,
                command,
                project.as_deref_mut(),
                as_target,
                format,
                sensitive_input,
                output,
            )?;
        }
        Command::Policy { command } => {
            execute_policy(
                vault,
                command,
                project.as_deref(),
                as_target,
                format,
                sensitive_input,
                output,
            )?;
        }
        Command::Audit { command } => {
            execute_audit(vault, command, format, sensitive_input, output)?;
        }
        Command::Keystore { command } => {
            execute_keystore(vault, command, sensitive_input, output)?;
        }
        Command::Session {
            credential_file,
            machine_unlock,
            command,
        } => {
            let credential_file =
                resolve_credential(credential_file, project.as_deref(), as_target)?;
            execute_session(
                vault,
                &credential_file,
                machine_unlock,
                command,
                format,
                sensitive_input,
                output,
            )?;
        }
        Command::Run {
            profile,
            credential_file,
            machine_unlock,
            dry_run,
            command,
        } => {
            return execute_run_command(
                vault,
                project.as_deref(),
                as_target,
                profile,
                credential_file,
                machine_unlock,
                dry_run,
                format,
                &command,
                sensitive_input,
                output,
            );
        }
        Command::Completions { shell } => {
            write!(output, "{}", super::completions::render(shell))?;
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
    format: OutputFormat,
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
    write_next(output, format, &["envvault profile create NAME"])?;
    Ok(())
}

fn execute_list(
    vault: &Path,
    verbose: bool,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let records = application.list_secrets()?;
    let grants = if verbose {
        application.use_grant_labels()?
    } else {
        Vec::new()
    };
    if format == OutputFormat::Json {
        let secrets = records
            .iter()
            .map(|record| {
                if verbose {
                    let mut users = grants
                        .iter()
                        .filter(|(secret_id, _)| *secret_id == record.id())
                        .map(|(_, label)| serde_json::Value::String(label.clone()))
                        .collect::<Vec<_>>();
                    users.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
                    users.dedup();
                    serde_json::json!({
                        "name": record.name().as_str(),
                        "secret_id": record.id().to_string(),
                        "use": users,
                    })
                } else {
                    serde_json::json!({ "name": record.name().as_str() })
                }
            })
            .collect::<Vec<_>>();
        return write_json(output, &serde_json::json!({ "secrets": secrets }));
    }
    if !verbose {
        for record in records {
            writeln!(output, "{}", record.name())?;
        }
        return Ok(());
    }
    for record in records {
        let mut users = grants
            .iter()
            .filter(|(secret_id, _)| *secret_id == record.id())
            .map(|(_, label)| label.clone())
            .collect::<Vec<_>>();
        users.sort();
        users.dedup();
        let grants = if users.is_empty() {
            "-".to_owned()
        } else {
            users.join(",")
        };
        writeln!(output, "{}\t{}\tuse:{grants}", record.name(), record.id())?;
    }
    Ok(())
}

fn execute_rename(
    vault: &Path,
    current: String,
    new: String,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let current = SecretName::new(current)?;
    let new = SecretName::new(new)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let record = application.rename_secret(&current, new)?;
    writeln!(output, "Secret renamed")?;
    writeln!(output, "secret_id: {}", record.id())?;
    writeln!(output, "name: {}", record.name())?;
    Ok(())
}

fn execute_change_password(
    vault: &Path,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let current = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &current)?;
    let new_password = sensitive_input.read_new()?;
    application.change_password(&new_password)?;
    writeln!(output, "Master password changed")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_run_command(
    vault: &Path,
    project: Option<&Project>,
    as_target: Option<&str>,
    profile: Option<PathBuf>,
    credential_file: Option<PathBuf>,
    machine_unlock: bool,
    dry_run: bool,
    format: OutputFormat,
    command: &[OsString],
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<ExecutionOutcome, CliError> {
    let profile = resolve_profile(profile, project, as_target)?;
    let credential_file = resolve_credential(credential_file, project, as_target)?;
    if dry_run {
        execute_run_preview(
            vault,
            &profile,
            &credential_file,
            machine_unlock,
            format,
            sensitive_input,
            output,
        )?;
        return Ok(ExecutionOutcome::Success);
    }
    if command.is_empty() {
        return Err(CliError::RunCommandRequired);
    }
    execute_run(
        vault,
        &profile,
        &credential_file,
        command,
        machine_unlock,
        sensitive_input,
    )
    .map(ExecutionOutcome::Child)
}

fn execute_run_preview(
    vault: &Path,
    profile_path: &Path,
    credential_file: &Path,
    machine_unlock: bool,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let profile = read_profile(profile_path)?;
    let mut application =
        open_machine_caller(vault, credential_file, machine_unlock, sensitive_input)?;
    let previews = application.preview_profile_use(&profile)?;
    if format == OutputFormat::Json {
        let secrets = previews
            .iter()
            .map(|(environment, outcome)| {
                serde_json::json!({
                    "environment": environment,
                    "outcome": outcome.as_str(),
                })
            })
            .collect::<Vec<_>>();
        return write_json(
            output,
            &serde_json::json!({
                "dry_run": true,
                "executed": false,
                "secrets": secrets,
            }),
        );
    }
    writeln!(output, "dry_run: yes")?;
    writeln!(output, "executed: no")?;
    for (environment, outcome) in previews {
        writeln!(output, "{environment}\t{}", outcome.as_str())?;
    }
    Ok(())
}

fn execute_exists(
    vault: &Path,
    name: String,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let exists = application.secret_exists(&name)?;
    if format == OutputFormat::Json {
        return write_json(output, &serde_json::json!({ "exists": exists }));
    }
    writeln!(output, "{exists}")?;
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
    dry_run: bool,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let source_bytes = read_source(source)?;
    let entries = dotenv::parse(&source_bytes)?;
    drop(source_bytes);
    if dry_run {
        let names = entries
            .iter()
            .map(dotenv::DotenvEntry::name)
            .cloned()
            .collect::<Vec<_>>();
        drop(entries);
        let plan = application.plan_import(&names)?;
        let create = plan
            .iter()
            .filter(|item| item.action() == crate::broker::service::ImportPlanAction::Create)
            .count();
        let replace = plan
            .iter()
            .filter(|item| item.action() == crate::broker::service::ImportPlanAction::Replace)
            .count();
        let conflict = plan
            .iter()
            .filter(|item| item.action() == crate::broker::service::ImportPlanAction::Conflict)
            .count();
        if format == OutputFormat::Json {
            let entries = plan
                .iter()
                .map(|item| {
                    serde_json::json!({
                        "name": item.name().as_str(),
                        "action": item.action().as_str(),
                    })
                })
                .collect::<Vec<_>>();
            return write_json(
                output,
                &serde_json::json!({
                    "dry_run": true,
                    "committed": false,
                    "create": create,
                    "replace": replace,
                    "conflict": conflict,
                    "source_preserved": true,
                    "entries": entries,
                }),
            );
        }
        writeln!(output, "dry_run: yes")?;
        writeln!(output, "committed: no")?;
        writeln!(output, "create: {create}")?;
        writeln!(output, "replace: {replace}")?;
        writeln!(output, "conflict: {conflict}")?;
        writeln!(output, "source_preserved: yes")?;
        for item in plan {
            writeln!(output, "{}\t{}", item.name(), item.action().as_str())?;
        }
        return Ok(());
    }
    let imported = application.import_secrets(entries)?;
    writeln!(output, "Imported {} Secrets", imported.len())?;
    writeln!(output, "source_preserved: yes")?;
    write_next(output, format, &["envvault profile create NAME"])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_example(
    vault: &Path,
    path: &Path,
    profile: Option<PathBuf>,
    project: Option<&Project>,
    as_target: Option<&str>,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let names = example_names(&mut application, profile, project, as_target)?;
    let example = dotenv::render_example(names.iter())?;
    write_new(path, &example)?;
    writeln!(output, "Example generated")?;
    writeln!(output, "example_file_created: yes")?;
    write_next(output, format, &["envvault run -- ./app"])?;
    Ok(())
}

fn example_names(
    application: &mut CliApplication,
    profile: Option<PathBuf>,
    project: Option<&Project>,
    as_target: Option<&str>,
) -> Result<Vec<SecretName>, CliError> {
    if profile.is_none() && as_target.is_none() {
        return Ok(application
            .list_secrets()?
            .into_iter()
            .map(|record| record.name().clone())
            .collect());
    }
    let profile = read_profile(&resolve_profile(profile, project, as_target)?)?;
    let listed = application.list_secrets()?;
    let mut names = Vec::with_capacity(profile.bindings().len());
    for binding in profile.bindings() {
        if !listed
            .iter()
            .any(|record| record.id() == binding.secret_id())
        {
            return Err(CliError::SecretUnavailable);
        }
        names.push(SecretName::new(binding.environment().to_owned())?);
    }
    Ok(names)
}

fn execute_verify(
    vault: &Path,
    name: String,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let name = SecretName::new(name)?;
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let expected = sensitive_input.read_expected_secret_value()?;
    let matches = application.verify_secret(&name, &expected)?;
    let result = if matches { "match" } else { "mismatch" };
    if format == OutputFormat::Json {
        return write_json(output, &serde_json::json!({ "result": result }));
    }
    writeln!(output, "{result}")?;
    Ok(())
}

fn execute_init(
    vault: &Path,
    write_project_file: bool,
    format: OutputFormat,
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
        write_init_project_files(&project, output)?;
    }
    write_next(
        output,
        format,
        &["envvault import --dry-run .env", "envvault set NAME"],
    )?;
    Ok(())
}

fn write_init_project_files(project: &Project, output: &mut dyn Write) -> Result<(), CliError> {
    match config::write_new(project) {
        Ok(()) => {
            writeln!(output, "project_file: {}", project.file_path().display())?;
        }
        Err(config::ProjectError::AlreadyExists) => {}
        Err(error) => return Err(error.into()),
    }
    match config::ensure_gitignore(project.root())? {
        config::GitignoreStatus::Created => writeln!(output, "gitignore: created")?,
        config::GitignoreStatus::Updated => writeln!(output, "gitignore: updated")?,
        config::GitignoreStatus::Unchanged => writeln!(output, "gitignore: unchanged")?,
    }
    Ok(())
}

fn execute_policy(
    vault: &Path,
    command: PolicyCommand,
    project: Option<&Project>,
    as_target: Option<&str>,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        PolicyCommand::List => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let (generation, listings) = application.list_policy_rules()?;
            if format == OutputFormat::Json {
                let rules = listings
                    .iter()
                    .map(|listing| {
                        serde_json::json!({
                            "caller_id": listing.caller().id().to_string(),
                            "caller_kind": listing.caller().kind().to_string(),
                            "caller_name": listing
                                .caller_name()
                                .map_or("-", crate::identity::CallerName::as_str),
                            "secret": listing.secret_name().map_or_else(
                                || listing.secret_id().to_string(),
                                ToString::to_string,
                            ),
                            "operation": listing.operation().as_str(),
                            "effect": listing.effect().as_str(),
                        })
                    })
                    .collect::<Vec<_>>();
                write_json(
                    output,
                    &serde_json::json!({
                        "policy_generation": generation,
                        "rules": rules,
                    }),
                )?;
                return Ok(());
            }
            writeln!(output, "policy_generation: {generation}")?;
            for listing in listings {
                let caller_name = listing
                    .caller_name()
                    .map_or("-", crate::identity::CallerName::as_str);
                let secret = listing
                    .secret_name()
                    .map_or_else(|| listing.secret_id().to_string(), ToString::to_string);
                writeln!(
                    output,
                    "{}\t{}\t{}\t{secret}\t{}\t{}",
                    listing.caller().id(),
                    listing.caller().kind(),
                    caller_name,
                    listing.operation(),
                    listing.effect().as_str(),
                )?;
            }
        }
        PolicyCommand::GrantUse { caller_id, profile } => {
            let caller_id = resolve_policy_caller(caller_id, project, as_target)?;
            let profile = read_profile(&resolve_profile(profile, project, as_target)?)?;
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let generation = application.grant_profile_use(caller_id, &profile)?;
            writeln!(output, "Profile use granted")?;
            writeln!(output, "bindings: {}", profile.bindings().len())?;
            writeln!(output, "policy_generation: {generation}")?;
            write_next(output, format, &["envvault run -- ./app"])?;
        }
        PolicyCommand::GrantInspect { caller_id, profile } => {
            let caller_id = resolve_policy_caller(caller_id, project, as_target)?;
            let profile = read_profile(&resolve_profile(profile, project, as_target)?)?;
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let generation = application.grant_profile_inspect(caller_id, &profile)?;
            writeln!(output, "Profile inspect granted")?;
            writeln!(output, "bindings: {}", profile.bindings().len())?;
            writeln!(output, "policy_generation: {generation}")?;
            write_next(output, format, &["envvault run --dry-run"])?;
        }
        PolicyCommand::RevokeUse {
            caller_id,
            profile,
            secrets,
        } => {
            let caller_id = resolve_policy_caller(caller_id, project, as_target)?;
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let secret_ids =
                resolve_revoke_secret_ids(&mut application, project, as_target, profile, secrets)?;
            let generation = application.revoke_use(caller_id, &secret_ids)?;
            writeln!(output, "Use grants revoked")?;
            writeln!(output, "secrets: {}", secret_ids.len())?;
            writeln!(output, "policy_generation: {generation}")?;
        }
    }
    Ok(())
}

fn resolve_policy_caller(
    caller_id: Option<CallerId>,
    project: Option<&Project>,
    as_target: Option<&str>,
) -> Result<CallerId, CliError> {
    if let Some(caller_id) = caller_id {
        return Ok(caller_id);
    }
    if let Some(name) = as_target {
        return require_target(project, name)?
            .caller_id()
            .ok_or(CliError::ProjectTargetIncomplete);
    }
    project
        .and_then(Project::caller_id)
        .ok_or(CliError::ProjectDefaultMissing)
}

fn resolve_revoke_secret_ids(
    application: &mut CliApplication,
    project: Option<&Project>,
    as_target: Option<&str>,
    profile: Option<PathBuf>,
    secrets: Vec<String>,
) -> Result<Vec<crate::secret::SecretId>, CliError> {
    if secrets.is_empty() {
        let profile = read_profile(&resolve_profile(profile, project, as_target)?)?;
        return Ok(profile
            .bindings()
            .iter()
            .map(crate::profile::ProfileBinding::secret_id)
            .collect());
    }
    let mut names = Vec::with_capacity(secrets.len());
    for name in secrets {
        names.push(SecretName::new(name)?);
    }
    application.secret_ids_for_names(names)
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

fn execute_audit_list(
    vault: &Path,
    caller_id: Option<CallerId>,
    secret: Option<String>,
    operation: Option<String>,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let password = sensitive_input.read_existing()?;
    let mut application = CliApplication::open_owner(vault, &password)?;
    let secret_id = match secret {
        Some(name) => {
            let name = SecretName::new(name)?;
            Some(
                application
                    .list_secrets()?
                    .into_iter()
                    .find(|record| record.name() == &name)
                    .ok_or(CliError::SecretUnavailable)?
                    .id(),
            )
        }
        None => None,
    };
    let operation = match operation {
        Some(code) => Some(
            code.parse::<crate::policy::Operation>()
                .map_err(|_| CliError::InvalidAuditFilter)?,
        ),
        None => None,
    };
    let mut events = Vec::new();
    for event in application.audit_events()? {
        if caller_id.is_some_and(|id| event.caller().id() != id) {
            continue;
        }
        if secret_id.is_some_and(|id| event.secret_id() != Some(id)) {
            continue;
        }
        if operation.is_some_and(|value| event.operation() != Some(value)) {
            continue;
        }
        events.push(event);
    }
    if format == OutputFormat::Json {
        let events = events
            .into_iter()
            .map(|event| {
                serde_json::json!({
                    "unix_time_millis": event.unix_time_millis(),
                    "caller_kind": event.caller().kind().to_string(),
                    "caller_id": event.caller().id().to_string(),
                    "authentication_method": event.authentication_method().as_str(),
                    "target": audit_target(&event),
                    "decision": audit_decision(&event),
                })
            })
            .collect::<Vec<_>>();
        write_json(output, &serde_json::json!({ "events": events }))
    } else {
        for event in events {
            write_audit_event(output, event)?;
        }
        Ok(())
    }
}

fn execute_audit(
    vault: &Path,
    command: AuditCommand,
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match command {
        AuditCommand::List {
            caller_id,
            secret,
            operation,
        } => {
            execute_audit_list(
                vault,
                caller_id,
                secret,
                operation,
                format,
                sensitive_input,
                output,
            )?;
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

fn write_json(output: &mut dyn Write, value: &serde_json::Value) -> Result<(), CliError> {
    let encoded = serde_json::to_string(value).map_err(|_| CliError::OutputUnavailable)?;
    writeln!(output, "{encoded}")?;
    Ok(())
}

fn write_next(
    output: &mut dyn Write,
    format: OutputFormat,
    steps: &[&str],
) -> Result<(), CliError> {
    if format != OutputFormat::Text {
        return Ok(());
    }
    for step in steps {
        writeln!(output, "next: {step}")?;
    }
    Ok(())
}

fn audit_target(event: &crate::audit::AuditEvent) -> String {
    event.secret_id().map_or_else(
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
    )
}

fn audit_decision(event: &crate::audit::AuditEvent) -> String {
    match event.decision() {
        crate::policy::PolicyDecision::Allow => "allow".to_owned(),
        crate::policy::PolicyDecision::Deny(reason) => {
            let code = match reason {
                crate::policy::DenyReason::DefaultDeny => "default_deny",
                crate::policy::DenyReason::NoMatchingGrant => "no_matching_grant",
                crate::policy::DenyReason::ExplicitDeny => "explicit_deny",
                crate::policy::DenyReason::InvalidRequest => "invalid_request",
            };
            format!("deny:{code}")
        }
    }
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

const EXPIRING_SOON_MILLIS: u64 = 14 * 24 * 60 * 60 * 1_000;

fn credential_expiry_status(expires: Option<u64>) -> (String, &'static str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    match expires {
        None => ("legacy-unbounded".to_owned(), "unbounded"),
        Some(expiry) if now >= expiry => (expiry.to_string(), "expired"),
        Some(expiry) if expiry.saturating_sub(now) <= EXPIRING_SOON_MILLIS => {
            (expiry.to_string(), "expiring")
        }
        Some(expiry) => (expiry.to_string(), "ok"),
    }
}

fn write_audit_event(
    output: &mut dyn Write,
    event: crate::audit::AuditEvent,
) -> Result<(), CliError> {
    writeln!(
        output,
        "{}\t{}:{}\t{}\t{}\t{:?}",
        event.unix_time_millis(),
        event.caller().kind(),
        event.caller().id(),
        event.authentication_method().as_str(),
        audit_target(&event),
        event.decision()
    )?;
    Ok(())
}

fn execute_profile(
    vault: &Path,
    command: ProfileCommand,
    project: Option<&mut Project>,
    as_target: Option<&str>,
    format: OutputFormat,
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
            let path = resolve_profile_output(path, project.as_deref(), as_target)?;
            if let Some(parent) = path.parent() {
                config::ensure_vault_dir(parent)?;
            }
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let profile = application.create_profile(names)?;
            write_new_profile(&path, &profile)?;
            if let Some(name) = as_target {
                let Some(project) = project else {
                    return Err(CliError::NamedTargetRequiresProject);
                };
                project.set_named_profile(name, &path)?;
            } else if let Some(project) = project {
                project.set_default_profile(&path)?;
            }
            writeln!(output, "Profile created")?;
            writeln!(output, "bindings: {}", profile.bindings().len())?;
            writeln!(output, "profile_file_created: yes")?;
            write_next(output, format, &["envvault policy grant-use"])?;
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
    format: OutputFormat,
    sensitive_input: &mut dyn SensitiveInput,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let application = open_machine_caller(vault, credential_file, machine_unlock, sensitive_input)?;
    match command {
        SessionCommand::Whoami => {
            let caller = application.authenticated_caller();
            if format == OutputFormat::Json {
                write_json(
                    output,
                    &serde_json::json!({
                        "caller_id": caller.id().to_string(),
                        "caller_kind": caller.kind().to_string(),
                        "authentication_method": application.authentication_method().as_str(),
                    }),
                )?;
            } else {
                writeln!(output, "caller_id: {}", caller.id())?;
                writeln!(output, "caller_kind: {}", caller.kind())?;
                writeln!(
                    output,
                    "authentication_method: {}",
                    application.authentication_method().as_str()
                )?;
            }
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
    as_target: Option<&str>,
    format: OutputFormat,
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
                None if as_target.is_some() => {
                    default_named_file(project.as_deref(), as_target, "credential.json")?
                }
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
            if let Some(name) = as_target {
                let Some(project) = project.as_mut() else {
                    return Err(CliError::NamedTargetRequiresProject);
                };
                project.set_named_caller(name, issued.caller().id(), &credential_file)?;
            } else if let Some(project) = project.as_mut() {
                project.set_default_caller(issued.caller().id(), &credential_file)?;
            }
            writeln!(output, "Caller registered")?;
            writeln!(output, "caller_id: {}", issued.caller().id())?;
            writeln!(output, "caller_kind: {}", issued.caller().kind())?;
            writeln!(output, "credential_file_created: yes")?;
            write_next(output, format, &["envvault profile create SECRET"])?;
        }
        IdentityCommand::List => {
            let password = sensitive_input.read_existing()?;
            let mut application = CliApplication::open_owner(vault, &password)?;
            let callers = application.registered_callers()?;
            if format == OutputFormat::Json {
                let callers = callers
                    .iter()
                    .map(|registered| {
                        let (expiry, status) = credential_expiry_status(
                            registered.credential_expires_unix_time_millis(),
                        );
                        serde_json::json!({
                            "caller_id": registered.caller().id().to_string(),
                            "caller_kind": registered.caller().kind().to_string(),
                            "name": registered.name().as_str(),
                            "expires": expiry,
                            "status": status,
                        })
                    })
                    .collect::<Vec<_>>();
                write_json(output, &serde_json::json!({ "callers": callers }))?;
            } else {
                for registered in callers {
                    let (expiry, status) =
                        credential_expiry_status(registered.credential_expires_unix_time_millis());
                    writeln!(
                        output,
                        "{}\t{}\t{}\t{expiry}\t{status}",
                        registered.caller().id(),
                        registered.caller().kind(),
                        registered.name().as_str(),
                    )?;
                }
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
    as_target: Option<&str>,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(name) = as_target {
        return require_target(project, name)?
            .profile()
            .map(Path::to_path_buf)
            .ok_or(CliError::ProjectTargetIncomplete);
    }
    project
        .map(|value| value.profile().to_path_buf())
        .ok_or(CliError::ProjectDefaultMissing)
}

fn resolve_profile_output(
    explicit: Option<PathBuf>,
    project: Option<&Project>,
    as_target: Option<&str>,
) -> Result<PathBuf, CliError> {
    if explicit.is_some() {
        return resolve_profile(explicit, project, None);
    }
    if as_target.is_some() {
        return default_named_file(project, as_target, "profile.json");
    }
    resolve_profile(None, project, None)
}

fn resolve_credential(
    explicit: Option<PathBuf>,
    project: Option<&Project>,
    as_target: Option<&str>,
) -> Result<PathBuf, CliError> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(name) = as_target {
        return require_target(project, name)?
            .credential_file()
            .map(Path::to_path_buf)
            .ok_or(CliError::ProjectTargetIncomplete);
    }
    project
        .map(|value| value.credential_file().to_path_buf())
        .ok_or(CliError::ProjectDefaultMissing)
}

fn require_target<'a>(
    project: Option<&'a Project>,
    name: &str,
) -> Result<&'a crate::config::ProjectTarget, CliError> {
    validate_as_name(name)?;
    let project = project.ok_or(CliError::NamedTargetRequiresProject)?;
    project.target(name).ok_or(CliError::UnknownProjectTarget)
}

fn validate_as_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CliError::InvalidTargetName);
    }
    Ok(())
}

fn default_named_file(
    project: Option<&Project>,
    as_target: Option<&str>,
    suffix: &str,
) -> Result<PathBuf, CliError> {
    let name = as_target.ok_or(CliError::InvalidTargetName)?;
    validate_as_name(name)?;
    let root = project
        .map(Project::root)
        .ok_or(CliError::NamedTargetRequiresProject)?;
    Ok(root.join(".envvault").join(format!("{name}.{suffix}")))
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
                AuditCommand, CallerKindArg, Cli, Command, CompletionShell, IdentityCommand,
                OutputFormat, PolicyCommand, ProfileCommand, SessionCommand,
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

        fn then_password(mut self, value: &[u8]) -> Self {
            self.passwords.push_back(value.to_vec());
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
            target: None,
            format: OutputFormat::Text,
            command,
        }
    }

    #[test]
    fn as_is_rejected_on_owner_list() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("as-unused.vault.json");
        let mut input = FixedSensitiveInput::repeated(b"unused-as-password", 1);
        let mut output = Vec::new();
        let mut command = cli(vault, Command::List { verbose: false });
        command.target = Some("backend".to_owned());
        assert!(matches!(
            execute(command, &mut input, &mut output),
            Err(CliError::NamedTargetUnused)
        ));
        Ok(())
    }

    #[test]
    fn named_target_resolution_does_not_use_the_default_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let mut project = crate::config::default_layout(root.path());
        crate::config::write_new(&project)?;
        let default_id = CallerId::from_bytes([0x11; 16]);
        let named_id = CallerId::from_bytes([0x22; 16]);
        project.set_default_caller(
            default_id,
            &root.path().join(".envvault/app.credential.json"),
        )?;
        project.set_named_caller(
            "backend",
            named_id,
            &root.path().join(".envvault/backend.credential.json"),
        )?;
        project.set_named_profile(
            "backend",
            &root.path().join(".envvault/backend.profile.json"),
        )?;

        assert_eq!(
            super::resolve_policy_caller(None, Some(&project), None)?,
            default_id
        );
        assert_eq!(
            super::resolve_policy_caller(None, Some(&project), Some("backend"))?,
            named_id
        );
        assert!(
            super::resolve_profile(None, Some(&project), Some("backend"))?
                .ends_with("backend.profile.json")
        );
        assert!(matches!(
            super::resolve_credential(None, Some(&project), Some("agent")),
            Err(CliError::UnknownProjectTarget)
        ));
        Ok(())
    }

    #[test]
    fn completions_are_value_free_and_do_not_need_a_vault() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut input = FixedSensitiveInput::repeated(b"unused", 0);
        let mut output = Vec::new();
        execute(
            Cli {
                vault: None,
                masked_input: false,
                target: None,
                format: OutputFormat::Text,
                command: Command::Completions {
                    shell: CompletionShell::Bash,
                },
            },
            &mut input,
            &mut output,
        )?;
        let script = String::from_utf8(output)?;
        assert!(script.contains("complete -F _envvault envvault"));
        assert!(script.contains("change-password"));
        Ok(())
    }

    #[test]
    fn verbose_list_prints_id_without_values() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("verbose.vault.json");
        let password = b"verbose-cli-test-password";
        let secret = b"verbose-cli-secret-value";
        let mut input = FixedSensitiveInput::repeated(password, 3).with_secret_values(&[secret]);
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
            cli(vault, Command::List { verbose: true }),
            &mut input,
            &mut output,
        )?;
        let listed = String::from_utf8(output)?;
        assert!(listed.contains("API_TOKEN"));
        assert!(listed.contains("use:"));
        assert!(!listed.contains(std::str::from_utf8(secret)?));
        Ok(())
    }

    #[test]
    fn list_json_is_value_free() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("json.vault.json");
        let password = b"json-cli-test-password";
        let secret = b"json-cli-secret-value";
        let mut input = FixedSensitiveInput::repeated(password, 3).with_secret_values(&[secret]);
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
        let mut command = cli(vault, Command::List { verbose: false });
        command.format = OutputFormat::Json;
        execute(command, &mut input, &mut output)?;
        let listed = String::from_utf8(output)?;
        assert!(listed.contains("\"secrets\""));
        assert!(listed.contains("API_TOKEN"));
        assert!(!listed.contains(std::str::from_utf8(secret)?));
        Ok(())
    }

    #[test]
    fn rename_then_plain_list_is_value_free() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("rename.vault.json");
        let password = b"rename-cli-test-password";
        let secret = b"rename-cli-secret-value";
        let mut input = FixedSensitiveInput::repeated(password, 4).with_secret_values(&[secret]);
        let mut output = Vec::new();
        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "OLD_NAME".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Rename {
                    current: "OLD_NAME".to_owned(),
                    new: "NEW_NAME".to_owned(),
                },
            ),
            &mut input,
            &mut output,
        )?;
        output.clear();
        execute(
            cli(vault, Command::List { verbose: false }),
            &mut input,
            &mut output,
        )?;
        let listed = String::from_utf8(output)?;
        assert!(listed.contains("NEW_NAME"));
        assert!(!listed.contains("OLD_NAME"));
        assert!(!listed.contains(std::str::from_utf8(secret)?));
        Ok(())
    }

    #[test]
    fn change_password_cli_accepts_the_new_password() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("pw.vault.json");
        let password = b"change-cli-old-password";
        let next_password = b"change-cli-new-password";
        let mut input = FixedSensitiveInput::repeated(password, 2).then_password(next_password);
        let mut output = Vec::new();
        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        execute(
            cli(vault.clone(), Command::ChangePassword),
            &mut input,
            &mut output,
        )?;
        let mut next = FixedSensitiveInput::repeated(next_password, 1);
        output = Vec::new();
        execute(
            cli(vault, Command::List { verbose: false }),
            &mut next,
            &mut output,
        )?;
        assert!(output.is_empty() || String::from_utf8(output).is_ok());
        Ok(())
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
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[2], "test-app");
        assert_ne!(fields[3], "legacy-unbounded");
        let _expires_unix_time_millis = fields[3].parse::<u64>()?;
        assert!(matches!(fields[4], "ok" | "expiring"));

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
                    command: AuditCommand::List {
                        caller_id: None,
                        secret: None,
                        operation: None,
                    },
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
        execute(
            cli(vault.clone(), Command::List { verbose: false }),
            &mut input,
            &mut output,
        )?;
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
        let mut input = FixedSensitiveInput::repeated(password, 4);
        let mut output = Vec::new();

        execute(cli(vault.clone(), Command::Init), &mut input, &mut output)?;
        output.clear();
        execute(
            cli(
                vault.clone(),
                Command::Import {
                    source: source.clone(),
                    dry_run: true,
                },
            ),
            &mut input,
            &mut output,
        )?;
        let preview = String::from_utf8(output.clone())?;
        assert!(preview.contains("dry_run: yes"));
        assert!(preview.contains("committed: no"));
        assert!(preview.contains("create: 2"));
        assert!(preview.contains("DATABASE_URL\tcreate"));
        assert!(!preview.contains(std::str::from_utf8(database)?));
        execute(
            cli(
                vault.clone(),
                Command::Import {
                    source: source.clone(),
                    dry_run: false,
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
                    profile: None,
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
    fn init_project_files_write_gitignore_without_secrets() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let project = crate::config::default_layout(directory.path());
        let mut output = Vec::new();
        super::write_init_project_files(&project, &mut output)?;
        let rendered = String::from_utf8(output)?;
        assert!(rendered.contains("project_file:"));
        assert!(rendered.contains("gitignore: created"));
        let gitignore = fs::read_to_string(directory.path().join(".gitignore"))?;
        assert!(gitignore.contains(".envvault/"));
        assert!(gitignore.contains("*.credential.json"));
        let mut second = Vec::new();
        super::write_init_project_files(&project, &mut second)?;
        assert!(String::from_utf8(second)?.contains("gitignore: unchanged"));
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
                cli(
                    vault.clone(),
                    Command::Import {
                        source,
                        dry_run: false,
                    },
                ),
                &mut input,
                &mut output,
            )
            .is_err()
        );
        output.clear();
        execute(
            cli(vault, Command::List { verbose: false }),
            &mut input,
            &mut output,
        )?;
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
                    command: AuditCommand::List {
                        caller_id: None,
                        secret: None,
                        operation: None,
                    },
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
            dry_run: false,
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

    struct PolicyCliFixture {
        vault: PathBuf,
        agent_credential: PathBuf,
        profile_file: PathBuf,
        app_id: CallerId,
        agent_id: CallerId,
    }

    fn caller_id_from_credential(path: &PathBuf) -> Result<CallerId, Box<dyn std::error::Error>> {
        Ok(CallerId::from_str(
            serde_json::from_slice::<Value>(&fs::read(path)?)?["caller_id"]
                .as_str()
                .ok_or("missing caller id")?,
        )?)
    }

    fn prepare_policy_cli_fixture(
        directory: &std::path::Path,
        input: &mut FixedSensitiveInput,
        output: &mut Vec<u8>,
    ) -> Result<PolicyCliFixture, Box<dyn std::error::Error>> {
        let vault = directory.join("policy.vault.json");
        let app_credential = directory.join("backend.credential.json");
        let agent_credential = directory.join("agent.credential.json");
        let profile_file = directory.join("shared.profile.json");
        execute(cli(vault.clone(), Command::Init), input, output)?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "DATABASE_URL".to_owned(),
                },
            ),
            input,
            output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Set {
                    name: "OPENAI_API_KEY".to_owned(),
                },
            ),
            input,
            output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Register {
                        kind: CallerKindArg::Application,
                        name: "policy-backend".to_owned(),
                        credential_file: Some(app_credential.clone()),
                    },
                },
            ),
            input,
            output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Identity {
                    command: IdentityCommand::Register {
                        kind: CallerKindArg::AiAgent,
                        name: "policy-agent".to_owned(),
                        credential_file: Some(agent_credential.clone()),
                    },
                },
            ),
            input,
            output,
        )?;
        execute(
            cli(
                vault.clone(),
                Command::Profile {
                    command: ProfileCommand::Create {
                        output: Some(profile_file.clone()),
                        secrets: vec!["DATABASE_URL".to_owned(), "OPENAI_API_KEY".to_owned()],
                    },
                },
            ),
            input,
            output,
        )?;
        Ok(PolicyCliFixture {
            app_id: caller_id_from_credential(&app_credential)?,
            agent_id: caller_id_from_credential(&agent_credential)?,
            vault,
            agent_credential,
            profile_file,
        })
    }

    fn policy_list_output(
        vault: PathBuf,
        input: &mut FixedSensitiveInput,
        output: &mut Vec<u8>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        output.clear();
        execute(
            cli(
                vault,
                Command::Policy {
                    command: PolicyCommand::List,
                },
            ),
            input,
            output,
        )?;
        Ok(String::from_utf8(output.clone())?)
    }

    #[test]
    fn policy_list_inspect_and_revoke_use_are_exact_and_value_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let first_secret = b"first-policy-cli-secret";
        let second_secret = b"second-policy-cli-secret";
        let mut input = FixedSensitiveInput::repeated(b"policy-cli-test-password", 12)
            .with_secret_values(&[first_secret, second_secret]);
        let mut output = Vec::new();
        let fixture = prepare_policy_cli_fixture(directory.path(), &mut input, &mut output)?;

        execute(
            cli(
                fixture.vault.clone(),
                Command::Policy {
                    command: PolicyCommand::GrantUse {
                        caller_id: Some(fixture.app_id),
                        profile: Some(fixture.profile_file.clone()),
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        execute(
            cli(
                fixture.vault.clone(),
                Command::Policy {
                    command: PolicyCommand::GrantInspect {
                        caller_id: Some(fixture.agent_id),
                        profile: Some(fixture.profile_file.clone()),
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let listed = policy_list_output(fixture.vault.clone(), &mut input, &mut output)?;
        assert!(listed.contains("policy-backend") && listed.contains("policy-agent"));
        assert!(listed.contains("\tuse\tallow") && listed.contains("\tlist\tallow"));
        assert!(!listed.contains(std::str::from_utf8(first_secret)?));

        assert!(
            execute(
                cli(
                    fixture.vault.clone(),
                    Command::Run {
                        profile: Some(fixture.profile_file),
                        credential_file: Some(fixture.agent_credential),
                        machine_unlock: false,
                        dry_run: false,
                        command: vec![OsString::from("true")],
                    },
                ),
                &mut input,
                &mut output,
            )
            .is_err()
        );
        execute(
            cli(
                fixture.vault.clone(),
                Command::Policy {
                    command: PolicyCommand::RevokeUse {
                        caller_id: Some(fixture.app_id),
                        profile: None,
                        secrets: vec!["OPENAI_API_KEY".to_owned()],
                    },
                },
            ),
            &mut input,
            &mut output,
        )?;
        let after_revoke = policy_list_output(fixture.vault, &mut input, &mut output)?;
        assert!(!after_revoke.lines().any(|line| {
            line.contains(&fixture.app_id.to_string())
                && line.contains("OPENAI_API_KEY")
                && line.contains("\tuse\tallow")
        }));
        assert!(after_revoke.lines().any(|line| {
            line.contains(&fixture.app_id.to_string())
                && line.contains("DATABASE_URL")
                && line.contains("\tuse\tallow")
        }));
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
