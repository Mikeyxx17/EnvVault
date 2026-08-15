use std::{ffi::OsString, path::PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use crate::identity::{CallerId, CallerKind};

#[derive(Debug, Parser)]
#[command(name = "envvault", version, about)]
pub(super) struct Cli {
    /// Encrypted Vault file. Defaults to `vault` in `envvault.json`.
    #[arg(long, global = true, value_name = "PATH")]
    pub(super) vault: Option<PathBuf>,

    /// Show one `*` per typed sensitive character; this reveals input length.
    #[arg(long, global = true)]
    pub(super) masked_input: bool,

    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Initialize a new Vault and its Owner identity.
    Init,
    /// Create or replace one Secret without placing its value in argv.
    Set {
        /// Secret name; the value is read separately from the terminal.
        name: String,
    },
    /// Compare an expected value without revealing the stored Secret.
    Verify {
        /// Secret name to verify.
        name: String,
    },
    /// List only the Secret names authorized for the Owner.
    List,
    /// Check an authorized Secret name without revealing its value.
    Exists {
        /// Secret name to check.
        name: String,
    },
    /// Delete one explicitly authorized Secret.
    Remove {
        /// Secret name to remove.
        name: String,
    },
    /// Import a strict dotenv file as independently managed Secrets.
    Import {
        /// Existing dotenv source; it is never modified or deleted.
        source: PathBuf,
    },
    /// Generate a new value-free dotenv example from authorized names.
    Example {
        /// New output file; an existing path is never overwritten.
        #[arg(long, default_value = ".env.example", value_name = "PATH")]
        output: PathBuf,
    },
    /// Manage authenticated application and AI-agent identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Create value-free runtime request Profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Manage exact runtime-use grants as the Vault Owner.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Inspect or explicitly migrate the authenticated Audit backend.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Manage operating-system-keystore-backed machine unlock.
    Keystore {
        #[command(subcommand)]
        command: KeystoreCommand,
    },
    /// Open an authenticated, value-free machine identity session.
    Session {
        /// Registered Application or AI Agent credential file.
        #[arg(long, value_name = "PATH")]
        credential_file: Option<PathBuf>,
        /// Unlock through the OS credential store without a Master Password prompt.
        #[arg(long)]
        machine_unlock: bool,
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Inject an authorized Profile into one child process.
    Run {
        /// Strict value-free Profile file.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
        /// Registered Application or AI Agent credential file.
        #[arg(long, value_name = "PATH")]
        credential_file: Option<PathBuf>,
        /// Unlock through the OS credential store without a Master Password prompt.
        #[arg(long)]
        machine_unlock: bool,
        /// Exact program and arguments following `--`; no shell is introduced.
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Remove the installed `envvault` binary. Vaults are kept unless `--purge-project`.
    Uninstall {
        /// Also delete this project's `.envvault/` directory and `envvault.json`.
        #[arg(long)]
        purge_project: bool,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(super) enum SessionCommand {
    /// Print only the verified caller identity and authentication method.
    Whoami,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(super) enum KeystoreCommand {
    /// Enable machine unlock after interactive Owner authentication.
    Enable,
    /// Verify and display value-free machine-unlock state.
    Status,
    /// Rotate the platform wrapping credential without changing the Master Key.
    Rotate,
    /// Disable machine unlock and remove platform credential entries.
    Disable,
}

#[derive(Debug, Clone, Copy, Subcommand)]
pub(super) enum AuditCommand {
    /// List value-free Audit events after exact Owner authorization.
    List,
    /// Explicitly migrate a legacy Vault Audit chain to the V2 sidecar backend.
    MigrateV2,
}

#[derive(Debug, Subcommand)]
pub(super) enum IdentityCommand {
    /// Register a caller and write its one-time credential to a new file.
    Register {
        /// Caller category; Human identities cannot be registered here.
        #[arg(long, value_enum)]
        kind: CallerKindArg,
        /// Unique management label (not used for policy matching).
        #[arg(long)]
        name: String,
        /// New credential file; defaults to `.envvault/<name>.credential.json`.
        #[arg(long, value_name = "PATH")]
        credential_file: Option<PathBuf>,
    },
    /// List registered non-Human callers without credential material.
    List,
    /// Revoke a registered caller credential.
    Revoke {
        /// Stable caller identifier to revoke.
        #[arg(long)]
        caller_id: CallerId,
    },
    /// Replace one caller credential while preserving its stable `CallerId`.
    Rotate {
        /// Stable caller identifier whose credential will be replaced.
        #[arg(long)]
        caller_id: CallerId,
        /// New credential file; an existing path is never overwritten.
        #[arg(long, value_name = "PATH")]
        credential_file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum ProfileCommand {
    /// Resolve authorized Secret names and write a new value-free Profile.
    Create {
        /// New Profile file; defaults to the path in `envvault.json`.
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Secret names, also used as the child environment keys.
        #[arg(required = true, num_args = 1..)]
        secrets: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum PolicyCommand {
    /// Grant exact `use` permission for every `SecretId` in a Profile.
    GrantUse {
        /// Registered Application or AI Agent caller receiving the grants.
        #[arg(long)]
        caller_id: Option<CallerId>,
        /// Strict value-free Profile whose exact `SecretIds` are granted.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum CallerKindArg {
    Application,
    AiAgent,
}

impl From<CallerKindArg> for CallerKind {
    fn from(value: CallerKindArg) -> Self {
        match value {
            CallerKindArg::Application => Self::Application,
            CallerKindArg::AiAgent => Self::AiAgent,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, Command, IdentityCommand, SessionCommand};

    #[test]
    fn parses_identity_registration_without_secret_arguments() {
        let cli = Cli::try_parse_from([
            "envvault",
            "--vault",
            "test.vault",
            "identity",
            "register",
            "--kind",
            "ai-agent",
            "--name",
            "test-agent",
            "--credential-file",
            "agent.credential.json",
        ]);

        assert!(matches!(
            cli.map(|value| value.command),
            Ok(Command::Identity {
                command: IdentityCommand::Register { .. }
            })
        ));
    }

    #[test]
    fn rejects_password_command_line_options() {
        assert!(
            Cli::try_parse_from([
                "envvault",
                "--vault",
                "test.vault",
                "--password",
                "must-not-be-accepted",
                "init",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_secret_value_command_line_options() {
        assert!(
            Cli::try_parse_from([
                "envvault",
                "--vault",
                "test.vault",
                "set",
                "API_TOKEN",
                "--value",
                "must-not-be-accepted",
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_optional_masked_input_and_value_free_verify() {
        let cli = Cli::try_parse_from([
            "envvault",
            "--masked-input",
            "--vault",
            "test.vault",
            "verify",
            "API_TOKEN",
        ]);

        assert!(matches!(
            cli,
            Ok(Cli {
                masked_input: true,
                command: Command::Verify { name },
                ..
            }) if name == "API_TOKEN"
        ));
    }

    #[test]
    fn parses_run_command_only_after_separator() {
        let cli = Cli::try_parse_from([
            "envvault",
            "--vault",
            "test.vault",
            "run",
            "--profile",
            "backend.profile.json",
            "--credential-file",
            "backend.credential.json",
            "--",
            "cargo",
            "run",
            "--release",
        ]);

        assert!(matches!(
            cli.map(|value| value.command),
            Ok(Command::Run { command, .. }) if command.len() == 3
        ));
    }

    #[test]
    fn parses_explicit_machine_unlock_without_accepting_key_material() {
        let cli = Cli::try_parse_from([
            "envvault",
            "--vault",
            "test.vault",
            "run",
            "--profile",
            "backend.profile.json",
            "--credential-file",
            "backend.credential.json",
            "--machine-unlock",
            "--",
            "cargo",
            "run",
        ]);

        assert!(matches!(
            cli.map(|value| value.command),
            Ok(Command::Run {
                machine_unlock: true,
                ..
            })
        ));
    }

    #[test]
    fn parses_value_free_machine_identity_session() {
        let cli = Cli::try_parse_from([
            "envvault",
            "--vault",
            "test.vault",
            "session",
            "--credential-file",
            "agent.credential.json",
            "--machine-unlock",
            "whoami",
        ]);

        assert!(matches!(
            cli.map(|value| value.command),
            Ok(Command::Session {
                machine_unlock: true,
                command: SessionCommand::Whoami,
                ..
            })
        ));
    }
}
