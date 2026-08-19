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

    /// Named target from `envvault.json` (`targets.<name>`).
    #[arg(long = "as", global = true, value_name = "NAME")]
    pub(super) target: Option<String>,

    /// Machine-readable value-free output for listing and preview commands.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub(super) format: OutputFormat,

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
    /// List authorized Secret names; `--verbose` adds `SecretId` and `use` grants.
    List {
        /// Include `SecretId` and callers granted `use`.
        #[arg(long)]
        verbose: bool,
    },
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
    /// Rename a Secret without changing its `SecretId` or value.
    Rename {
        /// Current Secret name.
        current: String,
        /// New Secret name.
        new: String,
    },
    /// Replace the Master Password and re-encrypt the Vault.
    ChangePassword,
    /// Import a strict dotenv file as independently managed Secrets.
    Import {
        /// Existing dotenv source; it is never modified or deleted.
        source: PathBuf,
        /// Preview create/replace/conflict without writing the Vault.
        #[arg(long)]
        dry_run: bool,
    },
    /// Generate a new value-free dotenv example from authorized names.
    Example {
        /// New output file; an existing path is never overwritten.
        #[arg(long, default_value = ".env.example", value_name = "PATH")]
        output: PathBuf,
        /// Restrict the example to environment keys in this Profile.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
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
    /// Inspect and update exact per-Secret authorization rules.
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
        /// Preview inject/deny/missing keys without starting the program.
        #[arg(long)]
        dry_run: bool,
        /// Exact program and arguments following `--`; no shell is introduced.
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
    /// Print shell completion script to stdout.
    Completions {
        /// Shell to generate completions for.
        shell: CompletionShell,
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

#[derive(Debug, Subcommand)]
pub(super) enum AuditCommand {
    /// List value-free Audit events after exact Owner authorization.
    List {
        /// Restrict to this caller identifier.
        #[arg(long)]
        caller_id: Option<CallerId>,
        /// Restrict to this Secret name (resolved after `list` authorization).
        #[arg(long)]
        secret: Option<String>,
        /// Restrict to this operation code, such as `use` or `list`.
        #[arg(long)]
        operation: Option<String>,
    },
    /// Explicitly migrate a legacy Vault Audit chain to the V2 sidecar backend.
    MigrateV2,
    /// Run a loopback ADR 0015 CAS service in an independent data directory.
    ServeAnchor {
        /// Private directory for CAS state. Must not be the Vault directory.
        #[arg(long, value_name = "PATH")]
        data_dir: PathBuf,
        /// Loopback listen address. Defaults to `127.0.0.1:7432`.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
        /// Bearer token file. Created if missing. Defaults to `<data-dir>/token.json`.
        #[arg(long, value_name = "PATH")]
        token_file: Option<PathBuf>,
        /// PEM certificate chain. Required unless `--allow-plaintext`.
        #[arg(long, value_name = "PATH")]
        tls_cert: Option<PathBuf>,
        /// PEM private key. Required unless `--allow-plaintext`.
        #[arg(long, value_name = "PATH")]
        tls_key: Option<PathBuf>,
        /// Listen without TLS. Loopback tests only; this is not a production mode.
        #[arg(long)]
        allow_plaintext: bool,
    },
    /// Point this Vault at a mandatory loopback CAS after Owner authentication.
    ConfigureAnchor {
        /// Loopback endpoint, preferably `https://127.0.0.1:7432`.
        #[arg(long, value_name = "URL")]
        endpoint: String,
        /// Existing Bearer token file issued by `audit serve-anchor`.
        #[arg(long, value_name = "PATH")]
        token_file: PathBuf,
        /// PEM trust anchor used to verify `https://` endpoints.
        #[arg(long, value_name = "PATH")]
        tls_ca: Option<PathBuf>,
        /// Allow an `http://` loopback endpoint. Not a production mode.
        #[arg(long)]
        allow_plaintext: bool,
    },
    /// Print value-free remote-anchor configuration and last-confirmed generation.
    AnchorStatus,
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
    /// List persisted per-Secret rules without Secret Values.
    List,
    /// Grant exact `use` permission for every `SecretId` in a Profile.
    GrantUse {
        /// Registered Application or AI Agent caller receiving the grants.
        #[arg(long)]
        caller_id: Option<CallerId>,
        /// Strict value-free Profile whose exact `SecretIds` are granted.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
    },
    /// Grant exact `list` and `exists` permission for every `SecretId` in a Profile.
    GrantInspect {
        /// Registered Application or AI Agent caller receiving the grants.
        #[arg(long)]
        caller_id: Option<CallerId>,
        /// Strict value-free Profile whose exact `SecretIds` are granted.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
    },
    /// Remove exact `use` grants for Profile secrets and/or named Secrets.
    RevokeUse {
        /// Registered Application or AI Agent caller losing the grants.
        #[arg(long)]
        caller_id: Option<CallerId>,
        /// Strict value-free Profile whose exact `SecretIds` lose `use`.
        #[arg(long, value_name = "PATH")]
        profile: Option<PathBuf>,
        /// Secret name whose `use` grant is removed. Repeatable.
        #[arg(long = "secret", value_name = "NAME")]
        secrets: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum CallerKindArg {
    Application,
    AiAgent,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum CompletionShell {
    Bash,
    Zsh,
    Powershell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub(super) enum OutputFormat {
    /// Human-readable text.
    #[default]
    Text,
    /// Compact JSON without Secret Values.
    Json,
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

    use super::{AuditCommand, Cli, Command, IdentityCommand, PolicyCommand, SessionCommand};

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
    fn parses_global_as_target() {
        let cli = Cli::try_parse_from(["envvault", "--as", "backend", "run", "--", "./app"]);
        assert!(matches!(
            cli,
            Ok(Cli {
                target: Some(name),
                command: Command::Run { .. },
                ..
            }) if name == "backend"
        ));
    }

    #[test]
    fn parses_import_dry_run_without_secret_values() {
        let cli = Cli::try_parse_from(["envvault", "import", "--dry-run", "./.env"]);
        assert!(matches!(
            cli.map(|value| value.command),
            Ok(Command::Import { dry_run: true, .. })
        ));
    }

    #[test]
    fn parses_policy_inspect_and_revoke_without_secret_values() {
        let inspect = Cli::try_parse_from([
            "envvault",
            "policy",
            "grant-inspect",
            "--caller-id",
            "00000000-0000-0000-0000-000000000001",
            "--profile",
            "agent.profile.json",
        ]);
        assert!(matches!(
            inspect.map(|value| value.command),
            Ok(Command::Policy {
                command: PolicyCommand::GrantInspect { .. }
            })
        ));

        let revoke = Cli::try_parse_from([
            "envvault",
            "policy",
            "revoke-use",
            "--secret",
            "OPENAI_API_KEY",
        ]);
        assert!(matches!(
            revoke.map(|value| value.command),
            Ok(Command::Policy {
                command: PolicyCommand::RevokeUse { .. }
            })
        ));

        let list = Cli::try_parse_from(["envvault", "policy", "list"]);
        assert!(matches!(
            list.map(|value| value.command),
            Ok(Command::Policy {
                command: PolicyCommand::List
            })
        ));
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
    fn parses_audit_anchor_service_commands() {
        let serve = Cli::try_parse_from([
            "envvault",
            "audit",
            "serve-anchor",
            "--data-dir",
            "/tmp/anchor-data",
            "--listen",
            "127.0.0.1:0",
        ]);
        assert!(matches!(
            serve.map(|value| value.command),
            Ok(Command::Audit {
                command: AuditCommand::ServeAnchor { .. }
            })
        ));

        let configure = Cli::try_parse_from([
            "envvault",
            "--vault",
            "test.vault",
            "audit",
            "configure-anchor",
            "--endpoint",
            "http://127.0.0.1:7432",
            "--token-file",
            "token.json",
        ]);
        assert!(matches!(
            configure.map(|value| value.command),
            Ok(Command::Audit {
                command: AuditCommand::ConfigureAnchor { .. }
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
