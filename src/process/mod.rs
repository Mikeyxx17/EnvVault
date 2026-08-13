//! Child-process execution and runtime secret injection.
//!
//! Environment injection is a convenience boundary, not a security sandbox
//! against a caller that can modify or inspect the target process.

use core::fmt;
use std::{
    ffi::OsString,
    process::{Command, ExitStatus},
};

use crate::secret::SecretValue;

/// One authorized environment binding consumed by the child-process boundary.
///
/// This type deliberately implements neither `Debug` nor `Clone`.
pub struct InjectedSecret {
    environment: String,
    value: SecretValue,
}

impl InjectedSecret {
    /// Creates an authorized binding. Environment-key validation belongs to the
    /// Profile parser before this boundary is reached.
    #[must_use]
    pub fn new(environment: String, value: SecretValue) -> Self {
        Self { environment, value }
    }
}

/// Executes one exact argv vector with a cleared and explicitly rebuilt environment.
///
/// No shell is introduced. The child receives a small platform bootstrap
/// allowlist plus the supplied authorized Secret bindings; all other parent
/// variables are removed.
///
/// # Errors
///
/// Rejects an empty command, Secret Values that cannot be represented as UTF-8
/// environment values, and process creation failures.
pub fn run(command: &[OsString], secrets: &[InjectedSecret]) -> Result<ExitStatus, ProcessError> {
    let program = command.first().ok_or(ProcessError::EmptyCommand)?;
    let mut child = Command::new(program);
    child.args(&command[1..]);
    child.env_clear();
    inherit_platform_bootstrap(&mut child);
    for secret in secrets {
        let value = std::str::from_utf8(secret.value.expose_secret())
            .map_err(|_| ProcessError::InvalidEnvironmentValue)?;
        child.env(&secret.environment, value);
    }
    child.status().map_err(|_| ProcessError::SpawnUnavailable)
}

fn inherit_platform_bootstrap(command: &mut Command) {
    #[cfg(windows)]
    const NAMES: &[&str] = &[
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "PATHEXT",
        "PATH",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ];
    #[cfg(not(windows))]
    const NAMES: &[&str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ];

    for name in NAMES {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

/// Safe process-runtime failure category without argv or Secret Values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// No program was supplied after `--`.
    EmptyCommand,
    /// A Secret Value cannot be represented by the platform-neutral V1 UTF-8 boundary.
    InvalidEnvironmentValue,
    /// The child process could not be created or observed.
    SpawnUnavailable,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyCommand => "a child command is required after --",
            Self::InvalidEnvironmentValue => {
                "an authorized Secret cannot be represented as a process environment value"
            }
            Self::SpawnUnavailable => "the child process could not be started",
        })
    }
}

impl std::error::Error for ProcessError {}

#[cfg(test)]
mod tests {
    use std::{env, ffi::OsString};

    use super::{InjectedSecret, ProcessError, run};
    use crate::secret::SecretValue;

    #[test]
    fn child_receives_authorized_values_but_not_the_general_parent_environment()
    -> Result<(), Box<dyn std::error::Error>> {
        if env::var("ENVVAULT_PROCESS_TEST_MODE").as_deref() == Ok("child") {
            assert_eq!(
                env::var("ENVVAULT_PROCESS_TEST_SECRET").as_deref(),
                Ok("runtime-only")
            );
            assert!(env::var_os("CARGO_MANIFEST_DIR").is_none());
            return Ok(());
        }

        let executable = env::current_exe()?;
        let command = vec![
            executable.into_os_string(),
            OsString::from("--exact"),
            OsString::from(
                "process::tests::child_receives_authorized_values_but_not_the_general_parent_environment",
            ),
        ];
        let secrets = vec![
            InjectedSecret::new(
                "ENVVAULT_PROCESS_TEST_MODE".to_owned(),
                SecretValue::new(b"child".to_vec()),
            ),
            InjectedSecret::new(
                "ENVVAULT_PROCESS_TEST_SECRET".to_owned(),
                SecretValue::new(b"runtime-only".to_vec()),
            ),
        ];
        let status = run(&command, &secrets)?;

        assert!(status.success());
        Ok(())
    }

    #[test]
    fn rejects_empty_command_and_non_utf8_value() {
        assert_eq!(run(&[], &[]), Err(ProcessError::EmptyCommand));
        let command = [OsString::from("unused")];
        let secrets = [InjectedSecret::new(
            "TOKEN".to_owned(),
            SecretValue::new(vec![0xff]),
        )];
        assert_eq!(
            run(&command, &secrets),
            Err(ProcessError::InvalidEnvironmentValue)
        );
    }
}
