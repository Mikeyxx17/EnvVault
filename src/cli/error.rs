use core::fmt;
use std::io;

use crate::{
    broker::BrokerError, config::ProjectError, dotenv::DotenvError, identity::CallerNameError,
    process::ProcessError, profile::ProfileError, secret::SecretNameError,
};

/// Safe CLI failure categories that never carry password or credential bytes.
#[derive(Debug)]
pub(super) enum CliError {
    Broker(BrokerError),
    Keystore(crate::keystore::KeystoreError),
    VaultPathRequired,
    Project(ProjectError),
    ProjectDefaultMissing,
    InvalidCallerName,
    PasswordInputUnavailable,
    SecretInputUnavailable,
    SecretUnavailable,
    Dotenv(DotenvError),
    DotenvSourceUnavailable,
    ExampleFileExists,
    ExampleFileUnavailable,
    CredentialFileExists,
    CredentialFileUnavailable,
    CredentialFileInvalid,
    CredentialRecoveryRequired,
    ProfileFileExists,
    ProfileFileUnavailable,
    ProfileFileInvalid,
    Process(ProcessError),
    OutputUnavailable,
    ConfirmationUnavailable,
    ConfirmationRejected,
    UninstallUnavailable,
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Broker(error) => error.fmt(formatter),
            Self::Keystore(error) => error.fmt(formatter),
            Self::VaultPathRequired => formatter.write_str(
                "no Vault path: pass --vault PATH or add envvault.json in this project",
            ),
            Self::Project(error) => error.fmt(formatter),
            Self::ProjectDefaultMissing => formatter.write_str(
                "project default path is missing; pass the flag or set it in envvault.json",
            ),
            Self::InvalidCallerName => formatter.write_str("invalid caller name"),
            Self::PasswordInputUnavailable => formatter
                .write_str("master password input requires an attached interactive terminal"),
            Self::SecretInputUnavailable => {
                formatter.write_str("Secret Value input requires an attached interactive terminal")
            }
            Self::SecretUnavailable => {
                formatter.write_str("the requested Secret is unavailable")
            }
            Self::Dotenv(error) => error.fmt(formatter),
            Self::DotenvSourceUnavailable => {
                formatter.write_str("dotenv source could not be read safely")
            }
            Self::ExampleFileExists => {
                formatter.write_str("example file already exists; refusing to overwrite it")
            }
            Self::ExampleFileUnavailable => {
                formatter.write_str("example file could not be written safely")
            }
            Self::CredentialFileExists => {
                formatter.write_str("credential file already exists; refusing to overwrite it")
            }
            Self::CredentialFileUnavailable => {
                formatter.write_str("credential file could not be written safely")
            }
            Self::CredentialFileInvalid => formatter.write_str("credential file is invalid"),
            Self::CredentialRecoveryRequired => formatter.write_str(
                "credential delivery recovery could not complete safely; preserve the recovery file and inspect the destination",
            ),
            Self::ProfileFileExists => {
                formatter.write_str("Profile file already exists; refusing to overwrite it")
            }
            Self::ProfileFileUnavailable => {
                formatter.write_str("Profile file could not be accessed safely")
            }
            Self::ProfileFileInvalid => formatter.write_str("Profile file is invalid"),
            Self::Process(error) => error.fmt(formatter),
            Self::OutputUnavailable => formatter.write_str("command output is unavailable"),
            Self::ConfirmationUnavailable => formatter.write_str(
                "uninstall confirmation requires an attached interactive terminal",
            ),
            Self::ConfirmationRejected => {
                formatter.write_str("confirmation phrase did not match; nothing was deleted")
            }
            Self::UninstallUnavailable => {
                formatter.write_str("uninstall could not complete safely")
            }
        }
    }
}

impl std::error::Error for CliError {}

impl From<ProjectError> for CliError {
    fn from(value: ProjectError) -> Self {
        Self::Project(value)
    }
}

impl From<BrokerError> for CliError {
    fn from(value: BrokerError) -> Self {
        Self::Broker(value)
    }
}

impl From<crate::keystore::KeystoreError> for CliError {
    fn from(value: crate::keystore::KeystoreError) -> Self {
        Self::Keystore(value)
    }
}

impl From<CallerNameError> for CliError {
    fn from(_value: CallerNameError) -> Self {
        Self::InvalidCallerName
    }
}

impl From<SecretNameError> for CliError {
    fn from(_value: SecretNameError) -> Self {
        Self::SecretUnavailable
    }
}

impl From<DotenvError> for CliError {
    fn from(value: DotenvError) -> Self {
        Self::Dotenv(value)
    }
}

impl From<ProfileError> for CliError {
    fn from(_value: ProfileError) -> Self {
        Self::ProfileFileInvalid
    }
}

impl From<ProcessError> for CliError {
    fn from(value: ProcessError) -> Self {
        Self::Process(value)
    }
}

impl From<io::Error> for CliError {
    fn from(_value: io::Error) -> Self {
        Self::OutputUnavailable
    }
}
