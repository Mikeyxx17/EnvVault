//! Command-line parsing, user interaction, and command dispatch.
//!
//! This boundary must not place secret values in process arguments.

mod application;
mod args;
mod commands;
mod credential_file;
mod credential_recovery;
mod dotenv_file;
mod error;
mod example_file;
mod password;
mod profile_file;

use std::{ffi::OsString, io, process::ExitCode};

use clap::Parser as _;

use args::Cli;
use commands::{ExecutionOutcome, execute};
use password::TerminalSensitiveInput;

/// Parses the process arguments and executes one safe CLI command.
///
/// Master passwords are collected only from an attached terminal with echo
/// disabled; they are never accepted as command-line options or environment
/// variables.
#[must_use]
pub fn run() -> ExitCode {
    run_from(std::env::args_os(), &mut io::stdout(), &mut io::stderr())
}

fn run_from<I, T>(args: I, output: &mut dyn io::Write, errors: &mut dyn io::Write) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let exit_code = ExitCode::from(error.exit_code().try_into().unwrap_or(2));
            if error.use_stderr() {
                let _ignored = write!(errors, "{error}");
            } else {
                let _ignored = write!(output, "{error}");
            }
            return exit_code;
        }
    };

    let mut sensitive_input = TerminalSensitiveInput::new(cli.masked_input);
    match execute(cli, &mut sensitive_input, output) {
        Ok(ExecutionOutcome::Success) => ExitCode::SUCCESS,
        Ok(ExecutionOutcome::Child(status)) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or_else(|| ExitCode::from(1), ExitCode::from),
        Err(error) => {
            let _ignored = writeln!(errors, "error: {error}");
            ExitCode::from(1)
        }
    }
}
