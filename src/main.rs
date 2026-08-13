//! `EnvVault` command-line executable.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    envvault::cli::run()
}
