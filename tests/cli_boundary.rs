//! Process-boundary tests for the `envvault` executable.

use std::{fs, process::Command};

use tempfile::tempdir;

#[test]
fn help_exposes_no_password_argument() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .arg("--help")
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("Usage:"));
    assert!(help.contains("identity"));
    assert!(help.contains("profile"));
    assert!(help.contains("policy"));
    assert!(help.contains("keystore"));
    assert!(help.contains("session"));
    assert!(help.contains("verify"));
    assert!(help.contains("--masked-input"));
    assert!(help.contains("run"));
    assert!(help.contains("uninstall"));
    assert!(!help.contains("--password"));
    assert!(!help.contains("PASSWORD"));
    Ok(())
}

#[test]
fn verify_help_accepts_no_expected_value_argument() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["verify", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("<NAME>"));
    assert!(!help.contains("--value"));
    assert!(!help.contains("--expected"));
    assert!(!help.contains("SECRET_VALUE"));
    Ok(())
}

#[test]
fn session_help_accepts_only_identity_evidence_and_unlock_mode()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["session", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--credential-file"));
    assert!(help.contains("--machine-unlock"));
    assert!(help.contains("whoami"));
    assert!(!help.contains("--profile"));
    assert!(!help.contains("--value"));
    assert!(!help.contains("--password"));
    Ok(())
}

#[test]
fn audit_help_exposes_loopback_anchor_commands_without_token_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["audit", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("serve-anchor"));
    assert!(help.contains("configure-anchor"));
    assert!(help.contains("anchor-status"));
    assert!(!help.contains("--password"));
    assert!(!help.contains("--token "));
    assert!(!help.contains("SECRET"));
    Ok(())
}

#[test]
fn identity_help_exposes_value_free_credential_rotation() -> Result<(), Box<dyn std::error::Error>>
{
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["identity", "rotate", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--caller-id"));
    assert!(help.contains("--credential-file"));
    assert!(!help.contains("<CREDENTIAL>"));
    assert!(!help.contains("--value"));
    assert!(!help.contains("--password"));
    Ok(())
}

#[test]
fn uninstall_without_a_terminal_deletes_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["uninstall", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--purge-project"));
    assert!(!help.contains("--password"));
    assert!(!help.contains("--yes"));

    let refused = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .arg("uninstall")
        .output()?;
    assert!(!refused.status.success());
    assert!(String::from_utf8(refused.stderr)?.contains("interactive terminal"));
    Ok(())
}

#[test]
fn init_refuses_non_terminal_password_input() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let vault = directory.path().join("must-not-exist.vault.json");
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args([
            "--vault",
            vault.to_str().ok_or("non-UTF-8 test path")?,
            "init",
        ])
        .output()?;

    assert!(!output.status.success());
    assert!(!vault.exists());
    assert!(String::from_utf8(output.stderr)?.contains("interactive terminal"));
    assert!(fs::read_dir(directory.path())?.next().is_none());
    Ok(())
}

#[test]
fn set_help_exposes_no_secret_value_argument() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["set", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("<NAME>"));
    assert!(!help.contains("--value"));
    assert!(!help.contains("SECRET_VALUE"));
    Ok(())
}

#[test]
fn dotenv_help_keeps_values_out_of_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let import = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["import", "--help"])
        .output()?;
    assert!(import.status.success());
    let help = String::from_utf8(import.stdout)?;
    assert!(help.contains("<SOURCE>"));
    assert!(!help.contains("--value"));

    let example = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["example", "--help"])
        .output()?;
    assert!(example.status.success());
    assert!(String::from_utf8(example.stdout)?.contains("--output"));
    Ok(())
}

#[test]
fn run_help_requires_files_and_exact_child_argv_without_secret_values()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["run", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("--profile"));
    assert!(help.contains("--credential-file"));
    assert!(help.contains("--machine-unlock"));
    assert!(help.contains("<COMMAND>..."));
    assert!(!help.contains("--value"));
    assert!(!help.contains("--password"));
    Ok(())
}

#[test]
fn keystore_help_exposes_only_value_free_management_actions()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_envvault"))
        .args(["keystore", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for action in ["enable", "status", "rotate", "disable"] {
        assert!(help.contains(action));
    }
    assert!(!help.contains("--password"));
    assert!(!help.contains("--key"));
    assert!(!help.contains("--value"));
    Ok(())
}
