use std::io;

use dialoguer::{
    Password,
    console::{Key, Term},
};
use zeroize::Zeroizing;

use crate::crypto::MasterPassword;
use crate::secret::SecretValue;

use super::error::CliError;

pub(super) trait PasswordReader {
    fn read_new(&mut self) -> Result<MasterPassword, CliError>;
    fn read_existing(&mut self) -> Result<MasterPassword, CliError>;
}

pub(super) trait SecretValueReader {
    fn read_secret_value(&mut self) -> Result<SecretValue, CliError>;

    fn read_expected_secret_value(&mut self) -> Result<SecretValue, CliError> {
        self.read_secret_value()
    }
}

pub(super) trait ConfirmReader {
    fn confirm_phrase(&mut self, expected: &str) -> Result<(), CliError>;
}

pub(super) trait SensitiveInput: PasswordReader + SecretValueReader + ConfirmReader {}

impl<T: PasswordReader + SecretValueReader + ConfirmReader + ?Sized> SensitiveInput for T {}

pub(super) struct TerminalSensitiveInput {
    masked: bool,
}

impl TerminalSensitiveInput {
    pub(super) const fn new(masked: bool) -> Self {
        Self { masked }
    }

    fn read(
        &self,
        prompt: &str,
        confirmation: Option<(&str, &str)>,
        allow_empty: bool,
    ) -> io::Result<Zeroizing<String>> {
        if self.masked {
            return read_masked(prompt, confirmation, allow_empty);
        }
        let mut password = Password::new()
            .with_prompt(prompt)
            .allow_empty_password(allow_empty)
            .report(false);
        if let Some((confirmation_prompt, mismatch)) = confirmation {
            password = password.with_confirmation(confirmation_prompt, mismatch);
        }
        password
            .interact()
            .map(Zeroizing::new)
            .map_err(io::Error::other)
    }
}

impl PasswordReader for TerminalSensitiveInput {
    fn read_new(&mut self) -> Result<MasterPassword, CliError> {
        let password = self
            .read(
                "Master password",
                Some(("Confirm master password", "Master passwords do not match")),
                false,
            )
            .map_err(|_| CliError::PasswordInputUnavailable)?;
        Ok(MasterPassword::new(password.as_bytes().to_vec()))
    }

    fn read_existing(&mut self) -> Result<MasterPassword, CliError> {
        let password = self
            .read("Master password", None, false)
            .map_err(|_| CliError::PasswordInputUnavailable)?;
        Ok(MasterPassword::new(password.as_bytes().to_vec()))
    }
}

impl SecretValueReader for TerminalSensitiveInput {
    fn read_secret_value(&mut self) -> Result<SecretValue, CliError> {
        let value = self
            .read(
                "Secret value",
                Some(("Confirm secret value", "Secret values do not match")),
                true,
            )
            .map_err(|_| CliError::SecretInputUnavailable)?;
        Ok(SecretValue::new(value.as_bytes().to_vec()))
    }

    fn read_expected_secret_value(&mut self) -> Result<SecretValue, CliError> {
        let value = self
            .read("Expected secret value", None, true)
            .map_err(|_| CliError::SecretInputUnavailable)?;
        Ok(SecretValue::new(value.as_bytes().to_vec()))
    }
}

impl ConfirmReader for TerminalSensitiveInput {
    fn confirm_phrase(&mut self, expected: &str) -> Result<(), CliError> {
        let term = Term::stderr();
        if !term.is_term() {
            return Err(CliError::ConfirmationUnavailable);
        }
        term.write_str(&format!("Type `{expected}` to confirm: "))
            .and_then(|()| term.flush())
            .map_err(|_| CliError::ConfirmationUnavailable)?;
        let line = term
            .read_line()
            .map_err(|_| CliError::ConfirmationUnavailable)?;
        if line.trim() == expected {
            Ok(())
        } else {
            Err(CliError::ConfirmationRejected)
        }
    }
}

fn read_masked(
    prompt: &str,
    confirmation: Option<(&str, &str)>,
    allow_empty: bool,
) -> io::Result<Zeroizing<String>> {
    let term = Term::stderr();
    if !term.is_term() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "not a terminal",
        ));
    }
    loop {
        let value = read_masked_once(&term, prompt, allow_empty)?;
        if let Some((confirmation_prompt, mismatch)) = confirmation {
            let confirmed = read_masked_once(&term, confirmation_prompt, allow_empty)?;
            if value != confirmed {
                term.write_line(mismatch)?;
                continue;
            }
        }
        return Ok(value);
    }
}

fn read_masked_once(term: &Term, prompt: &str, allow_empty: bool) -> io::Result<Zeroizing<String>> {
    loop {
        term.write_str(prompt)?;
        term.write_str(": ")?;
        term.flush()?;
        let mut input = Zeroizing::new(String::new());
        loop {
            match term.read_key()? {
                Key::Char(character) => {
                    input.push(character);
                    term.write_str("*")?;
                    term.flush()?;
                }
                Key::Backspace => {
                    if input.pop().is_some() {
                        term.clear_chars(1)?;
                        term.flush()?;
                    }
                }
                Key::Enter if allow_empty || !input.is_empty() => {
                    term.write_line("")?;
                    return Ok(input);
                }
                Key::Enter => {
                    term.write_line("")?;
                    break;
                }
                Key::CtrlC | Key::Escape => {
                    term.write_line("")?;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "input cancelled",
                    ));
                }
                _ => {}
            }
        }
    }
}
