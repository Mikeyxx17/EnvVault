//! Platform-keystore-backed machine unlock.
//!
//! The operating-system store holds only a random wrapping key. The Vault
//! Master Key remains in an authenticated sidecar envelope bound to the Vault
//! identity and credential generation. Management is exposed only through the
//! Broker control plane.

use core::fmt;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        EncryptedEnvelope, KeystoreKey, MasterKey, decrypt_keystore, encrypt_keystore,
        generate_array,
    },
    secure_fs,
};

const FORMAT_NAME: &str = "envvault-machine-unlock";
const FORMAT_VERSION: u32 = 1;
const SERVICE_NAME: &str = "envvault-machine-unlock-v1";
const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const AAD_DOMAIN: &[u8] = b"envvault:machine-unlock:v1\0";
const VAULT_ID_LENGTH: usize = 16;
const MAX_BINDING_BYTES: u64 = 16 * 1024;
const MAX_RETIRED_ACCOUNTS: usize = 16;

/// Non-sensitive failure category for platform-keystore operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreError {
    /// No supported operating-system credential store is available.
    UnsupportedPlatform,
    /// The platform credential operation failed or the item is unavailable.
    CredentialUnavailable,
    /// The machine-unlock binding does not exist.
    NotEnabled,
    /// Machine unlock is already enabled.
    AlreadyEnabled,
    /// The binding is malformed, non-canonical, mismatched, or tampered.
    InvalidBinding,
    /// The binding could not be accessed through the protected filesystem path.
    BindingUnavailable,
    /// A size or generation bound was exceeded.
    ResourceLimitExceeded,
}

impl fmt::Display for KeystoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("platform machine unlock is unsupported on this build")
            }
            Self::CredentialUnavailable => {
                formatter.write_str("platform machine-unlock credential is unavailable")
            }
            Self::NotEnabled => formatter.write_str("platform machine unlock is not enabled"),
            Self::AlreadyEnabled => {
                formatter.write_str("platform machine unlock is already enabled")
            }
            Self::InvalidBinding => formatter.write_str("machine-unlock binding is invalid"),
            Self::BindingUnavailable => {
                formatter.write_str("machine-unlock binding is unavailable")
            }
            Self::ResourceLimitExceeded => {
                formatter.write_str("machine-unlock resource limit exceeded")
            }
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Value-free machine-unlock status returned after Owner authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineUnlockStatus {
    enabled: bool,
    backend: &'static str,
    generation: u64,
    cleanup_pending: usize,
}

impl MachineUnlockStatus {
    /// Returns whether non-interactive machine unlock is active.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the platform backend identifier.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        self.backend
    }

    /// Returns the active wrapping-credential generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the number of retired credential entries awaiting cleanup.
    #[must_use]
    pub const fn cleanup_pending(&self) -> usize {
        self.cleanup_pending
    }
}

pub(crate) trait CredentialStore {
    fn set(&mut self, account: &str, secret: &[u8]) -> Result<(), KeystoreError>;
    fn get(&mut self, account: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError>;
    fn delete(&mut self, account: &str) -> Result<(), KeystoreError>;
}

pub(crate) struct PlatformCredentialStore;

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
impl CredentialStore for PlatformCredentialStore {
    fn set(&mut self, account: &str, secret: &[u8]) -> Result<(), KeystoreError> {
        let entry = platform_entry(account)?;

        #[cfg(target_os = "linux")]
        let stored = Zeroizing::new(STANDARD.encode(secret).into_bytes());
        #[cfg(target_os = "linux")]
        let secret = stored.as_slice();

        entry
            .set_secret(secret)
            .map_err(|_| KeystoreError::CredentialUnavailable)
    }

    fn get(&mut self, account: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        let entry = platform_entry(account)?;
        let stored = entry
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|_| KeystoreError::CredentialUnavailable)?;

        #[cfg(target_os = "linux")]
        {
            STANDARD
                .decode(stored.as_slice())
                .map(Zeroizing::new)
                .map_err(|_| KeystoreError::CredentialUnavailable)
        }

        #[cfg(any(windows, target_os = "macos"))]
        {
            Ok(stored)
        }
    }

    fn delete(&mut self, account: &str) -> Result<(), KeystoreError> {
        let entry = platform_entry(account)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(_) => Err(KeystoreError::CredentialUnavailable),
        }
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn platform_entry(account: &str) -> Result<keyring_core::Entry, KeystoreError> {
    use std::sync::OnceLock;

    static INITIALIZED: OnceLock<Result<(), KeystoreError>> = OnceLock::new();
    let initialized = INITIALIZED.get_or_init(|| {
        #[cfg(windows)]
        let store = windows_native_keyring_store::Store::new()
            .map_err(|_| KeystoreError::CredentialUnavailable)?;

        #[cfg(target_os = "linux")]
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|_| KeystoreError::CredentialUnavailable)?;

        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::keychain::Store::new()
            .map_err(|_| KeystoreError::CredentialUnavailable)?;

        keyring_core::set_default_store(store);
        Ok(())
    });
    (*initialized)?;

    #[cfg(windows)]
    {
        use std::collections::HashMap;

        let modifiers = HashMap::from([("persistence", "local")]);
        keyring_core::Entry::new_with_modifiers(SERVICE_NAME, account, &modifiers)
            .map_err(|_| KeystoreError::CredentialUnavailable)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        keyring_core::Entry::new(SERVICE_NAME, account)
            .map_err(|_| KeystoreError::CredentialUnavailable)
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl CredentialStore for PlatformCredentialStore {
    fn set(&mut self, _account: &str, _secret: &[u8]) -> Result<(), KeystoreError> {
        Err(KeystoreError::UnsupportedPlatform)
    }

    fn get(&mut self, _account: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        Err(KeystoreError::UnsupportedPlatform)
    }

    fn delete(&mut self, _account: &str) -> Result<(), KeystoreError> {
        Err(KeystoreError::UnsupportedPlatform)
    }
}

pub(crate) fn enable(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
) -> Result<MachineUnlockStatus, KeystoreError> {
    enable_with_store(
        vault_path,
        vault_id,
        master_key,
        &mut PlatformCredentialStore,
    )
}

pub(crate) fn rotate(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
) -> Result<MachineUnlockStatus, KeystoreError> {
    rotate_with_store(
        vault_path,
        vault_id,
        master_key,
        &mut PlatformCredentialStore,
    )
}

pub(crate) fn disable(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
) -> Result<MachineUnlockStatus, KeystoreError> {
    disable_with_store(vault_path, vault_id, &mut PlatformCredentialStore)
}

pub(crate) fn status(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
) -> Result<MachineUnlockStatus, KeystoreError> {
    status_with_store(
        vault_path,
        vault_id,
        master_key,
        &mut PlatformCredentialStore,
    )
}

pub(crate) fn unlock(vault_path: &Path) -> Result<MasterKey, KeystoreError> {
    unlock_with_store(vault_path, &mut PlatformCredentialStore)
}

fn enable_with_store(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
    store: &mut dyn CredentialStore,
) -> Result<MachineUnlockStatus, KeystoreError> {
    let _lock = acquire_lock(vault_path)?;
    if binding_path_for(vault_path).exists() {
        return Err(KeystoreError::AlreadyEnabled);
    }
    let binding = create_binding(vault_id, 1, master_key, Vec::new(), store)?;
    if let Err(error) = write_new(&binding_path_for(vault_path), &serialize(&binding)?) {
        let _ignored = store.delete(&binding.account);
        return Err(error);
    }
    Ok(binding.status())
}

fn rotate_with_store(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
    store: &mut dyn CredentialStore,
) -> Result<MachineUnlockStatus, KeystoreError> {
    let _lock = acquire_lock(vault_path)?;
    let old = read_binding(vault_path)?;
    old.validate_for(vault_id)?;
    if old.state != BindingState::Active {
        return Err(KeystoreError::NotEnabled);
    }
    let generation = old
        .generation
        .checked_add(1)
        .ok_or(KeystoreError::ResourceLimitExceeded)?;
    let mut retired = old.retired_accounts;
    retired.push(old.account.clone());
    if retired.len() > MAX_RETIRED_ACCOUNTS {
        return Err(KeystoreError::ResourceLimitExceeded);
    }
    let candidate = create_binding(vault_id, generation, master_key, retired, store)?;
    if let Err(error) = write_atomically(&binding_path_for(vault_path), &serialize(&candidate)?) {
        let _ignored = store.delete(&candidate.account);
        return Err(error);
    }
    cleanup_retired(vault_path, candidate, store)
}

fn disable_with_store(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    store: &mut dyn CredentialStore,
) -> Result<MachineUnlockStatus, KeystoreError> {
    let _lock = acquire_lock(vault_path)?;
    let mut binding = read_binding(vault_path)?;
    binding.validate_for(vault_id)?;
    if binding.state == BindingState::Active {
        binding.retired_accounts.push(binding.account.clone());
        binding.state = BindingState::Disabled;
        binding.account.clear();
        binding.envelope = None;
        write_atomically(&binding_path_for(vault_path), &serialize(&binding)?)?;
    }
    binding
        .retired_accounts
        .retain(|account| store.delete(account).is_err());
    if binding.retired_accounts.is_empty() {
        fs::remove_file(binding_path_for(vault_path))
            .map_err(|_| KeystoreError::BindingUnavailable)?;
    } else {
        write_atomically(&binding_path_for(vault_path), &serialize(&binding)?)?;
    }
    Ok(binding.status())
}

fn status_with_store(
    vault_path: &Path,
    vault_id: [u8; VAULT_ID_LENGTH],
    master_key: &MasterKey,
    store: &mut dyn CredentialStore,
) -> Result<MachineUnlockStatus, KeystoreError> {
    let _lock = acquire_lock(vault_path)?;
    let binding = match read_binding(vault_path) {
        Ok(binding) => binding,
        Err(KeystoreError::NotEnabled) => {
            return Ok(MachineUnlockStatus {
                enabled: false,
                backend: platform_backend(),
                generation: 0,
                cleanup_pending: 0,
            });
        }
        Err(error) => return Err(error),
    };
    binding.validate_for(vault_id)?;
    if binding.state == BindingState::Active {
        let secret = store.get(&binding.account)?;
        let key_bytes: [u8; KeystoreKey::LENGTH] = secret
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::CredentialUnavailable)?;
        let key = KeystoreKey::new(Zeroizing::new(key_bytes));
        let envelope = binding
            .envelope
            .as_ref()
            .ok_or(KeystoreError::InvalidBinding)?;
        let plaintext = decrypt_keystore(&key, envelope, &aad(&binding))
            .map_err(|_| KeystoreError::InvalidBinding)?;
        if plaintext.len() != MasterKey::LENGTH
            || !bool::from(plaintext.as_slice().ct_eq(master_key.expose_secret()))
        {
            return Err(KeystoreError::InvalidBinding);
        }
    }
    Ok(binding.status())
}

fn unlock_with_store(
    vault_path: &Path,
    store: &mut dyn CredentialStore,
) -> Result<MasterKey, KeystoreError> {
    let _lock = acquire_lock(vault_path)?;
    let binding = read_binding(vault_path)?;
    binding.validate()?;
    if binding.state != BindingState::Active {
        return Err(KeystoreError::NotEnabled);
    }
    let bytes = store.get(&binding.account)?;
    let key_bytes: [u8; KeystoreKey::LENGTH] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::CredentialUnavailable)?;
    let key = KeystoreKey::new(Zeroizing::new(key_bytes));
    let envelope = binding
        .envelope
        .as_ref()
        .ok_or(KeystoreError::InvalidBinding)?;
    let plaintext = decrypt_keystore(&key, envelope, &aad(&binding))
        .map_err(|_| KeystoreError::InvalidBinding)?;
    let master_key: [u8; MasterKey::LENGTH] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::InvalidBinding)?;
    Ok(MasterKey::new(Zeroizing::new(master_key)))
}

fn create_binding(
    vault_id: [u8; VAULT_ID_LENGTH],
    generation: u64,
    master_key: &MasterKey,
    retired_accounts: Vec<String>,
    store: &mut dyn CredentialStore,
) -> Result<Binding, KeystoreError> {
    let account = account_name(vault_id, generation);
    let key_bytes = generate_array::<{ KeystoreKey::LENGTH }>()
        .map_err(|_| KeystoreError::CredentialUnavailable)?;
    let key = KeystoreKey::new(Zeroizing::new(key_bytes));
    let mut binding = Binding {
        vault_id,
        backend: platform_backend(),
        state: BindingState::Active,
        generation,
        account,
        envelope: None,
        retired_accounts,
    };
    let envelope = encrypt_keystore(&key, master_key.expose_secret(), &aad(&binding))
        .map_err(|_| KeystoreError::CredentialUnavailable)?;
    store.set(&binding.account, key.expose_secret())?;
    binding.envelope = Some(envelope);
    Ok(binding)
}

fn cleanup_retired(
    vault_path: &Path,
    mut binding: Binding,
    store: &mut dyn CredentialStore,
) -> Result<MachineUnlockStatus, KeystoreError> {
    binding
        .retired_accounts
        .retain(|account| store.delete(account).is_err());
    write_atomically(&binding_path_for(vault_path), &serialize(&binding)?)?;
    Ok(binding.status())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindingState {
    Active,
    Disabled,
}

#[derive(Clone, PartialEq, Eq)]
struct Binding {
    vault_id: [u8; VAULT_ID_LENGTH],
    backend: &'static str,
    state: BindingState,
    generation: u64,
    account: String,
    envelope: Option<EncryptedEnvelope>,
    retired_accounts: Vec<String>,
}

impl Binding {
    fn validate(&self) -> Result<(), KeystoreError> {
        if self.generation == 0
            || self.backend != platform_backend()
            || self.retired_accounts.len() > MAX_RETIRED_ACCOUNTS
        {
            return Err(KeystoreError::InvalidBinding);
        }
        match self.state {
            BindingState::Active
                if self.account == account_name(self.vault_id, self.generation)
                    && self.envelope.as_ref().is_some_and(|envelope| {
                        envelope.ciphertext.len()
                            == MasterKey::LENGTH + EncryptedEnvelope::TAG_LENGTH
                    }) => {}
            BindingState::Disabled if self.account.is_empty() && self.envelope.is_none() => {}
            _ => return Err(KeystoreError::InvalidBinding),
        }
        let unique = self.retired_accounts.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.retired_accounts.len()
            || self.retired_accounts.iter().any(|account| {
                account.is_empty()
                    || account == &self.account
                    || !account.starts_with(&format!("vault-{}-g", hex(self.vault_id)))
            })
        {
            return Err(KeystoreError::InvalidBinding);
        }
        Ok(())
    }

    fn validate_for(&self, vault_id: [u8; VAULT_ID_LENGTH]) -> Result<(), KeystoreError> {
        self.validate()?;
        if self.vault_id != vault_id {
            return Err(KeystoreError::InvalidBinding);
        }
        Ok(())
    }

    fn status(&self) -> MachineUnlockStatus {
        MachineUnlockStatus {
            enabled: self.state == BindingState::Active,
            backend: self.backend,
            generation: self.generation,
            cleanup_pending: self.retired_accounts.len(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingFile {
    format: String,
    version: u32,
    vault_id: String,
    backend: String,
    state: String,
    generation: u64,
    service: String,
    account: String,
    aead: String,
    envelope: Option<EnvelopeFile>,
    retired_accounts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFile {
    nonce: String,
    ciphertext: String,
}

fn serialize(binding: &Binding) -> Result<Vec<u8>, KeystoreError> {
    binding.validate()?;
    let envelope = binding.envelope.as_ref().map(|value| EnvelopeFile {
        nonce: STANDARD.encode(value.nonce),
        ciphertext: STANDARD.encode(&value.ciphertext),
    });
    let file = BindingFile {
        format: FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        vault_id: STANDARD.encode(binding.vault_id),
        backend: binding.backend.to_owned(),
        state: match binding.state {
            BindingState::Active => "active",
            BindingState::Disabled => "disabled",
        }
        .to_owned(),
        generation: binding.generation,
        service: SERVICE_NAME.to_owned(),
        account: binding.account.clone(),
        aead: AEAD_ALGORITHM.to_owned(),
        envelope,
        retired_accounts: binding.retired_accounts.clone(),
    };
    serde_json::to_vec_pretty(&file).map_err(|_| KeystoreError::InvalidBinding)
}

fn parse(bytes: &[u8]) -> Result<Binding, KeystoreError> {
    if u64::try_from(bytes.len()).map_err(|_| KeystoreError::ResourceLimitExceeded)?
        > MAX_BINDING_BYTES
    {
        return Err(KeystoreError::ResourceLimitExceeded);
    }
    let file: BindingFile =
        serde_json::from_slice(bytes).map_err(|_| KeystoreError::InvalidBinding)?;
    if file.format != FORMAT_NAME
        || file.version != FORMAT_VERSION
        || file.service != SERVICE_NAME
        || file.aead != AEAD_ALGORITHM
        || file.backend != platform_backend()
    {
        return Err(KeystoreError::InvalidBinding);
    }
    let vault_id = decode_array(&file.vault_id)?;
    let state = match file.state.as_str() {
        "active" => BindingState::Active,
        "disabled" => BindingState::Disabled,
        _ => return Err(KeystoreError::InvalidBinding),
    };
    let envelope = file
        .envelope
        .map(|value| {
            Ok(EncryptedEnvelope {
                nonce: decode_array(&value.nonce)?,
                ciphertext: STANDARD
                    .decode(value.ciphertext)
                    .map_err(|_| KeystoreError::InvalidBinding)?,
            })
        })
        .transpose()?;
    let binding = Binding {
        vault_id,
        backend: platform_backend(),
        state,
        generation: file.generation,
        account: file.account,
        envelope,
        retired_accounts: file.retired_accounts,
    };
    binding.validate()?;
    if serialize(&binding)? != bytes {
        return Err(KeystoreError::InvalidBinding);
    }
    Ok(binding)
}

fn read_binding(vault_path: &Path) -> Result<Binding, KeystoreError> {
    let path = binding_path_for(vault_path);
    let file = match secure_fs::open_existing(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(KeystoreError::NotEnabled);
        }
        Err(_) => return Err(KeystoreError::BindingUnavailable),
    };
    let length = file
        .metadata()
        .map_err(|_| KeystoreError::BindingUnavailable)?
        .len();
    if length > MAX_BINDING_BYTES {
        return Err(KeystoreError::ResourceLimitExceeded);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(length).map_err(|_| KeystoreError::ResourceLimitExceeded)?,
    );
    file.take(MAX_BINDING_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| KeystoreError::BindingUnavailable)?;
    parse(&bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), KeystoreError> {
    let mut file = secure_fs::create_new(path).map_err(|_| KeystoreError::BindingUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| KeystoreError::BindingUnavailable)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), KeystoreError> {
    secure_fs::ensure_safe_path(path, false).map_err(|_| KeystoreError::BindingUnavailable)?;
    let mut file = AtomicWriteFile::open(path).map_err(|_| KeystoreError::BindingUnavailable)?;
    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut())
        .map_err(|_| KeystoreError::BindingUnavailable)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| KeystoreError::BindingUnavailable)?;
    file.commit()
        .map_err(|_| KeystoreError::BindingUnavailable)?;
    secure_fs::protect_existing(path).map_err(|_| KeystoreError::BindingUnavailable)
}

fn acquire_lock(vault_path: &Path) -> Result<std::fs::File, KeystoreError> {
    let lock = secure_fs::open_lock(&lock_path_for(vault_path))
        .map_err(|_| KeystoreError::BindingUnavailable)?;
    lock.lock().map_err(|_| KeystoreError::BindingUnavailable)?;
    Ok(lock)
}

fn aad(binding: &Binding) -> Vec<u8> {
    let mut value = Vec::with_capacity(
        AAD_DOMAIN.len()
            + VAULT_ID_LENGTH
            + 8
            + binding.backend.len()
            + SERVICE_NAME.len()
            + binding.account.len()
            + 3,
    );
    value.extend_from_slice(AAD_DOMAIN);
    value.extend_from_slice(&binding.vault_id);
    value.extend_from_slice(&binding.generation.to_le_bytes());
    value.extend_from_slice(binding.backend.as_bytes());
    value.push(0);
    value.extend_from_slice(SERVICE_NAME.as_bytes());
    value.push(0);
    value.extend_from_slice(binding.account.as_bytes());
    value.push(0);
    value
}

fn account_name(vault_id: [u8; VAULT_ID_LENGTH], generation: u64) -> String {
    format!("vault-{}-g{generation}", hex(vault_id))
}

fn hex<const LENGTH: usize>(bytes: [u8; LENGTH]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(LENGTH * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_array<const LENGTH: usize>(value: &str) -> Result<[u8; LENGTH], KeystoreError> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| KeystoreError::InvalidBinding)?;
    bytes.try_into().map_err(|_| KeystoreError::InvalidBinding)
}

const fn platform_backend() -> &'static str {
    #[cfg(windows)]
    {
        "windows-credential-manager"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-secret-service"
    }
    #[cfg(target_os = "macos")]
    {
        "macos-keychain"
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        "unsupported"
    }
}

fn binding_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(vault_path.as_os_str());
    value.push(".machine-unlock-v1.json");
    PathBuf::from(value)
}

fn lock_path_for(vault_path: &Path) -> PathBuf {
    let mut value = OsString::from(binding_path_for(vault_path).as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use super::{
        CredentialStore, KeystoreError, disable_with_store, enable_with_store, parse, read_binding,
        rotate_with_store, serialize, unlock_with_store,
    };
    use crate::crypto::MasterKey;
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct MemoryStore(BTreeMap<String, Vec<u8>>);

    impl CredentialStore for MemoryStore {
        fn set(&mut self, account: &str, secret: &[u8]) -> Result<(), KeystoreError> {
            self.0.insert(account.to_owned(), secret.to_vec());
            Ok(())
        }

        fn get(&mut self, account: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
            self.0
                .get(account)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(KeystoreError::CredentialUnavailable)
        }

        fn delete(&mut self, account: &str) -> Result<(), KeystoreError> {
            self.0.remove(account);
            Ok(())
        }
    }

    struct FailingDeleteStore {
        inner: MemoryStore,
        failures_remaining: usize,
    }

    impl CredentialStore for FailingDeleteStore {
        fn set(&mut self, account: &str, secret: &[u8]) -> Result<(), KeystoreError> {
            self.inner.set(account, secret)
        }

        fn get(&mut self, account: &str) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
            self.inner.get(account)
        }

        fn delete(&mut self, account: &str) -> Result<(), KeystoreError> {
            if self.failures_remaining > 0 {
                self.failures_remaining -= 1;
                return Err(KeystoreError::CredentialUnavailable);
            }
            self.inner.delete(account)
        }
    }

    #[test]
    fn enables_unlocks_rotates_and_disables_without_storing_master_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let vault_id = [0x11; 16];
        let master = MasterKey::new(Zeroizing::new([0x55; MasterKey::LENGTH]));
        let mut store = MemoryStore::default();

        let enabled = enable_with_store(&vault, vault_id, &master, &mut store)?;
        assert!(enabled.enabled());
        assert_eq!(enabled.generation(), 1);
        assert!(
            store
                .0
                .values()
                .all(|value| value != master.expose_secret())
        );
        let unlocked = unlock_with_store(&vault, &mut store)?;
        assert_eq!(unlocked.expose_secret(), master.expose_secret());

        let rotated = rotate_with_store(&vault, vault_id, &master, &mut store)?;
        assert_eq!(rotated.generation(), 2);
        assert_eq!(store.0.len(), 1);
        assert_eq!(
            unlock_with_store(&vault, &mut store)?.expose_secret(),
            master.expose_secret()
        );

        let disabled = disable_with_store(&vault, vault_id, &mut store)?;
        assert!(!disabled.enabled());
        assert!(store.0.is_empty());
        assert!(matches!(
            unlock_with_store(&vault, &mut store),
            Err(KeystoreError::NotEnabled)
        ));
        Ok(())
    }

    #[test]
    fn binding_is_canonical_and_tamper_evident() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let master = MasterKey::new(Zeroizing::new([0x66; MasterKey::LENGTH]));
        let mut store = MemoryStore::default();
        enable_with_store(&vault, [0x22; 16], &master, &mut store)?;
        let binding = read_binding(&vault)?;
        let bytes = serialize(&binding)?;
        assert_eq!(serialize(&parse(&bytes)?)?, bytes);

        let mut modified = binding.clone();
        modified.generation += 1;
        let tampered = serialize(&modified);
        assert!(tampered.is_err());
        Ok(())
    }

    #[test]
    fn disabled_tombstone_blocks_unlock_and_retries_failed_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let vault_id = [0x33; 16];
        let master = MasterKey::new(Zeroizing::new([0x77; MasterKey::LENGTH]));
        let mut store = FailingDeleteStore {
            inner: MemoryStore::default(),
            failures_remaining: 1,
        };
        enable_with_store(&vault, vault_id, &master, &mut store)?;

        let first = disable_with_store(&vault, vault_id, &mut store)?;
        assert!(!first.enabled());
        assert_eq!(first.cleanup_pending(), 1);
        assert!(matches!(
            unlock_with_store(&vault, &mut store),
            Err(KeystoreError::NotEnabled)
        ));

        let second = disable_with_store(&vault, vault_id, &mut store)?;
        assert!(!second.enabled());
        assert_eq!(second.cleanup_pending(), 0);
        assert!(store.inner.0.is_empty());
        assert!(matches!(
            read_binding(&vault),
            Err(KeystoreError::NotEnabled)
        ));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "writes and removes transient entries in Windows Credential Manager"]
    fn real_windows_credential_manager_supports_the_full_machine_unlock_lifecycle()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let vault = directory.path().join("vault.json");
        let vault_id = crate::crypto::generate_array()?;
        let master_bytes = crate::crypto::generate_array()?;
        let master = MasterKey::new(Zeroizing::new(master_bytes));
        let mut store = super::PlatformCredentialStore;

        let native_store = windows_native_keyring_store::Store::new()?;
        keyring_core::set_default_store(native_store);
        let probe_account = format!("{}-probe", super::account_name(vault_id, 0));
        let probe = keyring_core::Entry::new_with_modifiers(
            super::SERVICE_NAME,
            &probe_account,
            &std::collections::HashMap::from([("persistence", "local")]),
        )?;
        probe.set_secret(b"envvault-platform-probe")?;
        let probe_secret = Zeroizing::new(probe.get_secret()?);
        if probe_secret.as_slice() != b"envvault-platform-probe" {
            return Err(Box::new(KeystoreError::CredentialUnavailable));
        }
        probe.delete_credential()?;

        let lifecycle = (|| -> Result<(), KeystoreError> {
            enable_with_store(&vault, vault_id, &master, &mut store)?;
            let unlocked = unlock_with_store(&vault, &mut store)?;
            if unlocked.expose_secret() != master.expose_secret() {
                return Err(KeystoreError::InvalidBinding);
            }
            rotate_with_store(&vault, vault_id, &master, &mut store)?;
            let unlocked = unlock_with_store(&vault, &mut store)?;
            if unlocked.expose_secret() != master.expose_secret() {
                return Err(KeystoreError::InvalidBinding);
            }
            Ok(())
        })();

        let disable_result = disable_with_store(&vault, vault_id, &mut store);
        for generation in 1..=2 {
            let _ignored = store.delete(&super::account_name(vault_id, generation));
        }
        lifecycle?;
        disable_result?;
        Ok(())
    }
}
