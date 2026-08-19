use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use atomic_write_file::AtomicWriteFile;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        AuditKey, CryptoError, EncryptedEnvelope, KdfConfig, KdfLimits, KdfParams, MasterKey,
        MasterPassword, decrypt, decrypt_audit, derive_master_key, encrypt, encrypt_audit,
        generate_array, generate_secret_id,
    },
    secret::{SecretId, SecretName, SecretRecord, SecretValue},
    secure_fs,
};

use super::{
    VaultError,
    format::{
        FORMAT_VERSION, MAX_AUDIT_EVENTS, MAX_RECORDS, MAX_VAULT_FILE_BYTES, StoredAudit,
        StoredIdentity, StoredPolicy, StoredRecord, VAULT_ID_LENGTH, VaultState, parse, serialize,
    },
    payload::{decode_metadata, decode_value, encode_metadata, encode_value},
};

const KEY_CHECK_PLAINTEXT: &[u8] = b"envvault-key-check-v1";
const KEY_CHECK_AAD_DOMAIN: &[u8] = b"envvault:key-check:v1\0";
const METADATA_AAD_DOMAIN: &[u8] = b"envvault:secret-metadata:v1\0";
const VALUE_AAD_DOMAIN: &[u8] = b"envvault:secret-value:v1\0";
const POLICY_AAD_DOMAIN: &[u8] = b"envvault:policy:v1\0";
const IDENTITY_AAD_DOMAIN: &[u8] = b"envvault:identity-registry:v1\0";
const AUDIT_KEY_AAD_DOMAIN: &[u8] = b"envvault:audit-key:v1\0";
const AUDIT_EVENT_AAD_DOMAIN: &[u8] = b"envvault:audit-event:v1\0";
const MAX_POLICY_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_IDENTITY_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_AUDIT_PAYLOAD_BYTES: usize = 4 * 1024;

/// Unlocked V1 file Vault used internally by the Broker boundary.
///
/// This type is crate-private so external callers cannot bypass future Broker
/// authorization by using the storage layer directly.
pub(crate) struct FileVault {
    path: PathBuf,
    state: VaultState,
    key: MasterKey,
    audit_key: AuditKey,
}

impl FileVault {
    pub(crate) fn create(
        path: &Path,
        password: &MasterPassword,
        initial_identity_payload: &[u8],
        initial_policy_payload: &[u8],
    ) -> Result<Self, VaultError> {
        Self::create_with_params(
            path,
            password,
            KdfParams::recommended(),
            initial_identity_payload,
            initial_policy_payload,
        )
    }

    fn create_with_params(
        path: &Path,
        password: &MasterPassword,
        params: KdfParams,
        initial_identity_payload: &[u8],
        initial_policy_payload: &[u8],
    ) -> Result<Self, VaultError> {
        if initial_policy_payload.len() > MAX_POLICY_PAYLOAD_BYTES {
            return Err(VaultError::PolicyPayloadTooLarge);
        }
        if initial_identity_payload.len() > MAX_IDENTITY_PAYLOAD_BYTES {
            return Err(VaultError::IdentityPayloadTooLarge);
        }
        let path = resolve_target(path)?;
        let lock_path = lock_path_for(&path);
        let _lock = acquire_lock(&lock_path)?;
        ensure_leaf_is_not_symlink(&path)?;
        if path.exists() {
            return Err(VaultError::AlreadyExists);
        }

        let vault_id = generate_array::<VAULT_ID_LENGTH>().map_err(map_crypto_error)?;
        let salt = generate_array::<{ KdfConfig::SALT_LENGTH }>().map_err(map_crypto_error)?;
        let kdf = KdfConfig::new(params, salt);
        let key =
            derive_master_key(password, kdf, KdfLimits::default()).map_err(map_crypto_error)?;
        let key_check = encrypt(&key, KEY_CHECK_PLAINTEXT, &key_check_aad(vault_id, kdf))
            .map_err(map_crypto_error)?;
        let identity_generation = 1;
        let identity_envelope = encrypt(
            &key,
            initial_identity_payload,
            &identity_aad(vault_id, identity_generation),
        )
        .map_err(map_crypto_error)?;
        let policy_generation = 1;
        let policy_envelope = encrypt(
            &key,
            initial_policy_payload,
            &policy_aad(vault_id, policy_generation),
        )
        .map_err(map_crypto_error)?;
        let audit_key_bytes = generate_array::<{ AuditKey::LENGTH }>().map_err(map_crypto_error)?;
        let initial_audit_head = [0_u8; EncryptedEnvelope::TAG_LENGTH];
        let audit_key_envelope = encrypt(
            &key,
            &audit_key_bytes,
            &audit_key_aad(vault_id, 0, initial_audit_head),
        )
        .map_err(map_crypto_error)?;
        let audit_key = AuditKey::new(Zeroizing::new(audit_key_bytes));
        let state = VaultState {
            generation: 1,
            vault_id,
            kdf,
            key_check,
            identity: StoredIdentity {
                generation: identity_generation,
                envelope: identity_envelope,
            },
            policy: StoredPolicy {
                generation: policy_generation,
                envelope: policy_envelope,
            },
            audit: StoredAudit {
                key_envelope: audit_key_envelope,
                head_authenticator: initial_audit_head,
                events: Vec::new(),
            },
            records: BTreeMap::new(),
        };
        write_state_atomically(&path, &state)?;

        Ok(Self {
            path,
            state,
            key,
            audit_key,
        })
    }

    pub(crate) fn open(path: &Path, password: &MasterPassword) -> Result<Self, VaultError> {
        let path = resolve_target(path)?;
        let lock_path = lock_path_for(&path);
        let _lock = acquire_lock(&lock_path)?;
        ensure_leaf_is_regular_file(&path)?;
        let state = read_state(&path)?;
        let key = derive_master_key(password, state.kdf, KdfLimits::default())
            .map_err(|_| VaultError::UnlockFailed)?;
        Self::open_unlocked(path, state, key)
    }

    pub(crate) fn open_with_master_key(path: &Path, key: MasterKey) -> Result<Self, VaultError> {
        let path = resolve_target(path)?;
        let lock_path = lock_path_for(&path);
        let _lock = acquire_lock(&lock_path)?;
        ensure_leaf_is_regular_file(&path)?;
        let state = read_state(&path)?;
        Self::open_unlocked(path, state, key)
    }

    fn open_unlocked(path: PathBuf, state: VaultState, key: MasterKey) -> Result<Self, VaultError> {
        let plaintext = decrypt(
            &key,
            &state.key_check,
            &key_check_aad(state.vault_id, state.kdf),
        )
        .map_err(|_| VaultError::UnlockFailed)?;
        if plaintext.as_slice() != KEY_CHECK_PLAINTEXT {
            return Err(VaultError::UnlockFailed);
        }

        let audit_key_plaintext = decrypt(
            &key,
            &state.audit.key_envelope,
            &audit_key_aad(
                state.vault_id,
                u64::try_from(state.audit.events.len()).map_err(|_| VaultError::CorruptedAudit)?,
                state.audit.head_authenticator,
            ),
        )
        .map_err(|_| VaultError::CorruptedAudit)?;
        let audit_key_bytes: [u8; AuditKey::LENGTH] = audit_key_plaintext
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::CorruptedAudit)?;
        let audit_key = AuditKey::new(Zeroizing::new(audit_key_bytes));
        verify_audit_chain(&state, &audit_key)?;

        Ok(Self {
            path,
            state,
            key,
            audit_key,
        })
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.state.generation
    }

    pub(crate) const fn vault_id(&self) -> [u8; VAULT_ID_LENGTH] {
        self.state.vault_id
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn master_key(&self) -> &MasterKey {
        &self.key
    }

    pub(crate) const fn policy_generation(&self) -> u64 {
        self.state.policy.generation
    }

    pub(crate) const fn identity_generation(&self) -> u64 {
        self.state.identity.generation
    }

    pub(crate) fn identity_payload(&self) -> Result<(u64, Zeroizing<Vec<u8>>), VaultError> {
        let generation = self.state.identity.generation;
        let plaintext = decrypt(
            &self.key,
            &self.state.identity.envelope,
            &identity_aad(self.state.vault_id, generation),
        )
        .map_err(|_| VaultError::CorruptedIdentity)?;
        Ok((generation, plaintext))
    }

    pub(crate) fn replace_identity_payload(
        &mut self,
        expected_generation: u64,
        payload: &[u8],
    ) -> Result<u64, VaultError> {
        if payload.len() > MAX_IDENTITY_PAYLOAD_BYTES {
            return Err(VaultError::IdentityPayloadTooLarge);
        }
        if self.state.identity.generation != expected_generation {
            return Err(VaultError::IdentityGenerationMismatch);
        }
        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let envelope = encrypt(
            &self.key,
            payload,
            &identity_aad(self.state.vault_id, new_generation),
        )
        .map_err(map_crypto_error)?;
        let mut candidate = self.state.clone();
        candidate.identity = StoredIdentity {
            generation: new_generation,
            envelope,
        };
        self.commit(candidate)?;
        Ok(new_generation)
    }

    pub(crate) fn audit_payloads(&self) -> Result<Vec<Zeroizing<Vec<u8>>>, VaultError> {
        decrypt_audit_chain(&self.state, &self.audit_key)
    }

    pub(crate) fn append_audit_payload(&mut self, payload: &[u8]) -> Result<(), VaultError> {
        if payload.len() > MAX_AUDIT_PAYLOAD_BYTES {
            return Err(VaultError::AuditPayloadTooLarge);
        }
        if self.state.audit.events.len() >= MAX_AUDIT_EVENTS {
            return Err(VaultError::ResourceLimitExceeded);
        }
        let sequence = u64::try_from(self.state.audit.events.len())
            .map_err(|_| VaultError::ResourceLimitExceeded)?
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let previous = self.state.audit.head_authenticator;
        let envelope = encrypt_audit(
            &self.audit_key,
            payload,
            &audit_event_aad(self.state.vault_id, sequence, previous),
        )
        .map_err(map_crypto_error)?;
        let new_head = envelope_authenticator(&envelope)?;
        let audit_key_envelope = encrypt(
            &self.key,
            self.audit_key.expose_secret(),
            &audit_key_aad(self.state.vault_id, sequence, new_head),
        )
        .map_err(map_crypto_error)?;
        let mut candidate = self.state.clone();
        candidate.audit.events.push(envelope);
        candidate.audit.head_authenticator = new_head;
        candidate.audit.key_envelope = audit_key_envelope;
        self.commit(candidate)
    }

    pub(crate) fn policy_payload(&self) -> Result<(u64, zeroize::Zeroizing<Vec<u8>>), VaultError> {
        let generation = self.state.policy.generation;
        let plaintext = decrypt(
            &self.key,
            &self.state.policy.envelope,
            &policy_aad(self.state.vault_id, generation),
        )
        .map_err(|_| VaultError::CorruptedPolicy)?;
        Ok((generation, plaintext))
    }

    pub(crate) fn replace_policy_payload(
        &mut self,
        expected_generation: u64,
        payload: &[u8],
    ) -> Result<u64, VaultError> {
        if payload.len() > MAX_POLICY_PAYLOAD_BYTES {
            return Err(VaultError::PolicyPayloadTooLarge);
        }
        if self.state.policy.generation != expected_generation {
            return Err(VaultError::PolicyGenerationMismatch);
        }
        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let envelope = encrypt(
            &self.key,
            payload,
            &policy_aad(self.state.vault_id, new_generation),
        )
        .map_err(map_crypto_error)?;
        let mut candidate = self.state.clone();
        candidate.policy = StoredPolicy {
            generation: new_generation,
            envelope,
        };
        self.commit(candidate)?;
        Ok(new_generation)
    }

    pub(crate) fn create_secret_and_replace_policy(
        &mut self,
        secret_id: SecretId,
        name: SecretName,
        value: &SecretValue,
        expected_policy_generation: u64,
        policy_payload: &[u8],
    ) -> Result<(SecretRecord, u64), VaultError> {
        if policy_payload.len() > MAX_POLICY_PAYLOAD_BYTES {
            return Err(VaultError::PolicyPayloadTooLarge);
        }
        if self.state.policy.generation != expected_policy_generation {
            return Err(VaultError::PolicyGenerationMismatch);
        }
        if self.state.records.len() >= MAX_RECORDS {
            return Err(VaultError::ResourceLimitExceeded);
        }
        if self.state.records.contains_key(&secret_id) {
            return Err(VaultError::AlreadyExists);
        }
        self.ensure_name_is_available(&name, None)?;

        let new_policy_generation = expected_policy_generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let policy_envelope = encrypt(
            &self.key,
            policy_payload,
            &policy_aad(self.state.vault_id, new_policy_generation),
        )
        .map_err(map_crypto_error)?;
        let stored = self.encrypt_record(secret_id, 1, &name, value)?;
        let mut candidate = self.state.clone();
        candidate.records.insert(secret_id, stored);
        candidate.policy = StoredPolicy {
            generation: new_policy_generation,
            envelope: policy_envelope,
        };
        self.commit(candidate)?;
        Ok((SecretRecord::new(secret_id, name), new_policy_generation))
    }

    pub(crate) fn upsert_secrets_and_replace_policy(
        &mut self,
        upserts: Vec<(SecretId, SecretName, SecretValue)>,
        policy_update: Option<(u64, &[u8])>,
    ) -> Result<(Vec<SecretRecord>, Option<u64>), VaultError> {
        let mut ids = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        let mut new_count = 0_usize;
        for (secret_id, name, _) in &upserts {
            if !ids.insert(*secret_id) || !names.insert(name.clone()) {
                return Err(VaultError::AlreadyExists);
            }
            self.ensure_name_is_available(name, Some(*secret_id))?;
            if !self.state.records.contains_key(secret_id) {
                new_count = new_count
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)?;
            }
        }
        if self
            .state
            .records
            .len()
            .checked_add(new_count)
            .ok_or(VaultError::ResourceLimitExceeded)?
            > MAX_RECORDS
        {
            return Err(VaultError::ResourceLimitExceeded);
        }

        let policy = if let Some((expected_generation, payload)) = policy_update {
            if payload.len() > MAX_POLICY_PAYLOAD_BYTES {
                return Err(VaultError::PolicyPayloadTooLarge);
            }
            if self.state.policy.generation != expected_generation {
                return Err(VaultError::PolicyGenerationMismatch);
            }
            let generation = expected_generation
                .checked_add(1)
                .ok_or(VaultError::ResourceLimitExceeded)?;
            let envelope = encrypt(
                &self.key,
                payload,
                &policy_aad(self.state.vault_id, generation),
            )
            .map_err(map_crypto_error)?;
            Some(StoredPolicy {
                generation,
                envelope,
            })
        } else {
            None
        };

        let mut prepared = Vec::with_capacity(upserts.len());
        for (secret_id, name, value) in upserts {
            let revision = self.state.records.get(&secret_id).map_or(Ok(1), |stored| {
                stored
                    .revision
                    .checked_add(1)
                    .ok_or(VaultError::ResourceLimitExceeded)
            })?;
            let stored = self.encrypt_record(secret_id, revision, &name, &value)?;
            prepared.push((SecretRecord::new(secret_id, name), stored));
        }

        let mut candidate = self.state.clone();
        for (record, stored) in &prepared {
            candidate.records.insert(record.id(), stored.clone());
        }
        let policy_generation = policy.as_ref().map(|value| value.generation);
        if let Some(policy) = policy {
            candidate.policy = policy;
        }
        self.commit(candidate)?;
        Ok((
            prepared.into_iter().map(|(record, _)| record).collect(),
            policy_generation,
        ))
    }

    pub(crate) fn records(&self) -> Result<Vec<SecretRecord>, VaultError> {
        self.state
            .records
            .iter()
            .map(|(secret_id, stored)| self.decrypt_record(*secret_id, stored))
            .collect()
    }

    pub(crate) fn secret_ids(&self) -> Vec<SecretId> {
        self.state.records.keys().copied().collect()
    }

    pub(crate) fn contains_secret(&self, secret_id: SecretId) -> bool {
        self.state.records.contains_key(&secret_id)
    }

    pub(crate) fn record(&self, secret_id: SecretId) -> Result<SecretRecord, VaultError> {
        let stored = self
            .state
            .records
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        self.decrypt_record(secret_id, stored)
    }

    pub(crate) fn read_secret(&self, secret_id: SecretId) -> Result<SecretValue, VaultError> {
        let stored = self
            .state
            .records
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        let aad = record_aad(
            VALUE_AAD_DOMAIN,
            self.state.vault_id,
            secret_id,
            stored.revision,
        );
        let plaintext = decrypt(&self.key, &stored.value_envelope, &aad)
            .map_err(|_| VaultError::CorruptedSecret(secret_id))?;
        decode_value(&plaintext).map_err(|_| VaultError::CorruptedSecret(secret_id))
    }

    pub(crate) fn create_secret(
        &mut self,
        name: SecretName,
        value: &SecretValue,
    ) -> Result<SecretRecord, VaultError> {
        if self.state.records.len() >= MAX_RECORDS {
            return Err(VaultError::ResourceLimitExceeded);
        }
        self.ensure_name_is_available(&name, None)?;
        let secret_id = self.generate_unused_secret_id()?;
        let revision = 1;
        let stored = self.encrypt_record(secret_id, revision, &name, value)?;
        let mut candidate = self.state.clone();
        candidate.records.insert(secret_id, stored);
        self.commit(candidate)?;
        Ok(SecretRecord::new(secret_id, name))
    }

    pub(crate) fn replace_secret(
        &mut self,
        secret_id: SecretId,
        name: SecretName,
        value: &SecretValue,
    ) -> Result<SecretRecord, VaultError> {
        let previous = self
            .state
            .records
            .get(&secret_id)
            .ok_or(VaultError::NotFound)?;
        self.ensure_name_is_available(&name, Some(secret_id))?;
        let revision = previous
            .revision
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        let stored = self.encrypt_record(secret_id, revision, &name, value)?;
        let mut candidate = self.state.clone();
        candidate.records.insert(secret_id, stored);
        self.commit(candidate)?;
        Ok(SecretRecord::new(secret_id, name))
    }

    pub(crate) fn remove_secret(&mut self, secret_id: SecretId) -> Result<(), VaultError> {
        if !self.state.records.contains_key(&secret_id) {
            return Err(VaultError::NotFound);
        }
        let mut candidate = self.state.clone();
        candidate.records.remove(&secret_id);
        self.commit(candidate)
    }

    fn decrypt_record(
        &self,
        secret_id: SecretId,
        stored: &StoredRecord,
    ) -> Result<SecretRecord, VaultError> {
        let aad = record_aad(
            METADATA_AAD_DOMAIN,
            self.state.vault_id,
            secret_id,
            stored.revision,
        );
        let plaintext = decrypt(&self.key, &stored.metadata_envelope, &aad)
            .map_err(|_| VaultError::CorruptedSecret(secret_id))?;
        let name =
            decode_metadata(&plaintext).map_err(|_| VaultError::CorruptedSecret(secret_id))?;
        Ok(SecretRecord::new(secret_id, name))
    }

    pub(crate) fn change_password(
        &mut self,
        new_password: &MasterPassword,
    ) -> Result<(), VaultError> {
        let salt = generate_array::<{ KdfConfig::SALT_LENGTH }>().map_err(map_crypto_error)?;
        let kdf = KdfConfig::new(KdfParams::recommended(), salt);
        let new_key =
            derive_master_key(new_password, kdf, KdfLimits::default()).map_err(map_crypto_error)?;
        let mut candidate = self.state.clone();
        candidate.kdf = kdf;
        candidate.key_check = encrypt(
            &new_key,
            KEY_CHECK_PLAINTEXT,
            &key_check_aad(self.state.vault_id, kdf),
        )
        .map_err(map_crypto_error)?;

        let (identity_generation, identity_payload) = self.identity_payload()?;
        candidate.identity.envelope = encrypt(
            &new_key,
            &identity_payload,
            &identity_aad(self.state.vault_id, identity_generation),
        )
        .map_err(map_crypto_error)?;

        let (policy_generation, policy_payload) = self.policy_payload()?;
        candidate.policy.envelope = encrypt(
            &new_key,
            &policy_payload,
            &policy_aad(self.state.vault_id, policy_generation),
        )
        .map_err(map_crypto_error)?;

        let event_count =
            u64::try_from(self.state.audit.events.len()).map_err(|_| VaultError::CorruptedAudit)?;
        candidate.audit.key_envelope = encrypt(
            &new_key,
            self.audit_key.expose_secret(),
            &audit_key_aad(
                self.state.vault_id,
                event_count,
                self.state.audit.head_authenticator,
            ),
        )
        .map_err(map_crypto_error)?;

        let mut records = BTreeMap::new();
        for secret_id in self.secret_ids() {
            let stored = self
                .state
                .records
                .get(&secret_id)
                .ok_or(VaultError::NotFound)?;
            let record = self.decrypt_record(secret_id, stored)?;
            let value = self.read_secret(secret_id)?;
            records.insert(
                secret_id,
                self.encrypt_record_with_key(
                    &new_key,
                    secret_id,
                    stored.revision,
                    record.name(),
                    &value,
                )?,
            );
        }
        candidate.records = records;
        self.commit(candidate)?;
        self.key = new_key;
        Ok(())
    }

    fn encrypt_record(
        &self,
        secret_id: SecretId,
        revision: u64,
        name: &SecretName,
        value: &SecretValue,
    ) -> Result<StoredRecord, VaultError> {
        self.encrypt_record_with_key(&self.key, secret_id, revision, name, value)
    }

    fn encrypt_record_with_key(
        &self,
        key: &MasterKey,
        secret_id: SecretId,
        revision: u64,
        name: &SecretName,
        value: &SecretValue,
    ) -> Result<StoredRecord, VaultError> {
        let metadata_payload = encode_metadata(name)?;
        let value_payload = encode_value(value)?;
        let metadata_envelope = encrypt(
            key,
            &metadata_payload,
            &record_aad(
                METADATA_AAD_DOMAIN,
                self.state.vault_id,
                secret_id,
                revision,
            ),
        )
        .map_err(map_crypto_error)?;
        let value_envelope = encrypt(
            key,
            &value_payload,
            &record_aad(VALUE_AAD_DOMAIN, self.state.vault_id, secret_id, revision),
        )
        .map_err(map_crypto_error)?;
        Ok(StoredRecord {
            revision,
            metadata_envelope,
            value_envelope,
        })
    }

    fn ensure_name_is_available(
        &self,
        name: &SecretName,
        except: Option<SecretId>,
    ) -> Result<(), VaultError> {
        for record in self.records()? {
            if Some(record.id()) != except && record.name() == name {
                return Err(VaultError::AlreadyExists);
            }
        }
        Ok(())
    }

    fn generate_unused_secret_id(&self) -> Result<SecretId, VaultError> {
        for _ in 0..16 {
            let id = generate_secret_id().map_err(map_crypto_error)?;
            if !self.state.records.contains_key(&id) {
                return Ok(id);
            }
        }
        Err(VaultError::RandomSourceUnavailable)
    }

    fn commit(&mut self, mut candidate: VaultState) -> Result<(), VaultError> {
        let lock_path = lock_path_for(&self.path);
        let _lock = acquire_lock(&lock_path)?;
        ensure_leaf_is_regular_file(&self.path)?;
        let current = read_state(&self.path)?;
        if current != self.state {
            return Err(VaultError::ConcurrentModification);
        }
        candidate.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or(VaultError::ResourceLimitExceeded)?;
        write_state_atomically(&self.path, &candidate)?;
        self.state = candidate;
        Ok(())
    }
}

fn map_crypto_error(error: CryptoError) -> VaultError {
    match error {
        CryptoError::RandomSourceUnavailable => VaultError::RandomSourceUnavailable,
        CryptoError::InvalidKdfParameters => VaultError::ResourceLimitExceeded,
        CryptoError::KeyDerivationFailed => VaultError::KeyDerivationFailed,
        CryptoError::EncryptionFailed => VaultError::EncryptionFailed,
        CryptoError::AuthenticationFailed => VaultError::UnlockFailed,
    }
}

fn key_check_aad(vault_id: [u8; VAULT_ID_LENGTH], kdf: KdfConfig) -> Vec<u8> {
    let mut aad = Vec::with_capacity(KEY_CHECK_AAD_DOMAIN.len() + 52);
    aad.extend_from_slice(KEY_CHECK_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&KdfParams::VERSION.to_be_bytes());
    aad.extend_from_slice(&kdf.params.memory_kib.to_be_bytes());
    aad.extend_from_slice(&kdf.params.iterations.to_be_bytes());
    aad.extend_from_slice(&kdf.params.parallelism.to_be_bytes());
    aad.extend_from_slice(&kdf.salt);
    aad
}

fn record_aad(
    domain: &[u8],
    vault_id: [u8; VAULT_ID_LENGTH],
    secret_id: SecretId,
    revision: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + 44);
    aad.extend_from_slice(domain);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(secret_id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    aad
}

fn policy_aad(vault_id: [u8; VAULT_ID_LENGTH], generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(POLICY_AAD_DOMAIN.len() + 28);
    aad.extend_from_slice(POLICY_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn identity_aad(vault_id: [u8; VAULT_ID_LENGTH], generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(IDENTITY_AAD_DOMAIN.len() + 28);
    aad.extend_from_slice(IDENTITY_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad
}

fn audit_key_aad(
    vault_id: [u8; VAULT_ID_LENGTH],
    event_count: u64,
    head_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AUDIT_KEY_AAD_DOMAIN.len() + 44);
    aad.extend_from_slice(AUDIT_KEY_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&event_count.to_be_bytes());
    aad.extend_from_slice(&head_authenticator);
    aad
}

fn audit_event_aad(
    vault_id: [u8; VAULT_ID_LENGTH],
    sequence: u64,
    previous_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AUDIT_EVENT_AAD_DOMAIN.len() + 44);
    aad.extend_from_slice(AUDIT_EVENT_AAD_DOMAIN);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(&vault_id);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(&previous_authenticator);
    aad
}

fn previous_audit_authenticator(
    events: &[EncryptedEnvelope],
) -> Result<[u8; EncryptedEnvelope::TAG_LENGTH], VaultError> {
    let Some(previous) = events.last() else {
        return Ok([0_u8; EncryptedEnvelope::TAG_LENGTH]);
    };
    let start = previous
        .ciphertext
        .len()
        .checked_sub(EncryptedEnvelope::TAG_LENGTH)
        .ok_or(VaultError::CorruptedAudit)?;
    previous.ciphertext[start..]
        .try_into()
        .map_err(|_| VaultError::CorruptedAudit)
}

fn envelope_authenticator(
    envelope: &EncryptedEnvelope,
) -> Result<[u8; EncryptedEnvelope::TAG_LENGTH], VaultError> {
    previous_audit_authenticator(std::slice::from_ref(envelope))
}

fn verify_audit_chain(state: &VaultState, key: &AuditKey) -> Result<(), VaultError> {
    decrypt_audit_chain(state, key).map(|_| ())
}

fn decrypt_audit_chain(
    state: &VaultState,
    key: &AuditKey,
) -> Result<Vec<Zeroizing<Vec<u8>>>, VaultError> {
    let mut plaintexts = Vec::with_capacity(state.audit.events.len());
    let mut previous = [0_u8; EncryptedEnvelope::TAG_LENGTH];
    for (index, event) in state.audit.events.iter().enumerate() {
        let sequence = u64::try_from(index)
            .map_err(|_| VaultError::CorruptedAudit)?
            .checked_add(1)
            .ok_or(VaultError::CorruptedAudit)?;
        let plaintext = decrypt_audit(
            key,
            event,
            &audit_event_aad(state.vault_id, sequence, previous),
        )
        .map_err(|_| VaultError::CorruptedAudit)?;
        if plaintext.len() > MAX_AUDIT_PAYLOAD_BYTES {
            return Err(VaultError::CorruptedAudit);
        }
        plaintexts.push(plaintext);
        previous = envelope_authenticator(event)?;
    }
    if previous != state.audit.head_authenticator {
        return Err(VaultError::CorruptedAudit);
    }
    Ok(plaintexts)
}

fn resolve_target(path: &Path) -> Result<PathBuf, VaultError> {
    let file_name = path.file_name().ok_or(VaultError::UnsafePath)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize().map_err(VaultError::from)?;
    Ok(parent.join(file_name))
}

fn lock_path_for(path: &Path) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(".lock");
    PathBuf::from(value)
}

fn acquire_lock(path: &Path) -> Result<File, VaultError> {
    let file = secure_fs::open_lock(path).map_err(map_secure_io)?;
    file.lock()?;
    Ok(file)
}

fn ensure_leaf_is_not_symlink(path: &Path) -> Result<(), VaultError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(VaultError::UnsafePath),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn ensure_leaf_is_regular_file(path: &Path) -> Result<(), VaultError> {
    ensure_leaf_is_not_symlink(path)?;
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotFound
        } else {
            error.into()
        }
    })?;
    if !metadata.is_file() {
        return Err(VaultError::UnsafePath);
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<VaultState, VaultError> {
    let file = secure_fs::open_existing(path).map_err(map_secure_io)?;
    let length = file.metadata()?.len();
    if length > MAX_VAULT_FILE_BYTES {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let capacity = usize::try_from(length).map_err(|_| VaultError::ResourceLimitExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_VAULT_FILE_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    parse(&bytes)
}

fn write_state_atomically(path: &Path, state: &VaultState) -> Result<(), VaultError> {
    secure_fs::ensure_safe_path(path, true).map_err(map_secure_io)?;
    let bytes = serialize(state)?;
    let mut file = AtomicWriteFile::open(path)?;

    #[cfg(unix)]
    secure_fs::protect_open_file(file.as_file_mut()).map_err(map_secure_io)?;

    file.write_all(&bytes)?;
    file.sync_all()?;
    file.commit()?;
    secure_fs::protect_existing(path).map_err(map_secure_io)?;
    Ok(())
}

fn map_secure_io(error: std::io::Error) -> VaultError {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        VaultError::UnsafePath
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::Value;
    use tempfile::tempdir;

    use super::FileVault;
    use crate::{
        crypto::{KdfParams, MasterPassword},
        secret::{SecretId, SecretName, SecretValue},
        vault::VaultError,
    };

    fn test_params() -> KdfParams {
        KdfParams {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        }
    }

    fn password() -> MasterPassword {
        MasterPassword::new(b"correct horse test battery".to_vec())
    }

    fn create_test_vault(path: &Path) -> Result<FileVault, VaultError> {
        FileVault::create_with_params(
            path,
            &password(),
            test_params(),
            b"test-identity-registry-v1",
            b"test-policy-v1",
        )
    }

    #[test]
    fn persists_independent_secret_records_without_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let database = vault.create_secret(
            SecretName::new("DATABASE_URL")?,
            &SecretValue::new(b"postgres://test-only".to_vec()),
        )?;
        let token = vault.create_secret(
            SecretName::new("OPENAI_API_KEY")?,
            &SecretValue::new(b"sk-test-not-real".to_vec()),
        )?;

        let bytes = fs::read(&path)?;
        assert!(
            !bytes
                .windows("DATABASE_URL".len())
                .any(|w| w == b"DATABASE_URL")
        );
        assert!(
            !bytes
                .windows("postgres://test-only".len())
                .any(|w| w == b"postgres://test-only")
        );

        drop(vault);
        let reopened = FileVault::open(&path, &password())?;
        assert_eq!(reopened.records()?.len(), 2);
        assert_eq!(
            reopened.read_secret(database.id())?.expose_secret(),
            b"postgres://test-only"
        );
        assert_eq!(
            reopened.read_secret(token.id())?.expose_secret(),
            b"sk-test-not-real"
        );
        Ok(())
    }

    #[test]
    fn rejects_an_incorrect_password() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        drop(create_test_vault(&path)?);
        let wrong = MasterPassword::new(b"incorrect test password".to_vec());

        assert!(matches!(
            FileVault::open(&path, &wrong),
            Err(VaultError::UnlockFailed)
        ));
        Ok(())
    }

    #[test]
    fn change_password_keeps_secrets_and_rejects_the_old_password()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let record = vault.create_secret(
            SecretName::new("DATABASE_URL")?,
            &SecretValue::new(b"postgres://password-change".to_vec()),
        )?;
        let new_password = MasterPassword::new(b"replacement-master-password".to_vec());
        vault.change_password(&new_password)?;
        drop(vault);
        assert!(matches!(
            FileVault::open(&path, &password()),
            Err(VaultError::UnlockFailed)
        ));
        let reopened = FileVault::open(&path, &new_password)?;
        assert_eq!(
            reopened.read_secret(record.id())?.expose_secret(),
            b"postgres://password-change"
        );
        Ok(())
    }

    #[test]
    fn detects_ciphertext_tampering_per_secret() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let record = vault.create_secret(
            SecretName::new("JWT_SECRET")?,
            &SecretValue::new(b"test-only-jwt".to_vec()),
        )?;
        drop(vault);

        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let ciphertext = document
            .pointer_mut("/records/0/value_envelope/ciphertext")
            .and_then(|value| value.as_str())
            .ok_or("missing test ciphertext")?
            .to_owned();
        let mut bytes = ciphertext.into_bytes();
        let first = bytes.first_mut().ok_or("empty test ciphertext")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        let modified = String::from_utf8(bytes)?;
        *document
            .pointer_mut("/records/0/value_envelope/ciphertext")
            .ok_or("missing test ciphertext")? = Value::String(modified);
        fs::write(&path, serde_json::to_vec_pretty(&document)?)?;

        let reopened = FileVault::open(&path, &password())?;
        assert!(matches!(
            reopened.read_secret(record.id()),
            Err(VaultError::CorruptedSecret(id)) if id == record.id()
        ));
        Ok(())
    }

    #[test]
    fn prevents_lost_updates_between_open_instances() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        drop(create_test_vault(&path)?);
        let mut first = FileVault::open(&path, &password())?;
        let mut stale = FileVault::open(&path, &password())?;
        first.create_secret(
            SecretName::new("DATABASE_URL")?,
            &SecretValue::new(b"test-database".to_vec()),
        )?;

        let stale_result = stale.create_secret(
            SecretName::new("JWT_SECRET")?,
            &SecretValue::new(b"test-jwt".to_vec()),
        );
        assert!(matches!(
            stale_result,
            Err(VaultError::ConcurrentModification)
        ));

        let reopened = FileVault::open(&path, &password())?;
        let records = reopened.records()?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name().as_str(), "DATABASE_URL");
        Ok(())
    }

    #[test]
    fn replace_and_remove_advance_generation() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let created = vault.create_secret(
            SecretName::new("TOKEN")?,
            &SecretValue::new(b"test-one".to_vec()),
        )?;
        assert_eq!(vault.generation(), 2);

        vault.replace_secret(
            created.id(),
            SecretName::new("TOKEN")?,
            &SecretValue::new(b"test-two".to_vec()),
        )?;
        assert_eq!(vault.generation(), 3);
        assert_eq!(vault.record(created.id())?.name().as_str(), "TOKEN");
        assert_eq!(
            vault.read_secret(created.id())?.expose_secret(),
            b"test-two"
        );

        vault.remove_secret(created.id())?;
        assert_eq!(vault.generation(), 4);
        assert!(matches!(
            vault.record(created.id()),
            Err(VaultError::NotFound)
        ));
        Ok(())
    }

    #[test]
    fn secret_and_policy_creation_commit_together() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let secret_id = SecretId::from_bytes([0x45; SecretId::BYTE_LENGTH]);

        let (record, policy_generation) = vault.create_secret_and_replace_policy(
            secret_id,
            SecretName::new("ATOMIC_TOKEN")?,
            &SecretValue::new(b"atomic-value".to_vec()),
            1,
            b"test-policy-v2",
        )?;
        assert_eq!(record.id(), secret_id);
        assert_eq!(policy_generation, 2);
        assert_eq!(vault.policy_payload()?.1.as_slice(), b"test-policy-v2");
        assert_eq!(
            vault.read_secret(secret_id)?.expose_secret(),
            b"atomic-value"
        );

        let stale_id = SecretId::from_bytes([0x46; SecretId::BYTE_LENGTH]);
        assert!(matches!(
            vault.create_secret_and_replace_policy(
                stale_id,
                SecretName::new("STALE_TOKEN")?,
                &SecretValue::new(b"must-not-commit".to_vec()),
                1,
                b"stale-policy",
            ),
            Err(VaultError::PolicyGenerationMismatch)
        ));
        assert!(!vault.contains_secret(stale_id));
        Ok(())
    }

    #[test]
    fn batch_upsert_and_policy_update_commit_together() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let existing = vault.create_secret(
            SecretName::new("EXISTING")?,
            &SecretValue::new(b"old-value".to_vec()),
        )?;
        let new_id = SecretId::from_bytes([0x47; SecretId::BYTE_LENGTH]);

        let (records, generation) = vault.upsert_secrets_and_replace_policy(
            vec![
                (
                    existing.id(),
                    SecretName::new("EXISTING")?,
                    SecretValue::new(b"new-value".to_vec()),
                ),
                (
                    new_id,
                    SecretName::new("NEW_VALUE")?,
                    SecretValue::new(b"created-value".to_vec()),
                ),
            ],
            Some((1, b"batch-policy-v2")),
        )?;
        assert_eq!(records.len(), 2);
        assert_eq!(generation, Some(2));
        assert_eq!(
            vault.read_secret(existing.id())?.expose_secret(),
            b"new-value"
        );
        assert_eq!(vault.read_secret(new_id)?.expose_secret(), b"created-value");

        let stale_id = SecretId::from_bytes([0x48; SecretId::BYTE_LENGTH]);
        assert!(matches!(
            vault.upsert_secrets_and_replace_policy(
                vec![(
                    stale_id,
                    SecretName::new("STALE_BATCH")?,
                    SecretValue::new(b"must-not-commit".to_vec()),
                )],
                Some((1, b"stale-batch-policy")),
            ),
            Err(VaultError::PolicyGenerationMismatch)
        ));
        assert!(!vault.contains_secret(stale_id));
        Ok(())
    }

    #[test]
    fn policy_payload_is_authenticated_and_not_plaintext() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        let (generation, payload) = vault.policy_payload()?;
        assert_eq!(generation, 1);
        assert_eq!(payload.as_slice(), b"test-policy-v1");
        assert!(
            !fs::read(&path)?
                .windows(14)
                .any(|window| window == b"test-policy-v1")
        );

        let new_generation = vault.replace_policy_payload(generation, b"test-policy-v2")?;
        assert_eq!(new_generation, 2);
        assert!(matches!(
            vault.replace_policy_payload(generation, b"stale-policy"),
            Err(VaultError::PolicyGenerationMismatch)
        ));
        drop(vault);

        let reopened = FileVault::open(&path, &password())?;
        let (generation, payload) = reopened.policy_payload()?;
        assert_eq!(generation, 2);
        assert_eq!(payload.as_slice(), b"test-policy-v2");
        Ok(())
    }

    #[test]
    fn detects_policy_ciphertext_tampering() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        drop(create_test_vault(&path)?);

        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let ciphertext = document
            .pointer_mut("/policy/envelope/ciphertext")
            .and_then(|value| value.as_str())
            .ok_or("missing test policy ciphertext")?
            .to_owned();
        let mut bytes = ciphertext.into_bytes();
        let first = bytes.first_mut().ok_or("empty test policy ciphertext")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        *document
            .pointer_mut("/policy/envelope/ciphertext")
            .ok_or("missing test policy ciphertext")? = Value::String(String::from_utf8(bytes)?);
        fs::write(&path, serde_json::to_vec_pretty(&document)?)?;

        let reopened = FileVault::open(&path, &password())?;
        assert!(matches!(
            reopened.policy_payload(),
            Err(VaultError::CorruptedPolicy)
        ));
        Ok(())
    }

    #[test]
    fn identity_and_audit_payloads_are_authenticated_and_not_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;

        let (identity_generation, identity_payload) = vault.identity_payload()?;
        assert_eq!(identity_generation, 1);
        assert_eq!(identity_payload.as_slice(), b"test-identity-registry-v1");
        assert_eq!(
            vault.replace_identity_payload(1, b"test-identity-registry-v2")?,
            2
        );
        assert!(matches!(
            vault.replace_identity_payload(1, b"stale-test-identity"),
            Err(VaultError::IdentityGenerationMismatch)
        ));
        vault.append_audit_payload(b"test-audit-event-v1")?;
        assert_eq!(vault.audit_payloads()?.len(), 1);
        drop(vault);

        let bytes = fs::read(&path)?;
        assert!(
            !bytes
                .windows(b"test-identity-registry-v1".len())
                .any(|window| window == b"test-identity-registry-v1")
        );
        assert!(
            !bytes
                .windows(b"test-audit-event-v1".len())
                .any(|window| window == b"test-audit-event-v1")
        );
        let reopened = FileVault::open(&path, &password())?;
        let (identity_generation, identity_payload) = reopened.identity_payload()?;
        assert_eq!(identity_generation, 2);
        assert_eq!(identity_payload.as_slice(), b"test-identity-registry-v2");
        assert_eq!(
            reopened.audit_payloads()?[0].as_slice(),
            b"test-audit-event-v1"
        );
        Ok(())
    }

    #[test]
    fn detects_audit_chain_tampering_on_open() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        vault.append_audit_payload(b"first-test-event")?;
        vault.append_audit_payload(b"second-test-event")?;
        drop(vault);

        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let ciphertext = document
            .pointer_mut("/audit/events/0/ciphertext")
            .and_then(|value| value.as_str())
            .ok_or("missing test audit ciphertext")?
            .to_owned();
        let mut bytes = ciphertext.into_bytes();
        let first = bytes.first_mut().ok_or("empty test audit ciphertext")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        *document
            .pointer_mut("/audit/events/0/ciphertext")
            .ok_or("missing test audit ciphertext")? = Value::String(String::from_utf8(bytes)?);
        fs::write(&path, serde_json::to_vec_pretty(&document)?)?;

        assert!(matches!(
            FileVault::open(&path, &password()),
            Err(VaultError::CorruptedAudit)
        ));
        Ok(())
    }

    #[test]
    fn detects_audit_tail_deletion_without_a_whole_file_rollback()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut vault = create_test_vault(&path)?;
        vault.append_audit_payload(b"first-test-event")?;
        vault.append_audit_payload(b"second-test-event")?;
        drop(vault);

        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let events = document
            .pointer_mut("/audit/events")
            .and_then(Value::as_array_mut)
            .ok_or("missing test audit events")?;
        let _removed = events.pop().ok_or("missing audit tail")?;
        fs::write(&path, serde_json::to_vec_pretty(&document)?)?;

        assert!(matches!(
            FileVault::open(&path, &password()),
            Err(VaultError::CorruptedAudit)
        ));
        Ok(())
    }
}
