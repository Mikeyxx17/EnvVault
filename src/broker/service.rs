use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use subtle::ConstantTimeEq as _;

use crate::{
    audit::{AuditEvent, AuditSink},
    crypto::{
        KdfConfig, KdfLimits, KdfParams, MasterKey, MasterPassword, derive_key_material,
        generate_array, generate_secret_id, sensitive_values_equal,
    },
    identity::{
        AuthenticationDisposition, AuthenticationMethod, Caller, CallerCredential, CallerId,
        CallerKind, CallerName, CredentialVerifier, DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
        IdentityRegistryDocument, IssuedCallerCredential, RegisteredCaller, VerifiedCaller,
    },
    keystore::{self, MachineUnlockStatus},
    policy::{
        AuthorizationRequest, DenyReason, Operation, PolicyAvailability, PolicyDecision,
        PolicyDocument, PolicyDocumentError, PolicyEffect, PolicyEngine, PolicyEvaluator,
        PolicyRule, PolicySet, VaultAuthorizationRequest, VaultOperation, VaultPolicyEvaluator,
        VaultPolicyRule, VaultPolicySet,
    },
    secret::{SecretId, SecretName, SecretRecord, SecretValue},
    vault::{AuditRuntimeV2, FileVault, VaultError},
};

use super::BrokerError;

pub(crate) struct PreparedCallerRegistration {
    issued: IssuedCallerCredential,
    name: CallerName,
    verifier: CredentialVerifier,
    credential_issued_unix_time_millis: u64,
    credential_expires_unix_time_millis: u64,
}

impl PreparedCallerRegistration {
    pub(crate) const fn issued(&self) -> &IssuedCallerCredential {
        &self.issued
    }
}

pub(crate) struct PreparedCallerRotation {
    issued: IssuedCallerCredential,
    verifier: CredentialVerifier,
    expected_generation: u64,
    credential_issued_unix_time_millis: u64,
    credential_expires_unix_time_millis: u64,
}

impl PreparedCallerRotation {
    pub(crate) const fn issued(&self) -> &IssuedCallerCredential {
        &self.issued
    }
}

/// Result of one Secret in a batch `use` request.
///
/// The value is present only for an allowed request that was successfully read.
/// This type deliberately implements neither `Debug` nor `Clone`.
pub struct SecretUseResult {
    secret_id: SecretId,
    decision: PolicyDecision,
    value: Option<SecretValue>,
}

impl SecretUseResult {
    /// Returns the exact Secret covered by this result.
    #[must_use]
    pub const fn secret_id(&self) -> SecretId {
        self.secret_id
    }

    /// Returns the independent policy decision.
    pub const fn decision(&self) -> PolicyDecision {
        self.decision
    }

    /// Returns the Secret only when this exact request was allowed.
    #[must_use]
    pub fn value(&self) -> Option<&SecretValue> {
        self.value.as_ref()
    }

    /// Consumes the result and returns its authorized Secret, if present.
    #[must_use]
    pub fn into_value(self) -> Option<SecretValue> {
        self.value
    }
}

/// Internal Secret Broker that enforces Identity, Policy, Audit, then Vault.
pub(crate) struct SecretBroker<A> {
    vault: FileVault,
    policy: PolicyEngine,
    identities: IdentityRegistryDocument,
    audit: A,
    audit_v2: Option<AuditRuntimeV2>,
}

impl<A: AuditSink> SecretBroker<A> {
    pub(crate) fn bootstrap_owner(
        path: &Path,
        password: &MasterPassword,
        audit: A,
    ) -> Result<(Self, VerifiedCaller), BrokerError> {
        let owner_id =
            CallerId::from_bytes(generate_array().map_err(|_| BrokerError::IdentityUnavailable)?);
        let identity = IdentityRegistryDocument::new(1, owner_id);
        let identity_payload = identity
            .encode()
            .map_err(|_| BrokerError::IdentityUnavailable)?;
        let owner = identity.verified_owner();
        let mut vault_policy = VaultPolicySet::new();
        for operation in [
            VaultOperation::CreateSecret,
            VaultOperation::ManagePolicy,
            VaultOperation::ManageIdentity,
            VaultOperation::ReadAudit,
            VaultOperation::ManageKeystore,
        ] {
            if !vault_policy.insert(VaultPolicyRule::new(
                owner.caller(),
                operation,
                PolicyEffect::Allow,
            )) {
                return Err(BrokerError::IdentityUnavailable);
            }
        }
        let policy_payload =
            PolicyDocument::new_with_vault_policy(1, PolicySet::default(), vault_policy)
                .and_then(|document| document.encode())
                .map_err(|_| BrokerError::IdentityUnavailable)?;
        let vault = FileVault::create(path, password, &identity_payload, &policy_payload)?;
        AuditRuntimeV2::initialize_new(path, vault.vault_id(), vault.master_key())?;
        let broker = Self::from_unlocked_vault(vault, audit)?;
        Ok((broker, owner))
    }

    pub(crate) fn open_owner(
        path: &Path,
        password: &MasterPassword,
        audit: A,
    ) -> Result<(Self, VerifiedCaller), BrokerError> {
        let vault = FileVault::open(path, password)?;
        let identity = load_identities(&vault)?;
        let owner = identity.verified_owner();
        let broker = Self::from_unlocked_vault(vault, audit)?;
        Ok((broker, owner))
    }

    pub(crate) fn open_owner_for_audit_migration(
        path: &Path,
        password: &MasterPassword,
        audit: A,
    ) -> Result<(Self, VerifiedCaller), BrokerError> {
        let vault = FileVault::open(path, password)?;
        let identity = load_identities(&vault)?;
        let owner = identity.verified_owner();
        let broker = Self::from_unlocked_vault_internal(vault, audit, true)?;
        Ok((broker, owner))
    }

    pub(crate) fn open(
        path: &Path,
        password: &MasterPassword,
        audit: A,
    ) -> Result<Self, BrokerError> {
        let vault = FileVault::open(path, password)?;
        Self::from_unlocked_vault(vault, audit)
    }

    pub(crate) fn open_with_master_key(
        path: &Path,
        master_key: MasterKey,
        audit: A,
    ) -> Result<Self, BrokerError> {
        let vault = FileVault::open_with_master_key(path, master_key)?;
        Self::from_unlocked_vault(vault, audit)
    }

    pub(crate) fn from_unlocked_vault(vault: FileVault, audit: A) -> Result<Self, BrokerError> {
        Self::from_unlocked_vault_internal(vault, audit, false)
    }

    fn from_unlocked_vault_internal(
        vault: FileVault,
        audit: A,
        allow_incomplete_migration: bool,
    ) -> Result<Self, BrokerError> {
        if AuditRuntimeV2::migration_in_progress(vault.path())? && !allow_incomplete_migration {
            return Err(BrokerError::AuditMigrationInvalid);
        }
        let policy = load_policy(&vault)?;
        let identities = load_identities(&vault)?;
        validate_audit(&vault)?;
        let audit_v2 = if AuditRuntimeV2::exists(vault.path())? {
            let mut runtime = AuditRuntimeV2::for_vault(vault.path(), vault.vault_id())
                .map_err(|_| BrokerError::AuditUnavailable)?;
            runtime
                .read_all(vault.path(), vault.master_key())
                .map_err(|_| BrokerError::AuditUnavailable)?;
            Some(runtime)
        } else {
            None
        };
        Ok(Self {
            vault,
            policy,
            identities,
            audit,
            audit_v2,
        })
    }

    pub(crate) const fn policy_availability(&self) -> PolicyAvailability {
        self.policy.availability()
    }

    pub(crate) const fn policy_generation(&self) -> u64 {
        self.vault.policy_generation()
    }

    pub(crate) const fn identity_generation(&self) -> u64 {
        self.vault.identity_generation()
    }

    pub(crate) fn enable_machine_unlock(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<MachineUnlockStatus, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageKeystore)?;
        Ok(keystore::enable(
            self.vault.path(),
            self.vault.vault_id(),
            self.vault.master_key(),
        )?)
    }

    pub(crate) fn grant_self_machine_unlock_management(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<u64, BrokerError> {
        let document = self.read_policy(actor)?;
        let mut vault_policy = document.vault_policy().clone();
        if !vault_policy.insert(VaultPolicyRule::new(
            actor.caller(),
            VaultOperation::ManageKeystore,
            PolicyEffect::Allow,
        )) {
            return Ok(document.generation());
        }
        self.replace_policy(
            actor,
            document.generation(),
            document.policy().clone(),
            vault_policy,
        )
    }

    pub(crate) fn rotate_machine_unlock(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<MachineUnlockStatus, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageKeystore)?;
        Ok(keystore::rotate(
            self.vault.path(),
            self.vault.vault_id(),
            self.vault.master_key(),
        )?)
    }

    pub(crate) fn disable_machine_unlock(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<MachineUnlockStatus, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageKeystore)?;
        Ok(keystore::disable(self.vault.path(), self.vault.vault_id())?)
    }

    pub(crate) fn machine_unlock_status(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<MachineUnlockStatus, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageKeystore)?;
        Ok(keystore::status(
            self.vault.path(),
            self.vault.vault_id(),
            self.vault.master_key(),
        )?)
    }

    pub(crate) fn register_caller(
        &mut self,
        actor: &VerifiedCaller,
        kind: CallerKind,
        name: CallerName,
    ) -> Result<IssuedCallerCredential, BrokerError> {
        let prepared = self.prepare_caller_registration(actor, kind, name)?;
        self.commit_caller_registration(actor, prepared)
    }

    #[cfg(test)]
    fn register_caller_at(
        &mut self,
        actor: &VerifiedCaller,
        kind: CallerKind,
        name: CallerName,
        unix_time_millis: u64,
    ) -> Result<IssuedCallerCredential, BrokerError> {
        let prepared = self.prepare_caller_registration_at(actor, kind, name, unix_time_millis)?;
        self.commit_caller_registration(actor, prepared)
    }

    pub(crate) fn prepare_caller_rotation(
        &mut self,
        actor: &VerifiedCaller,
        caller_id: CallerId,
    ) -> Result<PreparedCallerRotation, BrokerError> {
        self.prepare_caller_rotation_at(actor, caller_id, current_unix_time_millis())
    }

    fn prepare_caller_rotation_at(
        &mut self,
        actor: &VerifiedCaller,
        caller_id: CallerId,
        unix_time_millis: u64,
    ) -> Result<PreparedCallerRotation, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        let credential_issued_unix_time_millis =
            unix_time_millis.max(self.identities.last_observed_authentication_time());
        let caller = self
            .identities
            .registered_caller(caller_id)
            .ok_or(BrokerError::IdentityUpdateInvalid)?
            .caller();
        let credential = CallerCredential::from_bytes(
            generate_array().map_err(|_| BrokerError::IdentityUpdateInvalid)?,
        );
        let params = KdfParams::recommended();
        let salt = generate_array().map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let config = KdfConfig::new(params, salt);
        let derived = derive_key_material(credential.expose_secret(), config, KdfLimits::default())
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let credential_expires_unix_time_millis =
            credential_expiry(credential_issued_unix_time_millis)?;
        Ok(PreparedCallerRotation {
            issued: IssuedCallerCredential::new(caller, credential),
            verifier: CredentialVerifier::new(
                params.memory_kib,
                params.iterations,
                params.parallelism,
                salt,
                *derived,
            ),
            expected_generation: self.identities.generation(),
            credential_issued_unix_time_millis,
            credential_expires_unix_time_millis,
        })
    }

    pub(crate) fn commit_caller_rotation(
        &mut self,
        actor: &VerifiedCaller,
        prepared: PreparedCallerRotation,
    ) -> Result<IssuedCallerCredential, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        if self.identities.generation() != prepared.expected_generation {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        let mut candidate = self.identities.clone();
        candidate
            .replace_credential(
                prepared.issued.caller().id(),
                prepared.verifier,
                prepared.credential_issued_unix_time_millis,
                prepared.credential_expires_unix_time_millis,
            )
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let new_generation = candidate
            .advance_generation()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let payload = candidate
            .encode()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let committed = self
            .vault
            .replace_identity_payload(prepared.expected_generation, &payload)?;
        if committed != new_generation {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        self.identities = candidate;
        Ok(prepared.issued)
    }

    pub(crate) fn caller_credential_is_current(
        &mut self,
        actor: &VerifiedCaller,
        caller: Caller,
        credential: &CallerCredential,
    ) -> Result<bool, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        let Some(verifier) = self.identities.credential(caller.id(), caller.kind()) else {
            return Ok(false);
        };
        let derived = derive_key_material(
            credential.expose_secret(),
            credential_kdf_config(verifier),
            KdfLimits::default(),
        )
        .map_err(|_| BrokerError::IdentityUnavailable)?;
        Ok(bool::from(
            derived.as_slice().ct_eq(verifier.verifier().as_slice()),
        ))
    }

    pub(crate) fn prepare_caller_registration(
        &mut self,
        actor: &VerifiedCaller,
        kind: CallerKind,
        name: CallerName,
    ) -> Result<PreparedCallerRegistration, BrokerError> {
        self.prepare_caller_registration_at(actor, kind, name, current_unix_time_millis())
    }

    fn prepare_caller_registration_at(
        &mut self,
        actor: &VerifiedCaller,
        kind: CallerKind,
        name: CallerName,
        unix_time_millis: u64,
    ) -> Result<PreparedCallerRegistration, BrokerError> {
        if kind == CallerKind::Human {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        let credential_issued_unix_time_millis =
            unix_time_millis.max(self.identities.last_observed_authentication_time());
        if self.identities.contains_name(&name) {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        let caller_id = self.generate_unused_caller_id()?;
        let caller = Caller::new(caller_id, kind);
        let credential = CallerCredential::from_bytes(
            generate_array().map_err(|_| BrokerError::IdentityUpdateInvalid)?,
        );
        let params = KdfParams::recommended();
        let salt = generate_array().map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let config = KdfConfig::new(params, salt);
        let derived = derive_key_material(credential.expose_secret(), config, KdfLimits::default())
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let verifier = CredentialVerifier::new(
            params.memory_kib,
            params.iterations,
            params.parallelism,
            salt,
            *derived,
        );
        let credential_expires_unix_time_millis =
            credential_expiry(credential_issued_unix_time_millis)?;
        Ok(PreparedCallerRegistration {
            issued: IssuedCallerCredential::new(caller, credential),
            name,
            verifier,
            credential_issued_unix_time_millis,
            credential_expires_unix_time_millis,
        })
    }

    pub(crate) fn commit_caller_registration(
        &mut self,
        actor: &VerifiedCaller,
        prepared: PreparedCallerRegistration,
    ) -> Result<IssuedCallerCredential, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        if self.identities.contains_name(&prepared.name)
            || self
                .identities
                .credential(
                    prepared.issued.caller().id(),
                    prepared.issued.caller().kind(),
                )
                .is_some()
        {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        let mut candidate = self.identities.clone();
        candidate
            .insert(
                RegisteredCaller::new(prepared.issued.caller(), prepared.name),
                prepared.verifier,
                prepared.credential_issued_unix_time_millis,
                prepared.credential_expires_unix_time_millis,
            )
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let expected_generation = candidate.generation();
        let new_generation = candidate
            .advance_generation()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let payload = candidate
            .encode()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let committed = self
            .vault
            .replace_identity_payload(expected_generation, &payload)?;
        if committed != new_generation {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        self.identities = candidate;
        Ok(prepared.issued)
    }

    pub(crate) fn authenticate_caller(
        &mut self,
        caller_id: CallerId,
        kind: CallerKind,
        credential: &CallerCredential,
    ) -> Result<VerifiedCaller, BrokerError> {
        self.authenticate_caller_at(caller_id, kind, credential, current_unix_time_millis())
    }

    fn authenticate_caller_at(
        &mut self,
        caller_id: CallerId,
        kind: CallerKind,
        credential: &CallerCredential,
        unix_time_millis: u64,
    ) -> Result<VerifiedCaller, BrokerError> {
        let method = match kind {
            CallerKind::Application => AuthenticationMethod::ApplicationCredential,
            CallerKind::AiAgent => AuthenticationMethod::AgentCredential,
            CallerKind::Human => return Err(BrokerError::IdentityUnavailable),
        };
        let caller = Caller::new(caller_id, kind);
        let mut candidate = self.identities.clone();
        let disposition = candidate.authentication_disposition(caller_id, unix_time_millis);
        let effective_unix_time_millis = candidate.last_observed_authentication_time();
        let credential_is_active =
            candidate.credential_is_active(caller_id, kind, effective_unix_time_millis);
        let authenticated = if disposition == AuthenticationDisposition::Blocked {
            false
        } else {
            let stored = self.identities.credential(caller_id, kind);
            let (config, expected) = stored.map_or_else(dummy_credential_verifier, |verifier| {
                (credential_kdf_config(verifier), *verifier.verifier())
            });
            let derived =
                derive_key_material(credential.expose_secret(), config, KdfLimits::default())
                    .map_err(|_| BrokerError::IdentityUnavailable)?;
            bool::from(derived.as_slice().ct_eq(expected.as_slice()))
                && stored.is_some()
                && credential_is_active
        };
        let decision = if authenticated {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny(DenyReason::InvalidRequest)
        };
        let event = AuditEvent::now_authentication(caller, method, decision);
        self.persist_audit_event(event)?;
        self.audit
            .record(event)
            .map_err(|_| BrokerError::AuditUnavailable)?;
        candidate.record_authentication_result(
            caller_id,
            unix_time_millis,
            authenticated,
            disposition,
        );
        persist_authentication_throttle(&mut self.vault, &mut candidate)?;
        self.identities = candidate;
        if !authenticated {
            return Err(BrokerError::IdentityUnavailable);
        }
        Ok(VerifiedCaller::new(caller, method))
    }

    pub(crate) fn registered_callers(
        &mut self,
        actor: &VerifiedCaller,
    ) -> Result<Vec<RegisteredCaller>, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        Ok(self.identities.callers())
    }

    pub(crate) fn revoke_caller(
        &mut self,
        actor: &VerifiedCaller,
        caller_id: CallerId,
    ) -> Result<u64, BrokerError> {
        self.require_vault_allow(actor, VaultOperation::ManageIdentity)?;
        let mut candidate = self.identities.clone();
        candidate
            .remove(caller_id)
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let expected_generation = candidate.generation();
        let new_generation = candidate
            .advance_generation()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let payload = candidate
            .encode()
            .map_err(|_| BrokerError::IdentityUpdateInvalid)?;
        let committed = self
            .vault
            .replace_identity_payload(expected_generation, &payload)?;
        if committed != new_generation {
            return Err(BrokerError::IdentityUpdateInvalid);
        }
        self.identities = candidate;
        Ok(committed)
    }

    pub(crate) fn create_secret(
        &mut self,
        caller: &VerifiedCaller,
        name: SecretName,
        value: &SecretValue,
    ) -> Result<SecretRecord, BrokerError> {
        self.require_vault_allow(caller, VaultOperation::CreateSecret)?;
        self.vault.create_secret(name, value).map_err(Into::into)
    }

    pub(crate) fn create_managed_secret(
        &mut self,
        caller: &VerifiedCaller,
        name: SecretName,
        value: &SecretValue,
    ) -> Result<SecretRecord, BrokerError> {
        self.require_vault_allow(caller, VaultOperation::CreateSecret)?;
        self.require_vault_allow(caller, VaultOperation::ManagePolicy)?;

        let (expected_generation, payload) = self.vault.policy_payload()?;
        let current =
            PolicyDocument::decode(&payload).map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        if current.generation() != expected_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        let (mut secret_policy, vault_policy) = current.into_policies();
        let secret_id = self.generate_unused_managed_secret_id(&secret_policy)?;
        for operation in [
            Operation::List,
            Operation::Exists,
            Operation::Verify,
            Operation::Write,
            Operation::Delete,
        ] {
            if !secret_policy.insert(PolicyRule::new(
                caller.caller(),
                secret_id,
                operation,
                PolicyEffect::Allow,
            )) {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
        }
        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(BrokerError::PolicyUpdateInvalid)?;
        let document =
            PolicyDocument::new_with_vault_policy(new_generation, secret_policy, vault_policy)
                .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let encoded = document
            .encode()
            .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let (record, committed_generation) = self.vault.create_secret_and_replace_policy(
            secret_id,
            name,
            value,
            expected_generation,
            &encoded,
        )?;
        if committed_generation != new_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        self.policy = PolicyEngine::from_document_result(Ok(Some(document)));
        Ok(record)
    }

    pub(crate) fn import_managed_secrets(
        &mut self,
        caller: &VerifiedCaller,
        entries: Vec<(SecretName, SecretValue)>,
    ) -> Result<Vec<SecretRecord>, BrokerError> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut input_names = BTreeSet::new();
        for (name, _) in &entries {
            if !input_names.insert(name.clone()) {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
        }

        let mut writable = BTreeMap::new();
        for secret_id in self.vault.secret_ids() {
            if self
                .authorize(caller, secret_id, Operation::Write)?
                .is_allowed()
            {
                let record = self.vault.record(secret_id)?;
                writable.insert(record.name().clone(), record.id());
            }
        }
        let new_count = entries
            .iter()
            .filter(|(name, _)| !writable.contains_key(name))
            .count();

        let mut policy_document = None;
        let mut policy_payload = None;
        let mut expected_policy_generation = None;
        let mut secret_policy = PolicySet::new();
        let mut vault_policy = VaultPolicySet::new();
        if new_count > 0 {
            self.require_vault_allow(caller, VaultOperation::CreateSecret)?;
            self.require_vault_allow(caller, VaultOperation::ManagePolicy)?;
            let (generation, payload) = self.vault.policy_payload()?;
            let current =
                PolicyDocument::decode(&payload).map_err(|_| BrokerError::PolicyUpdateInvalid)?;
            if current.generation() != generation {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
            (secret_policy, vault_policy) = current.into_policies();
            expected_policy_generation = Some(generation);
        }

        let mut reserved_ids = BTreeSet::new();
        let mut upserts = Vec::with_capacity(entries.len());
        for (name, value) in entries {
            let secret_id = if let Some(secret_id) = writable.get(&name) {
                *secret_id
            } else {
                let secret_id =
                    self.generate_unused_import_secret_id(&secret_policy, &reserved_ids)?;
                reserved_ids.insert(secret_id);
                for operation in [
                    Operation::List,
                    Operation::Exists,
                    Operation::Verify,
                    Operation::Write,
                    Operation::Delete,
                ] {
                    if !secret_policy.insert(PolicyRule::new(
                        caller.caller(),
                        secret_id,
                        operation,
                        PolicyEffect::Allow,
                    )) {
                        return Err(BrokerError::PolicyUpdateInvalid);
                    }
                }
                secret_id
            };
            upserts.push((secret_id, name, value));
        }

        if let Some(generation) = expected_policy_generation {
            let next_generation = generation
                .checked_add(1)
                .ok_or(BrokerError::PolicyUpdateInvalid)?;
            let document =
                PolicyDocument::new_with_vault_policy(next_generation, secret_policy, vault_policy)
                    .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
            policy_payload = Some(
                document
                    .encode()
                    .map_err(|_| BrokerError::PolicyUpdateInvalid)?,
            );
            policy_document = Some(document);
        }
        let update = expected_policy_generation.zip(policy_payload.as_deref());
        let (records, committed_policy_generation) = self
            .vault
            .upsert_secrets_and_replace_policy(upserts, update)?;
        if let Some(document) = policy_document {
            if committed_policy_generation != Some(document.generation()) {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
            self.policy = PolicyEngine::from_document_result(Ok(Some(document)));
        }
        Ok(records)
    }

    pub(crate) fn replace_secret(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
        value: &SecretValue,
    ) -> Result<SecretRecord, BrokerError> {
        self.require_allow(caller, secret_id, Operation::Write)?;
        let record = self.vault.record(secret_id)?;
        self.vault
            .replace_secret(secret_id, record.name().clone(), value)
            .map_err(Into::into)
    }

    pub(crate) fn delete_secret(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
    ) -> Result<(), BrokerError> {
        self.require_allow(caller, secret_id, Operation::Delete)?;
        self.vault.remove_secret(secret_id).map_err(Into::into)
    }

    pub(crate) fn replace_secret_by_name(
        &mut self,
        caller: &VerifiedCaller,
        name: &SecretName,
        value: &SecretValue,
    ) -> Result<Option<SecretRecord>, BrokerError> {
        for secret_id in self.vault.secret_ids() {
            let decision = self.authorize(caller, secret_id, Operation::Write)?;
            if decision.is_allowed() {
                let record = self.vault.record(secret_id)?;
                if record.name() == name {
                    return self
                        .vault
                        .replace_secret(secret_id, record.name().clone(), value)
                        .map(Some)
                        .map_err(Into::into);
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn secret_exists_by_name(
        &mut self,
        caller: &VerifiedCaller,
        name: &SecretName,
    ) -> Result<bool, BrokerError> {
        for secret_id in self.vault.secret_ids() {
            let decision = self.authorize(caller, secret_id, Operation::Exists)?;
            if decision.is_allowed() && self.vault.record(secret_id)?.name() == name {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn verify_secret_by_name(
        &mut self,
        caller: &VerifiedCaller,
        name: &SecretName,
        expected: &SecretValue,
    ) -> Result<Option<bool>, BrokerError> {
        for secret_id in self.vault.secret_ids() {
            let decision = self.authorize(caller, secret_id, Operation::Exists)?;
            if decision.is_allowed() && self.vault.record(secret_id)?.name() == name {
                match self.authorize(caller, secret_id, Operation::Verify)? {
                    PolicyDecision::Allow => {}
                    PolicyDecision::Deny(DenyReason::NoMatchingGrant)
                        if caller.caller() == self.identities.verified_owner().caller() =>
                    {
                        self.grant_self_verify(caller, secret_id)?;
                        self.require_allow(caller, secret_id, Operation::Verify)?;
                    }
                    PolicyDecision::Deny(reason) => {
                        return Err(BrokerError::AccessDenied(reason));
                    }
                }
                let stored = self.vault.read_secret(secret_id)?;
                return Ok(Some(sensitive_values_equal(
                    stored.expose_secret(),
                    expected.expose_secret(),
                )));
            }
        }
        Ok(None)
    }

    fn grant_self_verify(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
    ) -> Result<u64, BrokerError> {
        if caller.caller() != self.identities.verified_owner().caller() {
            return Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant));
        }
        self.require_vault_allow(caller, VaultOperation::ManagePolicy)?;
        let (expected_generation, payload) = self.vault.policy_payload()?;
        let current =
            PolicyDocument::decode(&payload).map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        if current.generation() != expected_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        let (mut secret_policy, vault_policy) = current.into_policies();
        if !secret_policy.insert(PolicyRule::new(
            caller.caller(),
            secret_id,
            Operation::Verify,
            PolicyEffect::Allow,
        )) {
            return Ok(expected_generation);
        }
        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(BrokerError::PolicyUpdateInvalid)?;
        let document =
            PolicyDocument::new_with_vault_policy(new_generation, secret_policy, vault_policy)
                .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let encoded = document
            .encode()
            .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let committed = self
            .vault
            .replace_policy_payload(expected_generation, &encoded)?;
        if committed != new_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        self.policy = PolicyEngine::from_document_result(Ok(Some(document)));
        Ok(committed)
    }

    pub(crate) fn delete_secret_by_name(
        &mut self,
        caller: &VerifiedCaller,
        name: &SecretName,
    ) -> Result<bool, BrokerError> {
        for secret_id in self.vault.secret_ids() {
            let decision = self.authorize(caller, secret_id, Operation::Delete)?;
            if decision.is_allowed() && self.vault.record(secret_id)?.name() == name {
                self.vault.remove_secret(secret_id)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn read_policy(
        &mut self,
        caller: &VerifiedCaller,
    ) -> Result<PolicyDocument, BrokerError> {
        self.require_vault_allow(caller, VaultOperation::ManagePolicy)?;
        let (generation, payload) = self.vault.policy_payload()?;
        let document =
            PolicyDocument::decode(&payload).map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        if document.generation() != generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        Ok(document)
    }

    pub(crate) fn read_audit(
        &mut self,
        caller: &VerifiedCaller,
    ) -> Result<Vec<AuditEvent>, BrokerError> {
        self.require_vault_allow(caller, VaultOperation::ReadAudit)?;
        if let Some(runtime) = self.audit_v2.as_mut() {
            return runtime
                .read_all(self.vault.path(), self.vault.master_key())
                .map_err(|_| BrokerError::AuditUnavailable);
        }
        decode_v1_audit(&self.vault)
    }

    pub(crate) fn migrate_audit_v2(
        &mut self,
        caller: &VerifiedCaller,
    ) -> Result<usize, BrokerError> {
        if AuditRuntimeV2::migration_in_progress(self.vault.path())? {
            let request =
                VaultAuthorizationRequest::new(caller.caller(), VaultOperation::ReadAudit);
            match self.policy.evaluate_vault(&request) {
                PolicyDecision::Allow => {}
                PolicyDecision::Deny(reason) => return Err(BrokerError::AccessDenied(reason)),
            }
        } else {
            self.require_vault_allow(caller, VaultOperation::ReadAudit)?;
        }
        if self.audit_v2.is_some() {
            return Err(BrokerError::AuditMigrationInvalid);
        }
        let events = decode_v1_audit(&self.vault)?;
        AuditRuntimeV2::migrate_v1(
            self.vault.path(),
            self.vault.vault_id(),
            self.vault.master_key(),
            &events,
        )?;
        self.audit_v2 = Some(AuditRuntimeV2::local_mirror());
        Ok(events.len())
    }

    pub(crate) fn replace_policy(
        &mut self,
        caller: &VerifiedCaller,
        expected_generation: u64,
        secret_policy: PolicySet,
        vault_policy: VaultPolicySet,
    ) -> Result<u64, BrokerError> {
        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(BrokerError::PolicyUpdateInvalid)?;
        let document =
            PolicyDocument::new_with_vault_policy(new_generation, secret_policy, vault_policy)
                .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let payload = document
            .encode()
            .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        self.require_vault_allow(caller, VaultOperation::ManagePolicy)?;
        let committed = self
            .vault
            .replace_policy_payload(expected_generation, &payload)?;
        self.policy = PolicyEngine::from_document_result(Ok(Some(document)));
        Ok(committed)
    }

    pub(crate) fn grant_profile_use(
        &mut self,
        actor: &VerifiedCaller,
        caller_id: CallerId,
        secret_ids: &[SecretId],
    ) -> Result<u64, BrokerError> {
        if secret_ids.is_empty() {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        let subject = self
            .identities
            .callers()
            .into_iter()
            .find(|registered| registered.caller().id() == caller_id)
            .map(|registered| registered.caller())
            .ok_or(BrokerError::IdentityUpdateInvalid)?;

        self.require_vault_allow(actor, VaultOperation::ManagePolicy)?;
        for secret_id in secret_ids {
            self.require_allow(actor, *secret_id, Operation::Exists)?;
            if !self.vault.contains_secret(*secret_id) {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
        }

        let (expected_generation, payload) = self.vault.policy_payload()?;
        let current =
            PolicyDocument::decode(&payload).map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        if current.generation() != expected_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        let (mut secret_policy, vault_policy) = current.into_policies();
        for secret_id in secret_ids {
            let has_explicit_deny = secret_policy.rules().any(|rule| {
                rule.caller() == subject
                    && rule.secret_id() == *secret_id
                    && rule.operation() == Operation::Use
                    && rule.effect() == PolicyEffect::Deny
            });
            if has_explicit_deny {
                return Err(BrokerError::PolicyUpdateInvalid);
            }
        }
        let mut changed = false;
        for secret_id in secret_ids {
            changed |= secret_policy.insert(PolicyRule::new(
                subject,
                *secret_id,
                Operation::Use,
                PolicyEffect::Allow,
            ));
        }
        if !changed {
            return Ok(expected_generation);
        }

        let new_generation = expected_generation
            .checked_add(1)
            .ok_or(BrokerError::PolicyUpdateInvalid)?;
        let document =
            PolicyDocument::new_with_vault_policy(new_generation, secret_policy, vault_policy)
                .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let encoded = document
            .encode()
            .map_err(|_| BrokerError::PolicyUpdateInvalid)?;
        let committed = self
            .vault
            .replace_policy_payload(expected_generation, &encoded)?;
        if committed != new_generation {
            return Err(BrokerError::PolicyUpdateInvalid);
        }
        self.policy = PolicyEngine::from_document_result(Ok(Some(document)));
        Ok(committed)
    }

    pub(crate) fn list(
        &mut self,
        caller: &VerifiedCaller,
    ) -> Result<Vec<SecretRecord>, BrokerError> {
        let mut allowed = Vec::new();
        for secret_id in self.vault.secret_ids() {
            let decision = self.authorize(caller, secret_id, Operation::List)?;
            if decision.is_allowed() {
                allowed.push(self.vault.record(secret_id)?);
            }
        }
        Ok(allowed)
    }

    pub(crate) fn exists(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
    ) -> Result<bool, BrokerError> {
        self.require_allow(caller, secret_id, Operation::Exists)?;
        Ok(self.vault.contains_secret(secret_id))
    }

    pub(crate) fn use_secret(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
    ) -> Result<SecretValue, BrokerError> {
        self.require_allow(caller, secret_id, Operation::Use)?;
        self.vault.read_secret(secret_id).map_err(Into::into)
    }

    pub(crate) fn read_plaintext(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
    ) -> Result<SecretValue, BrokerError> {
        self.require_allow(caller, secret_id, Operation::ReadPlaintext)?;
        self.vault.read_secret(secret_id).map_err(Into::into)
    }

    pub(crate) fn use_batch(
        &mut self,
        caller: &VerifiedCaller,
        secret_ids: impl IntoIterator<Item = SecretId>,
    ) -> Result<Vec<SecretUseResult>, BrokerError> {
        let mut results = Vec::new();
        for secret_id in secret_ids {
            let decision = self.authorize(caller, secret_id, Operation::Use)?;
            let value = if decision.is_allowed() {
                Some(self.vault.read_secret(secret_id)?)
            } else {
                None
            };
            results.push(SecretUseResult {
                secret_id,
                decision,
                value,
            });
        }
        Ok(results)
    }

    fn require_allow(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
        operation: Operation,
    ) -> Result<(), BrokerError> {
        match self.authorize(caller, secret_id, operation)? {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(BrokerError::AccessDenied(reason)),
        }
    }

    fn require_vault_allow(
        &mut self,
        caller: &VerifiedCaller,
        operation: VaultOperation,
    ) -> Result<(), BrokerError> {
        match self.authorize_vault(caller, operation)? {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Deny(reason) => Err(BrokerError::AccessDenied(reason)),
        }
    }

    fn authorize(
        &mut self,
        caller: &VerifiedCaller,
        secret_id: SecretId,
        operation: Operation,
    ) -> Result<PolicyDecision, BrokerError> {
        let request = AuthorizationRequest::new(caller.caller(), secret_id, operation);
        let decision = self.policy.evaluate(&request);
        let event = AuditEvent::now(
            caller.caller(),
            caller.authentication_method(),
            secret_id,
            operation,
            decision,
        );
        self.persist_audit_event(event)?;
        self.audit
            .record(event)
            .map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(decision)
    }

    fn authorize_vault(
        &mut self,
        caller: &VerifiedCaller,
        operation: VaultOperation,
    ) -> Result<PolicyDecision, BrokerError> {
        let request = VaultAuthorizationRequest::new(caller.caller(), operation);
        let decision = self.policy.evaluate_vault(&request);
        let event = AuditEvent::now_vault(
            caller.caller(),
            caller.authentication_method(),
            operation,
            decision,
        );
        self.persist_audit_event(event)?;
        self.audit
            .record(event)
            .map_err(|_| BrokerError::AuditUnavailable)?;
        Ok(decision)
    }

    fn persist_audit_event(&mut self, event: AuditEvent) -> Result<(), BrokerError> {
        if let Some(runtime) = self.audit_v2.as_mut() {
            return runtime
                .append(self.vault.path(), self.vault.master_key(), event)
                .map_err(|_| BrokerError::AuditUnavailable);
        }
        let payload = event.encode().map_err(|_| BrokerError::AuditUnavailable)?;
        self.vault
            .append_audit_payload(&payload)
            .map_err(|_| BrokerError::AuditUnavailable)
    }

    fn generate_unused_caller_id(&self) -> Result<CallerId, BrokerError> {
        for _ in 0..16 {
            let id = CallerId::from_bytes(
                generate_array().map_err(|_| BrokerError::IdentityUpdateInvalid)?,
            );
            if !self.identities.contains_id(id) {
                return Ok(id);
            }
        }
        Err(BrokerError::IdentityUpdateInvalid)
    }

    fn generate_unused_managed_secret_id(
        &self,
        policy: &PolicySet,
    ) -> Result<SecretId, BrokerError> {
        for _ in 0..16 {
            let id = generate_secret_id().map_err(|_| BrokerError::PolicyUpdateInvalid)?;
            if !self.vault.contains_secret(id) && !policy.rules().any(|rule| rule.secret_id() == id)
            {
                return Ok(id);
            }
        }
        Err(BrokerError::PolicyUpdateInvalid)
    }

    fn generate_unused_import_secret_id(
        &self,
        policy: &PolicySet,
        reserved: &BTreeSet<SecretId>,
    ) -> Result<SecretId, BrokerError> {
        for _ in 0..16 {
            let id = generate_secret_id().map_err(|_| BrokerError::PolicyUpdateInvalid)?;
            if !self.vault.contains_secret(id)
                && !reserved.contains(&id)
                && !policy.rules().any(|rule| rule.secret_id() == id)
            {
                return Ok(id);
            }
        }
        Err(BrokerError::PolicyUpdateInvalid)
    }
}

fn credential_kdf_config(verifier: &CredentialVerifier) -> KdfConfig {
    KdfConfig::new(
        KdfParams {
            memory_kib: verifier.memory_kib(),
            iterations: verifier.iterations(),
            parallelism: verifier.parallelism(),
        },
        verifier.salt(),
    )
}

fn dummy_credential_verifier() -> (KdfConfig, [u8; 32]) {
    (
        KdfConfig::new(KdfParams::recommended(), [0xA5; 16]),
        [0_u8; 32],
    )
}

fn persist_authentication_throttle(
    vault: &mut FileVault,
    candidate: &mut IdentityRegistryDocument,
) -> Result<(), BrokerError> {
    let expected_generation = candidate.generation();
    let new_generation = candidate
        .advance_generation()
        .map_err(|_| BrokerError::IdentityUnavailable)?;
    let payload = candidate
        .encode()
        .map_err(|_| BrokerError::IdentityUnavailable)?;
    let committed = vault
        .replace_identity_payload(expected_generation, &payload)
        .map_err(|_| BrokerError::IdentityUnavailable)?;
    if committed != new_generation {
        return Err(BrokerError::IdentityUnavailable);
    }
    Ok(())
}

fn current_unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn credential_expiry(issued_unix_time_millis: u64) -> Result<u64, BrokerError> {
    if issued_unix_time_millis == 0 {
        return Err(BrokerError::IdentityUpdateInvalid);
    }
    issued_unix_time_millis
        .checked_add(DEFAULT_CREDENTIAL_LIFETIME_MILLIS)
        .ok_or(BrokerError::IdentityUpdateInvalid)
}

fn validate_audit(vault: &FileVault) -> Result<(), BrokerError> {
    for payload in vault
        .audit_payloads()
        .map_err(|_| BrokerError::AuditUnavailable)?
    {
        AuditEvent::decode(&payload).map_err(|_| BrokerError::AuditUnavailable)?;
    }
    Ok(())
}

fn decode_v1_audit(vault: &FileVault) -> Result<Vec<AuditEvent>, BrokerError> {
    vault
        .audit_payloads()
        .map_err(|_| BrokerError::AuditUnavailable)?
        .iter()
        .map(|payload| AuditEvent::decode(payload).map_err(|_| BrokerError::AuditUnavailable))
        .collect()
}

fn load_identities(vault: &FileVault) -> Result<IdentityRegistryDocument, BrokerError> {
    let (envelope_generation, payload) = vault.identity_payload()?;
    let document =
        IdentityRegistryDocument::decode(&payload).map_err(|_| BrokerError::IdentityUnavailable)?;
    if document.generation() != envelope_generation {
        return Err(BrokerError::IdentityUnavailable);
    }
    for verifier in document.credentials() {
        credential_kdf_config(verifier)
            .params
            .validate(KdfLimits::default())
            .map_err(|_| BrokerError::IdentityUnavailable)?;
    }
    Ok(document)
}

fn load_policy(vault: &FileVault) -> Result<PolicyEngine, BrokerError> {
    match vault.policy_payload() {
        Ok((envelope_generation, payload)) => {
            let document = PolicyDocument::decode(&payload).and_then(|document| {
                if document.generation() == envelope_generation {
                    Ok(document)
                } else {
                    Err(PolicyDocumentError::InvalidFormat)
                }
            });
            Ok(PolicyEngine::from_document_result(document.map(Some)))
        }
        Err(VaultError::CorruptedPolicy) => Ok(PolicyEngine::from_document_result(Err(
            PolicyDocumentError::InvalidFormat,
        ))),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::Value;
    use tempfile::tempdir;

    use super::SecretBroker;
    use crate::{
        audit::{AuditError, AuditEvent, AuditSink},
        broker::BrokerError,
        crypto::MasterPassword,
        identity::{
            AuthenticationMethod, Caller, CallerCredential, CallerId, CallerKind, CallerName,
            CredentialVerifier, DEFAULT_CREDENTIAL_LIFETIME_MILLIS, IdentityRegistryDocument,
            RegisteredCaller, VerifiedCaller,
        },
        policy::{
            DenyReason, Operation, PolicyAvailability, PolicyDecision, PolicyDocument,
            PolicyEffect, PolicyRule, PolicySet, VaultOperation, VaultPolicyRule, VaultPolicySet,
        },
        secret::{SecretId, SecretName, SecretValue},
        vault::{FileVault, VaultError},
    };

    #[derive(Default)]
    struct MemoryAudit {
        events: Vec<AuditEvent>,
        fail: bool,
    }

    impl AuditSink for MemoryAudit {
        fn record(&mut self, event: AuditEvent) -> Result<(), AuditError> {
            if self.fail {
                Err(AuditError)
            } else {
                self.events.push(event);
                Ok(())
            }
        }
    }

    fn password() -> MasterPassword {
        MasterPassword::new(b"broker-test-password".to_vec())
    }

    fn caller(byte: u8, kind: CallerKind) -> Caller {
        Caller::new(CallerId::from_bytes([byte; CallerId::BYTE_LENGTH]), kind)
    }

    fn verified(caller: Caller) -> VerifiedCaller {
        VerifiedCaller::new(caller, AuthenticationMethod::ApplicationCredential)
    }

    fn identity_payload() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(IdentityRegistryDocument::new(1, CallerId::from_bytes([0x90; 16])).encode()?)
    }

    fn owner_vault_policy(owner: Caller) -> VaultPolicySet {
        let mut policy = VaultPolicySet::new();
        for operation in [
            VaultOperation::CreateSecret,
            VaultOperation::ManagePolicy,
            VaultOperation::ManageIdentity,
            VaultOperation::ReadAudit,
        ] {
            assert!(policy.insert(VaultPolicyRule::new(owner, operation, PolicyEffect::Allow,)));
        }
        policy
    }

    fn create_vault_with_policy(
        path: &Path,
        caller: Caller,
        grants: &[(SecretId, Operation)],
    ) -> Result<FileVault, Box<dyn std::error::Error>> {
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(path, &password(), &identity_payload()?, &initial)?;
        let mut policy = PolicySet::new();
        for (secret_id, operation) in grants {
            assert!(policy.insert(PolicyRule::new(
                caller,
                *secret_id,
                *operation,
                PolicyEffect::Allow,
            )));
        }
        let next = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &next)?, 2);
        Ok(vault)
    }

    #[test]
    fn use_and_read_plaintext_require_separate_grants() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::Application);
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(&path, &password(), &identity_payload()?, &initial)?;
        let record = vault.create_secret(
            SecretName::new("DATABASE_URL")?,
            &SecretValue::new(b"postgres://test-only".to_vec()),
        )?;
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            identity,
            record.id(),
            Operation::Use,
            PolicyEffect::Allow,
        )));
        let document = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &document)?, 2);
        let mut broker = SecretBroker::from_unlocked_vault(vault, MemoryAudit::default())?;
        let verified = verified(identity);

        assert_eq!(
            broker.use_secret(&verified, record.id())?.expose_secret(),
            b"postgres://test-only"
        );
        assert!(matches!(
            broker.read_plaintext(&verified, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        Ok(())
    }

    #[test]
    fn list_decrypts_only_allowed_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::AiAgent);
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(&path, &password(), &identity_payload()?, &initial)?;
        let allowed = vault.create_secret(
            SecretName::new("VISIBLE_NAME")?,
            &SecretValue::new(b"visible-test-value".to_vec()),
        )?;
        let denied = vault.create_secret(
            SecretName::new("HIDDEN_NAME")?,
            &SecretValue::new(b"hidden-test-value".to_vec()),
        )?;
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            identity,
            allowed.id(),
            Operation::List,
            PolicyEffect::Allow,
        )));
        let document = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &document)?, 2);
        drop(vault);
        corrupt_record_envelope(&path, denied.id(), "metadata_envelope")?;

        let mut broker = SecretBroker::open(&path, &password(), MemoryAudit::default())?;
        let records = broker.list(&verified(identity))?;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id(), allowed.id());
        assert_ne!(records[0].id(), denied.id());
        Ok(())
    }

    #[test]
    fn named_management_uses_its_exact_operation_without_list_permission()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(0x12, CallerKind::Application);
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(&path, &password(), &identity_payload()?, &initial)?;
        let target = vault.create_secret(
            SecretName::new("TARGET_NAME")?,
            &SecretValue::new(b"first-test-value".to_vec()),
        )?;
        let denied = vault.create_secret(
            SecretName::new("DENIED_NAME")?,
            &SecretValue::new(b"denied-test-value".to_vec()),
        )?;
        let mut policy = PolicySet::new();
        for operation in [Operation::Exists, Operation::Write, Operation::Delete] {
            assert!(policy.insert(PolicyRule::new(
                identity,
                target.id(),
                operation,
                PolicyEffect::Allow,
            )));
        }
        let document = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &document)?, 2);
        drop(vault);

        let mut broker = SecretBroker::open(&path, &password(), MemoryAudit::default())?;
        let verified = verified(identity);
        assert!(broker.list(&verified)?.is_empty());
        assert!(broker.secret_exists_by_name(&verified, &SecretName::new("TARGET_NAME")?)?);
        assert!(
            broker
                .replace_secret_by_name(
                    &verified,
                    &SecretName::new("TARGET_NAME")?,
                    &SecretValue::new(b"second-test-value".to_vec()),
                )?
                .is_some()
        );
        drop(broker);

        corrupt_record_envelope(&path, denied.id(), "metadata_envelope")?;
        let mut broker = SecretBroker::open(&path, &password(), MemoryAudit::default())?;
        assert!(broker.secret_exists_by_name(&verified, &SecretName::new("TARGET_NAME")?)?);
        assert!(!broker.secret_exists_by_name(&verified, &SecretName::new("DENIED_NAME")?)?);
        assert!(broker.delete_secret_by_name(&verified, &SecretName::new("TARGET_NAME")?)?);
        Ok(())
    }

    #[test]
    fn batch_returns_values_only_for_individual_allows() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::Application);
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(&path, &password(), &identity_payload()?, &initial)?;
        let first = vault.create_secret(
            SecretName::new("FIRST")?,
            &SecretValue::new(b"first-test".to_vec()),
        )?;
        let second = vault.create_secret(
            SecretName::new("SECOND")?,
            &SecretValue::new(b"second-test".to_vec()),
        )?;
        let third = vault.create_secret(
            SecretName::new("THIRD")?,
            &SecretValue::new(b"third-test".to_vec()),
        )?;
        let mut policy = PolicySet::new();
        for id in [first.id(), third.id()] {
            assert!(policy.insert(PolicyRule::new(
                identity,
                id,
                Operation::Use,
                PolicyEffect::Allow,
            )));
        }
        let document = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &document)?, 2);
        let mut broker = SecretBroker::from_unlocked_vault(vault, MemoryAudit::default())?;

        let results =
            broker.use_batch(&verified(identity), [first.id(), second.id(), third.id()])?;

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].secret_id(), first.id());
        assert_eq!(results[0].decision(), PolicyDecision::Allow);
        assert_eq!(
            results[0].value().map(SecretValue::expose_secret),
            Some(b"first-test".as_slice())
        );
        assert!(results[1].decision().is_denied());
        assert!(results[1].value().is_none());
        assert_eq!(results[2].decision(), PolicyDecision::Allow);
        assert_eq!(
            results[2].value().map(SecretValue::expose_secret),
            Some(b"third-test".as_slice())
        );
        Ok(())
    }

    #[test]
    fn invalid_authenticated_policy_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::Application);
        let mut vault = FileVault::create(
            &path,
            &password(),
            &identity_payload()?,
            b"not-a-policy-document",
        )?;
        let record = vault.create_secret(
            SecretName::new("TOKEN")?,
            &SecretValue::new(b"test-token".to_vec()),
        )?;
        let mut broker = SecretBroker::from_unlocked_vault(vault, MemoryAudit::default())?;

        assert_eq!(broker.policy_availability(), PolicyAvailability::Invalid);
        assert!(matches!(
            broker.use_secret(&verified(identity), record.id()),
            Err(BrokerError::AccessDenied(DenyReason::DefaultDeny))
        ));
        Ok(())
    }

    #[test]
    fn audit_failure_stops_before_allowed_secret_decryption()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::Application);
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let mut vault = FileVault::create(&path, &password(), &identity_payload()?, &initial)?;
        let record = vault.create_secret(
            SecretName::new("TOKEN")?,
            &SecretValue::new(b"test-token".to_vec()),
        )?;
        let mut policy = PolicySet::new();
        assert!(policy.insert(PolicyRule::new(
            identity,
            record.id(),
            Operation::Use,
            PolicyEffect::Allow,
        )));
        let document = PolicyDocument::new(2, policy)?.encode()?;
        assert_eq!(vault.replace_policy_payload(1, &document)?, 2);
        drop(vault);
        corrupt_envelope(&path, "/records/0/value_envelope/ciphertext")?;
        let audit = MemoryAudit {
            events: Vec::new(),
            fail: true,
        };
        let mut broker = SecretBroker::open(&path, &password(), audit)?;

        assert!(matches!(
            broker.use_secret(&verified(identity), record.id()),
            Err(BrokerError::AuditUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn exists_is_also_a_separate_audited_permission() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let identity = caller(1, CallerKind::Application);
        let secret_id = SecretId::from_bytes([0x44; SecretId::BYTE_LENGTH]);
        let vault = create_vault_with_policy(&path, identity, &[(secret_id, Operation::Exists)])?;
        let mut broker = SecretBroker::from_unlocked_vault(vault, MemoryAudit::default())?;

        assert!(!broker.exists(&verified(identity), secret_id)?);
        assert!(matches!(
            broker.use_secret(&verified(identity), secret_id),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        Ok(())
    }

    fn corrupt_envelope(path: &Path, pointer: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(&fs::read(path)?)?;
        let ciphertext = document
            .pointer_mut(pointer)
            .and_then(|value| value.as_str())
            .ok_or("missing test ciphertext")?
            .to_owned();
        let mut bytes = ciphertext.into_bytes();
        let first = bytes.first_mut().ok_or("empty test ciphertext")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        *document
            .pointer_mut(pointer)
            .ok_or("missing test ciphertext")? = Value::String(String::from_utf8(bytes)?);
        fs::write(path, serde_json::to_vec_pretty(&document)?)?;
        Ok(())
    }

    fn corrupt_record_envelope(
        path: &Path,
        secret_id: SecretId,
        envelope_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut document: Value = serde_json::from_slice(&fs::read(path)?)?;
        let records = document
            .get_mut("records")
            .and_then(Value::as_array_mut)
            .ok_or("missing test records")?;
        let target_id = secret_id.to_string();
        let record = records
            .iter_mut()
            .find(|record| {
                record.get("secret_id").and_then(Value::as_str) == Some(target_id.as_str())
            })
            .ok_or("missing test record")?;
        let ciphertext = record
            .get_mut(envelope_name)
            .and_then(|envelope| envelope.get_mut("ciphertext"))
            .and_then(|value| value.as_str())
            .ok_or("missing test ciphertext")?
            .to_owned();
        let mut bytes = ciphertext.into_bytes();
        let first = bytes.first_mut().ok_or("empty test ciphertext")?;
        *first = if *first == b'A' { b'B' } else { b'A' };
        *record
            .get_mut(envelope_name)
            .and_then(|envelope| envelope.get_mut("ciphertext"))
            .ok_or("missing test ciphertext")? = Value::String(String::from_utf8(bytes)?);
        fs::write(path, serde_json::to_vec_pretty(&document)?)?;
        Ok(())
    }

    #[test]
    fn corrupted_policy_envelope_opens_in_fail_closed_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        drop(FileVault::create(
            &path,
            &password(),
            &identity_payload()?,
            &initial,
        )?);
        corrupt_envelope(&path, "/policy/envelope/ciphertext")?;

        let broker = SecretBroker::open(&path, &password(), MemoryAudit::default())?;
        assert_eq!(broker.policy_availability(), PolicyAvailability::Invalid);
        Ok(())
    }

    #[test]
    fn broker_error_never_contains_secret_value() {
        let error = BrokerError::Vault(VaultError::SecretValueTooLarge);
        let rendered = error.to_string();

        assert!(!rendered.contains("test-token"));
    }

    #[test]
    fn secret_input_never_enters_audit_or_error_rendering() -> Result<(), Box<dyn std::error::Error>>
    {
        const SENTINEL: &[u8] = b"ENVVAULT_SECRET_SENTINEL_9f2c7a";
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        broker.create_managed_secret(
            &owner,
            SecretName::new("SAFE_NAME")?,
            &SecretValue::new(SENTINEL.to_vec()),
        )?;

        for event in &broker.audit.events {
            let encoded = event
                .encode()
                .map_err(|_| "audit event could not be encoded")?;
            assert!(
                !encoded
                    .windows(SENTINEL.len())
                    .any(|window| window == SENTINEL)
            );
            assert!(!format!("{event:?}").contains("ENVVAULT_SECRET_SENTINEL"));
        }
        let failure = BrokerError::Vault(VaultError::SecretValueTooLarge);
        assert!(!failure.to_string().contains("ENVVAULT_SECRET_SENTINEL"));
        assert!(!format!("{failure:?}").contains("ENVVAULT_SECRET_SENTINEL"));
        Ok(())
    }

    #[test]
    fn verify_is_exact_value_free_and_upgrades_only_the_legacy_owner_grant()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("legacy-verify.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let first = broker.create_managed_secret(
            &owner,
            SecretName::new("FIRST_TOKEN")?,
            &SecretValue::new(b"first-value".to_vec()),
        )?;
        let second = broker.create_managed_secret(
            &owner,
            SecretName::new("SECOND_TOKEN")?,
            &SecretValue::new(b"second-value".to_vec()),
        )?;

        let document = broker.read_policy(&owner)?;
        let mut policy = document.policy().clone();
        assert!(policy.remove(&PolicyRule::new(
            owner.caller(),
            first.id(),
            Operation::Verify,
            PolicyEffect::Allow,
        )));
        assert!(policy.remove(&PolicyRule::new(
            owner.caller(),
            second.id(),
            Operation::Verify,
            PolicyEffect::Allow,
        )));
        broker.replace_policy(
            &owner,
            document.generation(),
            policy,
            document.vault_policy().clone(),
        )?;
        let generation = broker.policy_generation();

        assert_eq!(
            broker.verify_secret_by_name(
                &owner,
                &SecretName::new("FIRST_TOKEN")?,
                &SecretValue::new(b"first-value".to_vec()),
            )?,
            Some(true)
        );
        assert_eq!(broker.policy_generation(), generation + 1);
        let upgraded = broker.read_policy(&owner)?;
        assert!(upgraded.policy().rules().any(|rule| {
            rule.caller() == owner.caller()
                && rule.secret_id() == first.id()
                && rule.operation() == Operation::Verify
                && rule.effect() == PolicyEffect::Allow
        }));
        assert!(!upgraded.policy().rules().any(|rule| {
            rule.caller() == owner.caller()
                && rule.secret_id() == second.id()
                && rule.operation() == Operation::Verify
        }));
        assert!(broker.audit.events.iter().all(|event| {
            event.encode().is_ok_and(|bytes| {
                !bytes
                    .windows(b"first-value".len())
                    .any(|window| window == b"first-value")
                    && !bytes
                        .windows(b"\"match\"".len())
                        .any(|window| window == b"\"match\"")
                    && !bytes
                        .windows(b"\"mismatch\"".len())
                        .any(|window| window == b"\"mismatch\"")
            })
        }));
        Ok(())
    }

    #[test]
    fn owner_bootstrap_is_single_use_and_reopens_the_same_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let owner_caller = owner.caller();

        assert_eq!(owner_caller.kind(), CallerKind::Human);
        assert_eq!(
            owner.authentication_method(),
            AuthenticationMethod::MasterPassword
        );
        assert_eq!(broker.policy_availability(), PolicyAvailability::Active);
        drop(broker);

        let (reopened, reopened_owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        assert_eq!(reopened_owner.caller(), owner_caller);
        drop(reopened);
        assert!(matches!(
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default()),
            Err(BrokerError::Vault(VaultError::AlreadyExists))
        ));
        Ok(())
    }

    #[test]
    fn broker_persists_a_denied_decision_before_returning() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let requested = SecretId::from_bytes([0x71; SecretId::BYTE_LENGTH]);

        assert!(matches!(
            broker.use_secret(&owner, requested),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        drop(broker);

        let (mut reopened, reopened_owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        let events = reopened.read_audit(&reopened_owner)?;
        assert_eq!(events.len(), 2);
        let event = events[0];
        assert_eq!(event.caller(), owner.caller());
        assert_eq!(event.secret_id(), Some(requested));
        assert_eq!(event.operation(), Some(Operation::Use));
        assert!(event.decision().is_denied());
        Ok(())
    }

    #[test]
    fn explicit_v1_migration_preserves_order_then_switches_to_v2_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("legacy-vault.json");
        let owner_id = CallerId::from_bytes([0x90; 16]);
        let identity = IdentityRegistryDocument::new(1, owner_id).encode()?;
        let owner_caller = Caller::new(owner_id, CallerKind::Human);
        let policy = PolicyDocument::new_with_vault_policy(
            1,
            PolicySet::new(),
            owner_vault_policy(owner_caller),
        )?
        .encode()?;
        let mut legacy = FileVault::create(&path, &password(), &identity, &policy)?;
        let first = AuditEvent::now_vault(
            owner_caller,
            AuthenticationMethod::MasterPassword,
            VaultOperation::ReadAudit,
            PolicyDecision::Allow,
        );
        legacy.append_audit_payload(&first.encode().map_err(|_| "event encode failed")?)?;
        drop(legacy);

        let (mut broker, owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        assert_eq!(broker.migrate_audit_v2(&owner)?, 2);
        assert!(matches!(
            broker.migrate_audit_v2(&owner),
            Err(BrokerError::AuditMigrationInvalid)
        ));
        let events = broker.read_audit(&owner)?;
        assert_eq!(events[0], first);
        assert_eq!(events.len(), 4);
        drop(broker);

        let legacy = FileVault::open(&path, &password())?;
        assert_eq!(legacy.audit_payloads()?.len(), 2);
        Ok(())
    }

    #[test]
    fn malformed_authenticated_identity_registry_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let initial = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        drop(FileVault::create(
            &path,
            &password(),
            b"not-an-identity-registry",
            &initial,
        )?);

        assert!(matches!(
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default()),
            Err(BrokerError::IdentityUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn tampered_identity_registry_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (broker, _owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        drop(broker);
        corrupt_envelope(&path, "/identity/envelope/ciphertext")?;

        assert!(matches!(
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default()),
            Err(BrokerError::Vault(VaultError::CorruptedIdentity))
        ));
        Ok(())
    }

    #[test]
    fn explicit_owner_create_grant_does_not_grant_secret_use()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;

        let record = broker.create_secret(
            &owner,
            SecretName::new("CREATED_TOKEN")?,
            &SecretValue::new(b"test-created-value".to_vec()),
        )?;
        assert!(matches!(
            broker.use_secret(&owner, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        assert_eq!(broker.audit.events.len(), 2);
        assert_eq!(
            broker.audit.events[0].vault_operation(),
            Some(VaultOperation::CreateSecret)
        );
        assert_eq!(broker.audit.events[0].secret_id(), None);
        Ok(())
    }

    #[test]
    fn another_human_cannot_inherit_owner_create_permission()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, _owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let impostor = verified(caller(0x55, CallerKind::Human));

        assert!(matches!(
            broker.create_secret(
                &impostor,
                SecretName::new("DENIED_TOKEN")?,
                &SecretValue::new(b"test-denied-value".to_vec()),
            ),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        assert!(broker.vault.secret_ids().is_empty());
        assert_eq!(
            broker.audit.events[0].vault_operation(),
            Some(VaultOperation::CreateSecret)
        );
        assert!(broker.audit.events[0].decision().is_denied());
        Ok(())
    }

    #[test]
    fn audit_failure_prevents_secret_creation() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        drop(broker);
        let (mut broker, owner_again) = SecretBroker::open_owner(
            &path,
            &password(),
            MemoryAudit {
                events: Vec::new(),
                fail: true,
            },
        )?;
        assert_eq!(owner_again.caller(), owner.caller());

        assert!(matches!(
            broker.create_secret(
                &owner_again,
                SecretName::new("NOT_CREATED")?,
                &SecretValue::new(b"test-not-created".to_vec()),
            ),
            Err(BrokerError::AuditUnavailable)
        ));
        assert!(broker.vault.secret_ids().is_empty());
        Ok(())
    }

    #[test]
    fn owner_policy_update_grants_only_the_exact_secret_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let record = broker.create_secret(
            &owner,
            SecretName::new("POLICY_TOKEN")?,
            &SecretValue::new(b"test-policy-value".to_vec()),
        )?;
        let mut secret_policy = PolicySet::new();
        assert!(secret_policy.insert(PolicyRule::new(
            owner.caller(),
            record.id(),
            Operation::Use,
            PolicyEffect::Allow,
        )));

        assert_eq!(
            broker.replace_policy(
                &owner,
                1,
                secret_policy.clone(),
                owner_vault_policy(owner.caller()),
            )?,
            2
        );
        assert_eq!(broker.policy_generation(), 2);
        assert_eq!(
            broker.use_secret(&owner, record.id())?.expose_secret(),
            b"test-policy-value"
        );
        assert!(matches!(
            broker.read_plaintext(&owner, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));

        assert!(matches!(
            broker.replace_policy(&owner, 1, secret_policy, owner_vault_policy(owner.caller()),),
            Err(BrokerError::Vault(VaultError::PolicyGenerationMismatch))
        ));
        assert_eq!(broker.policy_generation(), 2);
        let active = broker.read_policy(&owner)?;
        assert_eq!(active.generation(), 2);
        assert_eq!(active.policy().len(), 1);
        Ok(())
    }

    #[test]
    fn profile_grant_is_exact_idempotent_and_still_requires_authenticated_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let first = broker.create_managed_secret(
            &owner,
            SecretName::new("DATABASE_URL")?,
            &SecretValue::new(b"postgres://profile-test".to_vec()),
        )?;
        let second = broker.create_managed_secret(
            &owner,
            SecretName::new("JWT_SECRET")?,
            &SecretValue::new(b"jwt-profile-test".to_vec()),
        )?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("profile-backend")?,
        )?;
        let application = issued.caller();
        let credential = issued.into_credential();
        let application_identity =
            broker.authenticate_caller(application.id(), application.kind(), &credential)?;

        assert!(matches!(
            broker.use_secret(&application_identity, first.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        let generation =
            broker.grant_profile_use(&owner, application.id(), &[first.id(), second.id()])?;
        assert_eq!(
            broker.grant_profile_use(&owner, application.id(), &[first.id(), second.id()],)?,
            generation
        );

        let results = broker.use_batch(&application_identity, [first.id(), second.id()])?;
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|result| result.decision().is_allowed()));
        assert_eq!(
            results[0]
                .value()
                .ok_or("first value missing")?
                .expose_secret(),
            b"postgres://profile-test"
        );
        let impostor = verified(caller(0x66, CallerKind::Application));
        assert!(matches!(
            broker.use_secret(&impostor, first.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        Ok(())
    }

    #[test]
    fn audit_read_requires_its_own_vault_permission() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let other = verified(caller(0x66, CallerKind::Human));

        assert!(matches!(
            broker.read_audit(&other),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        let events = broker.read_audit(&owner)?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].vault_operation(), Some(VaultOperation::ReadAudit));
        assert!(events[0].decision().is_denied());
        assert_eq!(events[1].vault_operation(), Some(VaultOperation::ReadAudit));
        assert_eq!(events[1].decision(), PolicyDecision::Allow);
        Ok(())
    }

    #[test]
    fn application_credential_authenticates_after_reopen_and_revocation_invalidates_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("test-backend")?,
        )?;
        let application = issued.caller();
        let credential = issued.into_credential();
        assert_eq!(broker.identity_generation(), 2);
        drop(broker);

        let (mut reopened, reopened_owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        let verified =
            reopened.authenticate_caller(application.id(), application.kind(), &credential)?;
        assert_eq!(verified.caller(), application);
        assert_eq!(
            verified.authentication_method(),
            AuthenticationMethod::ApplicationCredential
        );
        assert_eq!(reopened.registered_callers(&reopened_owner)?.len(), 1);
        assert_eq!(
            reopened.revoke_caller(&reopened_owner, application.id())?,
            4
        );
        drop(reopened);
        let (mut reopened, _owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        assert!(matches!(
            reopened.authenticate_caller(application.id(), application.kind(), &credential),
            Err(BrokerError::IdentityUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn credential_rotation_preserves_identity_and_invalidates_the_old_credential()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("rotation.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("rotating-backend")?,
        )?;
        let caller = issued.caller();
        let old_credential = issued.into_credential();

        let prepared = broker.prepare_caller_rotation(&owner, caller.id())?;
        assert_eq!(prepared.issued().caller(), caller);
        let rotated = broker.commit_caller_rotation(&owner, prepared)?;
        assert_eq!(rotated.caller(), caller);
        assert_eq!(broker.identity_generation(), 3);
        assert!(broker.caller_credential_is_current(&owner, caller, rotated.credential())?);
        assert!(!broker.caller_credential_is_current(&owner, caller, &old_credential)?);
        assert!(matches!(
            broker.authenticate_caller(caller.id(), caller.kind(), &old_credential),
            Err(BrokerError::IdentityUnavailable)
        ));
        assert_eq!(
            broker
                .authenticate_caller(caller.id(), caller.kind(), rotated.credential())?
                .caller(),
            caller
        );
        Ok(())
    }

    #[test]
    fn credential_expiry_is_registry_enforced_and_rotation_restores_access()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("credential-expiry.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued_at = 100_u64;
        let expires_at = issued_at + DEFAULT_CREDENTIAL_LIFETIME_MILLIS;
        let issued = broker.register_caller_at(
            &owner,
            CallerKind::Application,
            CallerName::new("expiring-backend")?,
            issued_at,
        )?;
        let caller = issued.caller();
        assert_eq!(
            broker.registered_callers(&owner)?[0].credential_expires_unix_time_millis(),
            Some(expires_at)
        );
        assert!(
            broker
                .authenticate_caller_at(
                    caller.id(),
                    caller.kind(),
                    issued.credential(),
                    expires_at - 1,
                )
                .is_ok()
        );
        for now in [expires_at, 50] {
            assert!(matches!(
                broker
                    .authenticate_caller_at(caller.id(), caller.kind(), issued.credential(), now,),
                Err(BrokerError::IdentityUnavailable)
            ));
        }

        let rotated_at = expires_at + 10;
        let prepared = broker.prepare_caller_rotation_at(&owner, caller.id(), rotated_at)?;
        let rotated = broker.commit_caller_rotation(&owner, prepared)?;
        assert_eq!(
            broker.registered_callers(&owner)?[0].credential_expires_unix_time_millis(),
            Some(rotated_at + DEFAULT_CREDENTIAL_LIFETIME_MILLIS)
        );
        assert!(
            broker
                .authenticate_caller_at(
                    caller.id(),
                    caller.kind(),
                    rotated.credential(),
                    rotated_at,
                )
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn authentication_throttle_persists_and_clock_rollback_cannot_bypass_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("authentication-throttle.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller_at(
            &owner,
            CallerKind::Application,
            CallerName::new("throttled-backend")?,
            1,
        )?;
        let caller = issued.caller();
        let wrong = CallerCredential::from_bytes([0xF1; CallerCredential::LENGTH]);
        for attempt in 0..5_u64 {
            assert!(matches!(
                broker.authenticate_caller_at(caller.id(), caller.kind(), &wrong, 100 + attempt,),
                Err(BrokerError::IdentityUnavailable)
            ));
        }
        assert!(matches!(
            broker.authenticate_caller_at(caller.id(), caller.kind(), issued.credential(), 105,),
            Err(BrokerError::IdentityUnavailable)
        ));
        drop(broker);

        let (mut reopened, reopened_owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        assert!(matches!(
            reopened.authenticate_caller_at(caller.id(), caller.kind(), issued.credential(), 50,),
            Err(BrokerError::IdentityUnavailable)
        ));
        assert_eq!(
            reopened
                .authenticate_caller_at(caller.id(), caller.kind(), issued.credential(), 60_104,)?
                .caller(),
            caller
        );
        let authentication_events = reopened
            .read_audit(&reopened_owner)?
            .into_iter()
            .filter(|event| event.is_authentication_attempt())
            .collect::<Vec<_>>();
        assert_eq!(authentication_events.len(), 8);
        assert!(
            authentication_events[..7]
                .iter()
                .all(|event| { event.caller() == caller && event.decision().is_denied() })
        );
        assert!(authentication_events[7].decision().is_allowed());
        Ok(())
    }

    #[test]
    fn concurrent_authentication_throttle_update_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory
            .path()
            .join("authentication-concurrency.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller_at(
            &owner,
            CallerKind::AiAgent,
            CallerName::new("concurrent-agent")?,
            1,
        )?;
        drop(broker);
        let mut first = SecretBroker::open(&path, &password(), MemoryAudit::default())?;
        let mut stale = SecretBroker::open(&path, &password(), MemoryAudit::default())?;

        assert!(
            first
                .authenticate_caller_at(
                    issued.caller().id(),
                    issued.caller().kind(),
                    issued.credential(),
                    500,
                )
                .is_ok()
        );
        assert!(matches!(
            stale.authenticate_caller_at(
                issued.caller().id(),
                issued.caller().kind(),
                issued.credential(),
                500,
            ),
            Err(BrokerError::IdentityUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn wrong_unknown_and_wrong_kind_credentials_fail_uniformly()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued =
            broker.register_caller(&owner, CallerKind::AiAgent, CallerName::new("test-agent")?)?;
        let agent = issued.caller();
        let credential = issued.into_credential();
        let wrong = CallerCredential::from_bytes([0xFF; CallerCredential::LENGTH]);

        for result in [
            broker.authenticate_caller(agent.id(), agent.kind(), &wrong),
            broker.authenticate_caller(
                CallerId::from_bytes([0xEE; CallerId::BYTE_LENGTH]),
                agent.kind(),
                &wrong,
            ),
            broker.authenticate_caller(agent.id(), CallerKind::Application, &credential),
            broker.authenticate_caller(agent.id(), CallerKind::Human, &credential),
        ] {
            assert!(matches!(result, Err(BrokerError::IdentityUnavailable)));
        }
        let verified = broker.authenticate_caller(agent.id(), agent.kind(), &credential)?;
        assert_eq!(
            verified.authentication_method(),
            AuthenticationMethod::AgentCredential
        );
        let authentication_events = broker
            .audit
            .events
            .iter()
            .copied()
            .filter(|event| event.is_authentication_attempt())
            .collect::<Vec<_>>();
        assert_eq!(authentication_events.len(), 4);
        assert!(
            authentication_events[..3]
                .iter()
                .all(|event| event.decision().is_denied())
        );
        assert!(authentication_events[3].decision().is_allowed());
        assert!(authentication_events.iter().all(|event| {
            event.secret_id().is_none()
                && event.operation().is_none()
                && event.vault_operation().is_none()
        }));
        Ok(())
    }

    #[test]
    fn external_audit_failure_prevents_successful_machine_authentication()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory
            .path()
            .join("authentication-audit-failure.vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("audit-failure-application")?,
        )?;
        let caller = issued.caller();
        let credential = issued.into_credential();
        drop(broker);

        let mut reopened = SecretBroker::open(
            &path,
            &password(),
            MemoryAudit {
                events: Vec::new(),
                fail: true,
            },
        )?;
        assert!(matches!(
            reopened.authenticate_caller(caller.id(), caller.kind(), &credential),
            Err(BrokerError::AuditUnavailable)
        ));
        drop(reopened);

        let (mut recovered, recovered_owner) =
            SecretBroker::open_owner(&path, &password(), MemoryAudit::default())?;
        let events = recovered.read_audit(&recovered_owner)?;
        assert!(events.iter().any(|event| {
            event.is_authentication_attempt()
                && event.caller() == caller
                && event.decision().is_allowed()
        }));
        Ok(())
    }

    #[test]
    fn issued_credential_is_not_persisted_as_raw_or_base64()
    -> Result<(), Box<dyn std::error::Error>> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("credential-storage-test")?,
        )?;
        broker.authenticate_caller(
            issued.caller().id(),
            issued.caller().kind(),
            issued.credential(),
        )?;
        let raw = issued.credential().expose_secret();
        let encoded = STANDARD.encode(raw);
        drop(broker);
        let file = fs::read(&path)?;

        assert!(!file.windows(raw.len()).any(|window| window == raw));
        assert!(
            !file
                .windows(encoded.len())
                .any(|window| window == encoded.as_bytes())
        );
        Ok(())
    }

    #[test]
    fn audit_failure_prevents_identity_registration() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        drop(broker);
        let (mut broker, owner_again) = SecretBroker::open_owner(
            &path,
            &password(),
            MemoryAudit {
                events: Vec::new(),
                fail: true,
            },
        )?;
        assert_eq!(owner_again.caller(), owner.caller());

        assert!(matches!(
            broker.register_caller(
                &owner_again,
                CallerKind::Application,
                CallerName::new("not-registered")?,
            ),
            Err(BrokerError::AuditUnavailable)
        ));
        assert_eq!(broker.identity_generation(), 1);
        assert!(broker.identities.callers().is_empty());
        Ok(())
    }

    #[test]
    fn authenticated_application_still_needs_exact_secret_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        let issued = broker.register_caller(
            &owner,
            CallerKind::Application,
            CallerName::new("least-privilege-app")?,
        )?;
        let application = issued.caller();
        let verified = broker.authenticate_caller(
            application.id(),
            application.kind(),
            issued.credential(),
        )?;
        let record = broker.create_secret(
            &owner,
            SecretName::new("APP_TOKEN")?,
            &SecretValue::new(b"test-app-value".to_vec()),
        )?;
        assert!(matches!(
            broker.use_secret(&verified, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        let mut secret_policy = PolicySet::new();
        assert!(secret_policy.insert(PolicyRule::new(
            application,
            record.id(),
            Operation::Use,
            PolicyEffect::Allow,
        )));
        broker.replace_policy(&owner, 1, secret_policy, owner_vault_policy(owner.caller()))?;

        assert_eq!(
            broker.use_secret(&verified, record.id())?.expose_secret(),
            b"test-app-value"
        );
        assert!(matches!(
            broker.read_plaintext(&verified, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        Ok(())
    }

    #[test]
    fn managed_secret_creation_grants_only_owner_management_operations()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;

        let record = broker.create_managed_secret(
            &owner,
            SecretName::new("MANAGED_TOKEN")?,
            &SecretValue::new(b"first-value".to_vec()),
        )?;
        assert_eq!(broker.policy_generation(), 2);
        assert_eq!(broker.list(&owner)?, vec![record.clone()]);
        assert!(broker.exists(&owner, record.id())?);
        assert!(matches!(
            broker.use_secret(&owner, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));
        assert!(matches!(
            broker.read_plaintext(&owner, record.id()),
            Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
        ));

        let replaced = broker.replace_secret(
            &owner,
            record.id(),
            &SecretValue::new(b"second-value".to_vec()),
        )?;
        assert_eq!(replaced, record);
        broker.delete_secret(&owner, record.id())?;
        assert!(!broker.exists(&owner, record.id())?);
        assert!(broker.list(&owner)?.is_empty());
        Ok(())
    }

    #[test]
    fn managed_import_is_atomic_and_preserves_per_secret_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (mut broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;

        let first = broker.import_managed_secrets(
            &owner,
            vec![
                (
                    SecretName::new("DATABASE_URL")?,
                    SecretValue::new(b"first-database".to_vec()),
                ),
                (
                    SecretName::new("API_TOKEN")?,
                    SecretValue::new(b"first-token".to_vec()),
                ),
            ],
        )?;
        assert_eq!(first.len(), 2);
        assert_eq!(broker.policy_generation(), 2);
        for record in &first {
            assert!(matches!(
                broker.use_secret(&owner, record.id()),
                Err(BrokerError::AccessDenied(DenyReason::NoMatchingGrant))
            ));
        }

        let second = broker.import_managed_secrets(
            &owner,
            vec![
                (
                    SecretName::new("DATABASE_URL")?,
                    SecretValue::new(b"second-database".to_vec()),
                ),
                (
                    SecretName::new("NEW_TOKEN")?,
                    SecretValue::new(b"new-token".to_vec()),
                ),
            ],
        )?;
        assert_eq!(second.len(), 2);
        assert_eq!(broker.policy_generation(), 3);
        let third = broker.import_managed_secrets(
            &owner,
            vec![(
                SecretName::new("DATABASE_URL")?,
                SecretValue::new(b"third-database".to_vec()),
            )],
        )?;
        assert_eq!(third.len(), 1);
        assert_eq!(broker.policy_generation(), 3);
        drop(broker);

        let vault = FileVault::open(&path, &password())?;
        let records = vault.records()?;
        assert_eq!(records.len(), 3);
        let database = records
            .iter()
            .find(|record| record.name().as_str() == "DATABASE_URL")
            .ok_or("missing database")?;
        assert_eq!(
            vault.read_secret(database.id())?.expose_secret(),
            b"third-database"
        );
        Ok(())
    }

    #[test]
    fn audit_failure_prevents_managed_import() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let (broker, owner) =
            SecretBroker::bootstrap_owner(&path, &password(), MemoryAudit::default())?;
        drop(broker);
        let vault = FileVault::open(&path, &password())?;
        let mut broker = SecretBroker::from_unlocked_vault(
            vault,
            MemoryAudit {
                events: Vec::new(),
                fail: true,
            },
        )?;

        assert!(matches!(
            broker.import_managed_secrets(
                &owner,
                vec![(
                    SecretName::new("MUST_NOT_IMPORT")?,
                    SecretValue::new(b"not-imported".to_vec()),
                )],
            ),
            Err(BrokerError::AuditUnavailable)
        ));
        drop(broker);
        assert!(FileVault::open(&path, &password())?.secret_ids().is_empty());
        Ok(())
    }

    #[test]
    fn identity_document_generation_mismatch_fails_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mismatched =
            IdentityRegistryDocument::new(2, CallerId::from_bytes([0x77; 16])).encode()?;
        let policy = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let vault = FileVault::create(&path, &password(), &mismatched, &policy)?;

        assert!(matches!(
            SecretBroker::from_unlocked_vault(vault, MemoryAudit::default()),
            Err(BrokerError::IdentityUnavailable)
        ));
        Ok(())
    }

    #[test]
    fn identity_kdf_resource_exhaustion_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("vault.json");
        let mut registry = IdentityRegistryDocument::new(1, CallerId::from_bytes([0x78; 16]));
        registry.insert(
            RegisteredCaller::new(
                caller(0x79, CallerKind::Application),
                CallerName::new("malicious-kdf")?,
            ),
            CredentialVerifier::new(256 * 1024 + 1, 1, 1, [0x7a; 16], [0x7b; 32]),
            100,
            100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
        )?;
        let policy = PolicyDocument::new(1, PolicySet::new())?.encode()?;
        let vault = FileVault::create(&path, &password(), &registry.encode()?, &policy)?;

        assert!(matches!(
            SecretBroker::from_unlocked_vault(vault, MemoryAudit::default()),
            Err(BrokerError::IdentityUnavailable)
        ));
        Ok(())
    }
}
