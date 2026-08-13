use std::path::Path;

use crate::{
    audit::{AuditError, AuditEvent, AuditSink},
    broker::service::{PreparedCallerRegistration, PreparedCallerRotation, SecretBroker},
    crypto::MasterPassword,
    dotenv::DotenvEntry,
    identity::{
        Caller, CallerCredential, CallerId, CallerKind, CallerName, IssuedCallerCredential,
        RegisteredCaller, VerifiedCaller,
    },
    process::InjectedSecret,
    profile::{Profile, ProfileBinding},
    secret::{SecretName, SecretRecord, SecretValue},
};

use super::credential_recovery;
use super::error::CliError;

pub(super) struct CliApplication {
    broker: SecretBroker<NoExternalAudit>,
    actor: VerifiedCaller,
}

impl CliApplication {
    pub(super) fn init(path: &Path, password: &MasterPassword) -> Result<Caller, CliError> {
        let (_broker, owner) = SecretBroker::bootstrap_owner(path, password, NoExternalAudit)?;
        Ok(owner.caller())
    }

    pub(super) fn open_owner(path: &Path, password: &MasterPassword) -> Result<Self, CliError> {
        let (broker, owner) = SecretBroker::open_owner(path, password, NoExternalAudit)?;
        let mut application = Self {
            broker,
            actor: owner,
        };
        credential_recovery::recover(path, &mut application)?;
        Ok(application)
    }

    pub(super) fn open_owner_for_audit_migration(
        path: &Path,
        password: &MasterPassword,
    ) -> Result<Self, CliError> {
        let (broker, owner) =
            SecretBroker::open_owner_for_audit_migration(path, password, NoExternalAudit)?;
        Ok(Self {
            broker,
            actor: owner,
        })
    }

    pub(super) fn open_caller(
        path: &Path,
        password: &MasterPassword,
        caller_id: CallerId,
        kind: CallerKind,
        credential: &CallerCredential,
    ) -> Result<Self, CliError> {
        let mut broker = SecretBroker::open(path, password, NoExternalAudit)?;
        let actor = broker.authenticate_caller(caller_id, kind, credential)?;
        Ok(Self { broker, actor })
    }

    pub(super) fn open_caller_with_machine_unlock(
        path: &Path,
        caller_id: CallerId,
        kind: CallerKind,
        credential: &CallerCredential,
    ) -> Result<Self, CliError> {
        let master_key = crate::keystore::unlock(path)?;
        let mut broker = SecretBroker::open_with_master_key(path, master_key, NoExternalAudit)?;
        let actor = broker.authenticate_caller(caller_id, kind, credential)?;
        Ok(Self { broker, actor })
    }

    pub(super) const fn authenticated_caller(&self) -> Caller {
        self.actor.caller()
    }

    pub(super) const fn authentication_method(&self) -> crate::identity::AuthenticationMethod {
        self.actor.authentication_method()
    }

    pub(super) fn enable_machine_unlock(
        &mut self,
    ) -> Result<crate::keystore::MachineUnlockStatus, CliError> {
        self.broker
            .grant_self_machine_unlock_management(&self.actor)?;
        Ok(self.broker.enable_machine_unlock(&self.actor)?)
    }

    pub(super) fn machine_unlock_status(
        &mut self,
    ) -> Result<crate::keystore::MachineUnlockStatus, CliError> {
        Ok(self.broker.machine_unlock_status(&self.actor)?)
    }

    pub(super) fn rotate_machine_unlock(
        &mut self,
    ) -> Result<crate::keystore::MachineUnlockStatus, CliError> {
        Ok(self.broker.rotate_machine_unlock(&self.actor)?)
    }

    pub(super) fn disable_machine_unlock(
        &mut self,
    ) -> Result<crate::keystore::MachineUnlockStatus, CliError> {
        Ok(self.broker.disable_machine_unlock(&self.actor)?)
    }

    pub(super) fn prepare_caller_registration(
        &mut self,
        kind: CallerKind,
        name: String,
    ) -> Result<PreparedCallerRegistration, CliError> {
        Ok(self
            .broker
            .prepare_caller_registration(&self.actor, kind, CallerName::new(name)?)?)
    }

    pub(super) fn commit_caller_registration(
        &mut self,
        prepared: PreparedCallerRegistration,
    ) -> Result<IssuedCallerCredential, CliError> {
        Ok(self
            .broker
            .commit_caller_registration(&self.actor, prepared)?)
    }

    pub(super) fn prepare_caller_rotation(
        &mut self,
        caller_id: CallerId,
    ) -> Result<PreparedCallerRotation, CliError> {
        Ok(self
            .broker
            .prepare_caller_rotation(&self.actor, caller_id)?)
    }

    pub(super) fn commit_caller_rotation(
        &mut self,
        prepared: PreparedCallerRotation,
    ) -> Result<IssuedCallerCredential, CliError> {
        Ok(self.broker.commit_caller_rotation(&self.actor, prepared)?)
    }

    pub(super) fn caller_credential_is_current(
        &mut self,
        issued: &IssuedCallerCredential,
    ) -> Result<bool, CliError> {
        Ok(self.broker.caller_credential_is_current(
            &self.actor,
            issued.caller(),
            issued.credential(),
        )?)
    }

    pub(super) fn registered_callers(&mut self) -> Result<Vec<RegisteredCaller>, CliError> {
        Ok(self.broker.registered_callers(&self.actor)?)
    }

    pub(super) fn revoke_caller(&mut self, caller_id: CallerId) -> Result<u64, CliError> {
        Ok(self.broker.revoke_caller(&self.actor, caller_id)?)
    }

    pub(super) fn set_secret(
        &mut self,
        name: SecretName,
        value: &SecretValue,
    ) -> Result<SecretRecord, CliError> {
        if let Some(record) = self
            .broker
            .replace_secret_by_name(&self.actor, &name, value)?
        {
            Ok(record)
        } else {
            Ok(self
                .broker
                .create_managed_secret(&self.actor, name, value)?)
        }
    }

    pub(super) fn list_secrets(&mut self) -> Result<Vec<SecretRecord>, CliError> {
        let mut records = self.broker.list(&self.actor)?;
        records.sort_by(|left, right| left.name().cmp(right.name()));
        Ok(records)
    }

    pub(super) fn secret_exists(&mut self, name: &SecretName) -> Result<bool, CliError> {
        Ok(self.broker.secret_exists_by_name(&self.actor, name)?)
    }

    pub(super) fn verify_secret(
        &mut self,
        name: &SecretName,
        expected: &SecretValue,
    ) -> Result<bool, CliError> {
        self.broker
            .verify_secret_by_name(&self.actor, name, expected)?
            .ok_or(CliError::SecretUnavailable)
    }

    pub(super) fn remove_secret(&mut self, name: &SecretName) -> Result<(), CliError> {
        if self.broker.delete_secret_by_name(&self.actor, name)? {
            Ok(())
        } else {
            Err(CliError::SecretUnavailable)
        }
    }

    pub(super) fn import_secrets(
        &mut self,
        entries: Vec<DotenvEntry>,
    ) -> Result<Vec<SecretRecord>, CliError> {
        Ok(self.broker.import_managed_secrets(
            &self.actor,
            entries.into_iter().map(DotenvEntry::into_parts).collect(),
        )?)
    }

    pub(super) fn create_profile(&mut self, names: Vec<SecretName>) -> Result<Profile, CliError> {
        let records = self.list_secrets()?;
        let mut bindings = Vec::with_capacity(names.len());
        for name in names {
            let record = records
                .iter()
                .find(|record| record.name() == &name)
                .ok_or(CliError::SecretUnavailable)?;
            bindings.push(ProfileBinding::new(name.as_str().to_owned(), record.id())?);
        }
        Ok(Profile::new(bindings)?)
    }

    pub(super) fn grant_profile_use(
        &mut self,
        caller_id: CallerId,
        profile: &Profile,
    ) -> Result<u64, CliError> {
        let secret_ids = profile
            .bindings()
            .iter()
            .map(ProfileBinding::secret_id)
            .collect::<Vec<_>>();
        Ok(self
            .broker
            .grant_profile_use(&self.actor, caller_id, &secret_ids)?)
    }

    pub(super) fn use_profile(
        &mut self,
        profile: &Profile,
    ) -> Result<Vec<InjectedSecret>, CliError> {
        let results = self.broker.use_batch(
            &self.actor,
            profile.bindings().iter().map(ProfileBinding::secret_id),
        )?;
        if results.iter().any(|result| result.decision().is_denied()) {
            return Err(CliError::SecretUnavailable);
        }
        profile
            .bindings()
            .iter()
            .zip(results)
            .map(|(binding, result)| {
                result
                    .into_value()
                    .map(|value| InjectedSecret::new(binding.environment().to_owned(), value))
                    .ok_or(CliError::SecretUnavailable)
            })
            .collect()
    }

    pub(super) fn audit_events(&mut self) -> Result<Vec<AuditEvent>, CliError> {
        Ok(self.broker.read_audit(&self.actor)?)
    }

    pub(super) fn migrate_audit_v2(&mut self) -> Result<usize, CliError> {
        Ok(self.broker.migrate_audit_v2(&self.actor)?)
    }
}

struct NoExternalAudit;

impl AuditSink for NoExternalAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}
