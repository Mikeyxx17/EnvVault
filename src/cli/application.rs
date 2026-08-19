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
    secret::{SecretId, SecretName, SecretRecord, SecretValue},
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

    pub(super) fn plan_import(
        &mut self,
        names: &[SecretName],
    ) -> Result<Vec<crate::broker::service::ImportPlanItem>, CliError> {
        Ok(self.broker.plan_import(&self.actor, names)?)
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
        Ok(self
            .broker
            .grant_profile_use(&self.actor, caller_id, &profile_secret_ids(profile))?)
    }

    pub(super) fn grant_profile_inspect(
        &mut self,
        caller_id: CallerId,
        profile: &Profile,
    ) -> Result<u64, CliError> {
        Ok(self.broker.grant_profile_inspect(
            &self.actor,
            caller_id,
            &profile_secret_ids(profile),
        )?)
    }

    pub(super) fn revoke_use(
        &mut self,
        caller_id: CallerId,
        secret_ids: &[SecretId],
    ) -> Result<u64, CliError> {
        Ok(self
            .broker
            .revoke_profile_use(&self.actor, caller_id, secret_ids)?)
    }

    pub(super) fn secret_ids_for_names(
        &mut self,
        names: Vec<SecretName>,
    ) -> Result<Vec<SecretId>, CliError> {
        let records = self.list_secrets()?;
        let mut secret_ids = Vec::with_capacity(names.len());
        for name in names {
            let record = records
                .iter()
                .find(|record| record.name() == &name)
                .ok_or(CliError::SecretUnavailable)?;
            secret_ids.push(record.id());
        }
        secret_ids.sort_unstable();
        secret_ids.dedup();
        Ok(secret_ids)
    }

    pub(super) fn list_policy_rules(
        &mut self,
    ) -> Result<(u64, Vec<crate::broker::service::PolicyRuleListing>), CliError> {
        Ok(self.broker.list_policy_rules(&self.actor)?)
    }

    pub(super) fn use_grant_labels(&mut self) -> Result<Vec<(SecretId, String)>, CliError> {
        Ok(self.broker.use_grant_labels(&self.actor)?)
    }

    pub(super) fn use_profile(
        &mut self,
        profile: &Profile,
    ) -> Result<Vec<InjectedSecret>, CliError> {
        let results = self.broker.use_batch(
            &self.actor,
            profile.bindings().iter().map(ProfileBinding::secret_id),
        )?;
        let mut injected = Vec::with_capacity(results.len());
        for (binding, result) in profile.bindings().iter().zip(results) {
            if result.decision().is_denied() {
                if self.broker.contains_secret(result.secret_id()) {
                    return Err(CliError::SecretNotAuthorized);
                }
                return Err(CliError::SecretMissing);
            }
            let value = result.into_value().ok_or(CliError::SecretUnavailable)?;
            injected.push(InjectedSecret::new(binding.environment().to_owned(), value));
        }
        Ok(injected)
    }

    pub(super) fn preview_profile_use(
        &mut self,
        profile: &Profile,
    ) -> Result<Vec<(String, crate::broker::service::UsePreviewOutcome)>, CliError> {
        let previews = self.broker.preview_use(
            &self.actor,
            profile.bindings().iter().map(ProfileBinding::secret_id),
        )?;
        Ok(profile
            .bindings()
            .iter()
            .zip(previews)
            .map(|(binding, preview)| (binding.environment().to_owned(), preview.outcome()))
            .collect())
    }

    pub(super) fn rename_secret(
        &mut self,
        current: &SecretName,
        new_name: SecretName,
    ) -> Result<SecretRecord, CliError> {
        Ok(self
            .broker
            .rename_secret_by_name(&self.actor, current, new_name)?)
    }

    pub(super) fn change_password(
        &mut self,
        new_password: &MasterPassword,
    ) -> Result<(), CliError> {
        Ok(self.broker.change_password(&self.actor, new_password)?)
    }

    pub(super) fn audit_events(&mut self) -> Result<Vec<AuditEvent>, CliError> {
        Ok(self.broker.read_audit(&self.actor)?)
    }

    pub(super) fn migrate_audit_v2(&mut self) -> Result<usize, CliError> {
        Ok(self.broker.migrate_audit_v2(&self.actor)?)
    }
}

fn profile_secret_ids(profile: &Profile) -> Vec<SecretId> {
    profile
        .bindings()
        .iter()
        .map(ProfileBinding::secret_id)
        .collect()
}

struct NoExternalAudit;

impl AuditSink for NoExternalAudit {
    fn record(&mut self, _event: AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}
