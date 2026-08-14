use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::{
    AuthenticationMethod, Caller, CallerId, CallerKind, CallerName, VerifiedCaller,
    throttle::{
        AuthenticationDisposition, AuthenticationThrottleFile, AuthenticationThrottleState,
    },
};

const FORMAT_NAME: &str = "envvault-identity-registry";
const FORMAT_VERSION: u32 = 3;
const THROTTLE_FORMAT_VERSION: u32 = 2;
const LEGACY_FORMAT_VERSION: u32 = 1;
pub(crate) const MAX_IDENTITY_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_REGISTERED_CALLERS: usize = 256;
pub(crate) const DEFAULT_CREDENTIAL_LIFETIME_MILLIS: u64 = 90 * 24 * 60 * 60 * 1_000;
const SALT_LENGTH: usize = 16;
const VERIFIER_LENGTH: usize = 32;

/// Non-secret caller metadata returned by authorized identity management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCaller {
    caller: Caller,
    name: CallerName,
    credential_expires_unix_time_millis: Option<u64>,
}

impl RegisteredCaller {
    pub(crate) const fn new(caller: Caller, name: CallerName) -> Self {
        Self {
            caller,
            name,
            credential_expires_unix_time_millis: None,
        }
    }

    const fn with_credential_expiry(mut self, expires_unix_time_millis: u64) -> Self {
        self.credential_expires_unix_time_millis = if expires_unix_time_millis == u64::MAX {
            None
        } else {
            Some(expires_unix_time_millis)
        };
        self
    }

    /// Returns the exact registered policy subject.
    #[must_use]
    pub const fn caller(&self) -> Caller {
        self.caller
    }

    /// Returns the management-only caller label.
    #[must_use]
    pub const fn name(&self) -> &CallerName {
        &self.name
    }

    /// Returns the enforced credential expiry timestamp.
    ///
    /// `None` identifies a legacy V1/V2 credential that must be rotated to
    /// receive a bounded V3 lifetime.
    #[must_use]
    pub const fn credential_expires_unix_time_millis(&self) -> Option<u64> {
        self.credential_expires_unix_time_millis
    }
}

/// Argon2id credential verifier stored only inside the encrypted registry.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CredentialVerifier {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; SALT_LENGTH],
    verifier: [u8; VERIFIER_LENGTH],
}

impl CredentialVerifier {
    pub(crate) const fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        salt: [u8; SALT_LENGTH],
        verifier: [u8; VERIFIER_LENGTH],
    ) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
            salt,
            verifier,
        }
    }

    pub(crate) const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    pub(crate) const fn iterations(&self) -> u32 {
        self.iterations
    }

    pub(crate) const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    pub(crate) const fn salt(&self) -> [u8; SALT_LENGTH] {
        self.salt
    }

    pub(crate) const fn verifier(&self) -> &[u8; VERIFIER_LENGTH] {
        &self.verifier
    }
}

#[derive(Clone, PartialEq, Eq)]
struct RegistryEntry {
    metadata: RegisteredCaller,
    credential: CredentialVerifier,
    credential_issued_unix_time_millis: u64,
    credential_expires_unix_time_millis: u64,
}

/// Strict, generation-bound registry authenticated by the Vault envelope.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IdentityRegistryDocument {
    generation: u64,
    owner_id: CallerId,
    callers: BTreeMap<CallerId, RegistryEntry>,
    authentication_throttle: AuthenticationThrottleState,
}

impl IdentityRegistryDocument {
    pub(crate) fn new(generation: u64, owner_id: CallerId) -> Self {
        Self {
            generation,
            owner_id,
            callers: BTreeMap::new(),
            authentication_throttle: AuthenticationThrottleState::default(),
        }
    }

    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) const fn verified_owner(&self) -> VerifiedCaller {
        VerifiedCaller::new(
            Caller::new(self.owner_id, CallerKind::Human),
            AuthenticationMethod::MasterPassword,
        )
    }

    pub(crate) fn callers(&self) -> Vec<RegisteredCaller> {
        self.callers
            .values()
            .map(|entry| {
                entry
                    .metadata
                    .clone()
                    .with_credential_expiry(entry.credential_expires_unix_time_millis)
            })
            .collect()
    }

    pub(crate) fn contains_id(&self, id: CallerId) -> bool {
        self.owner_id == id || self.callers.contains_key(&id)
    }

    pub(crate) fn contains_name(&self, name: &CallerName) -> bool {
        self.callers
            .values()
            .any(|entry| entry.metadata.name() == name)
    }

    pub(crate) fn credential(&self, id: CallerId, kind: CallerKind) -> Option<&CredentialVerifier> {
        self.callers
            .get(&id)
            .filter(|entry| entry.metadata.caller().kind() == kind)
            .map(|entry| &entry.credential)
    }

    pub(crate) fn credential_is_active(
        &self,
        id: CallerId,
        kind: CallerKind,
        unix_time_millis: u64,
    ) -> bool {
        self.callers.get(&id).is_some_and(|entry| {
            entry.metadata.caller().kind() == kind
                && unix_time_millis >= entry.credential_issued_unix_time_millis
                && unix_time_millis < entry.credential_expires_unix_time_millis
        })
    }

    pub(crate) fn registered_caller(&self, id: CallerId) -> Option<&RegisteredCaller> {
        self.callers.get(&id).map(|entry| &entry.metadata)
    }

    pub(crate) fn credentials(&self) -> impl Iterator<Item = &CredentialVerifier> {
        self.callers.values().map(|entry| &entry.credential)
    }

    pub(crate) fn authentication_disposition(
        &mut self,
        caller_id: CallerId,
        unix_time_millis: u64,
    ) -> AuthenticationDisposition {
        self.authentication_throttle
            .disposition(caller_id, unix_time_millis)
    }

    pub(crate) const fn last_observed_authentication_time(&self) -> u64 {
        self.authentication_throttle
            .last_observed_unix_time_millis()
    }

    pub(crate) fn record_authentication_result(
        &mut self,
        caller_id: CallerId,
        unix_time_millis: u64,
        authenticated: bool,
        disposition: AuthenticationDisposition,
    ) {
        self.authentication_throttle.record_result(
            caller_id,
            unix_time_millis,
            authenticated,
            disposition,
        );
    }

    pub(crate) fn insert(
        &mut self,
        metadata: RegisteredCaller,
        credential: CredentialVerifier,
        credential_issued_unix_time_millis: u64,
        credential_expires_unix_time_millis: u64,
    ) -> Result<(), IdentityRegistryError> {
        if self.callers.len() >= MAX_REGISTERED_CALLERS
            || metadata.caller().kind() == CallerKind::Human
            || self.contains_id(metadata.caller().id())
            || self.contains_name(metadata.name())
            || !valid_credential_window(
                credential_issued_unix_time_millis,
                credential_expires_unix_time_millis,
            )
        {
            return Err(IdentityRegistryError);
        }
        let caller_id = metadata.caller().id();
        self.callers.insert(
            caller_id,
            RegistryEntry {
                metadata,
                credential,
                credential_issued_unix_time_millis,
                credential_expires_unix_time_millis,
            },
        );
        self.authentication_throttle.clear_bucket(caller_id);
        Ok(())
    }

    pub(crate) fn remove(&mut self, id: CallerId) -> Result<(), IdentityRegistryError> {
        self.callers
            .remove(&id)
            .map(|_| ())
            .ok_or(IdentityRegistryError)
    }

    pub(crate) fn replace_credential(
        &mut self,
        id: CallerId,
        credential: CredentialVerifier,
        credential_issued_unix_time_millis: u64,
        credential_expires_unix_time_millis: u64,
    ) -> Result<(), IdentityRegistryError> {
        if !valid_credential_window(
            credential_issued_unix_time_millis,
            credential_expires_unix_time_millis,
        ) {
            return Err(IdentityRegistryError);
        }
        let entry = self.callers.get_mut(&id).ok_or(IdentityRegistryError)?;
        entry.credential = credential;
        entry.credential_issued_unix_time_millis = credential_issued_unix_time_millis;
        entry.credential_expires_unix_time_millis = credential_expires_unix_time_millis;
        self.authentication_throttle.clear_bucket(id);
        Ok(())
    }

    pub(crate) fn advance_generation(&mut self) -> Result<u64, IdentityRegistryError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(IdentityRegistryError)?;
        Ok(self.generation)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, IdentityRegistryError> {
        if self.generation == 0 || self.callers.len() > MAX_REGISTERED_CALLERS {
            return Err(IdentityRegistryError);
        }
        let callers = self
            .callers
            .values()
            .map(|entry| RegistryEntryFileV3 {
                caller_id: entry.metadata.caller().id().to_string(),
                caller_kind: entry.metadata.caller().kind().as_str().to_owned(),
                name: entry.metadata.name().as_str().to_owned(),
                credential_issued_unix_time_millis: entry.credential_issued_unix_time_millis,
                credential_expires_unix_time_millis: entry.credential_expires_unix_time_millis,
                kdf: CredentialKdfFile {
                    algorithm: "argon2id".to_owned(),
                    version: 19,
                    memory_kib: entry.credential.memory_kib,
                    iterations: entry.credential.iterations,
                    parallelism: entry.credential.parallelism,
                    salt: STANDARD.encode(entry.credential.salt),
                },
                verifier: STANDARD.encode(entry.credential.verifier),
            })
            .collect();
        let file = IdentityRegistryFileV3 {
            format: FORMAT_NAME.to_owned(),
            version: FORMAT_VERSION,
            generation: self.generation,
            owner_id: self.owner_id.to_string(),
            owner_kind: CallerKind::Human.as_str().to_owned(),
            callers,
            authentication_throttle: self.authentication_throttle.to_file(),
        };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|_| IdentityRegistryError)?;
        if bytes.len() > MAX_IDENTITY_DOCUMENT_BYTES {
            return Err(IdentityRegistryError);
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, IdentityRegistryError> {
        if bytes.len() > MAX_IDENTITY_DOCUMENT_BYTES {
            return Err(IdentityRegistryError);
        }
        let header: IdentityRegistryHeader =
            serde_json::from_slice(bytes).map_err(|_| IdentityRegistryError)?;
        if header.format != FORMAT_NAME {
            return Err(IdentityRegistryError);
        }
        match header.version {
            LEGACY_FORMAT_VERSION => {
                let file: IdentityRegistryFileV1 =
                    serde_json::from_slice(bytes).map_err(|_| IdentityRegistryError)?;
                if file.format != FORMAT_NAME || file.version != LEGACY_FORMAT_VERSION {
                    return Err(IdentityRegistryError);
                }
                Self::decode_fields(
                    file.generation,
                    &file.owner_id,
                    &file.owner_kind,
                    file.callers
                        .into_iter()
                        .map(DecodedRegistryEntry::from_legacy)
                        .collect(),
                    AuthenticationThrottleState::default(),
                )
            }
            THROTTLE_FORMAT_VERSION => {
                let file: IdentityRegistryFileV2 =
                    serde_json::from_slice(bytes).map_err(|_| IdentityRegistryError)?;
                if file.format != FORMAT_NAME || file.version != THROTTLE_FORMAT_VERSION {
                    return Err(IdentityRegistryError);
                }
                let throttle = AuthenticationThrottleState::from_file(file.authentication_throttle)
                    .map_err(|_| IdentityRegistryError)?;
                Self::decode_fields(
                    file.generation,
                    &file.owner_id,
                    &file.owner_kind,
                    file.callers
                        .into_iter()
                        .map(DecodedRegistryEntry::from_legacy)
                        .collect(),
                    throttle,
                )
            }
            FORMAT_VERSION => {
                let file: IdentityRegistryFileV3 =
                    serde_json::from_slice(bytes).map_err(|_| IdentityRegistryError)?;
                if file.format != FORMAT_NAME || file.version != FORMAT_VERSION {
                    return Err(IdentityRegistryError);
                }
                let throttle = AuthenticationThrottleState::from_file(file.authentication_throttle)
                    .map_err(|_| IdentityRegistryError)?;
                Self::decode_fields(
                    file.generation,
                    &file.owner_id,
                    &file.owner_kind,
                    file.callers
                        .into_iter()
                        .map(DecodedRegistryEntry::from_v3)
                        .collect(),
                    throttle,
                )
            }
            _ => Err(IdentityRegistryError),
        }
    }

    fn decode_fields(
        generation: u64,
        owner_id: &str,
        owner_kind: &str,
        callers: Vec<DecodedRegistryEntry>,
        authentication_throttle: AuthenticationThrottleState,
    ) -> Result<Self, IdentityRegistryError> {
        if generation == 0
            || owner_kind != CallerKind::Human.as_str()
            || callers.len() > MAX_REGISTERED_CALLERS
        {
            return Err(IdentityRegistryError);
        }
        let owner_id = owner_id.parse().map_err(|_| IdentityRegistryError)?;
        let mut document = Self::new(generation, owner_id);
        for entry in callers {
            if entry.kdf.algorithm != "argon2id" || entry.kdf.version != 19 {
                return Err(IdentityRegistryError);
            }
            let caller_id = entry.caller_id.parse().map_err(|_| IdentityRegistryError)?;
            let caller_kind = entry
                .caller_kind
                .parse()
                .map_err(|_| IdentityRegistryError)?;
            let name = CallerName::new(entry.name).map_err(|_| IdentityRegistryError)?;
            let credential = CredentialVerifier::new(
                entry.kdf.memory_kib,
                entry.kdf.iterations,
                entry.kdf.parallelism,
                decode_array(&entry.kdf.salt)?,
                decode_array(&entry.verifier)?,
            );
            document.insert(
                RegisteredCaller::new(Caller::new(caller_id, caller_kind), name),
                credential,
                entry.credential_issued_unix_time_millis,
                entry.credential_expires_unix_time_millis,
            )?;
        }
        document.authentication_throttle = authentication_throttle;
        Ok(document)
    }
}

fn valid_credential_window(issued_unix_time_millis: u64, expires_unix_time_millis: u64) -> bool {
    (issued_unix_time_millis == 0 && expires_unix_time_millis == u64::MAX)
        || (issued_unix_time_millis > 0
            && expires_unix_time_millis.checked_sub(issued_unix_time_millis)
                == Some(DEFAULT_CREDENTIAL_LIFETIME_MILLIS))
}

fn decode_array<const LENGTH: usize>(encoded: &str) -> Result<[u8; LENGTH], IdentityRegistryError> {
    STANDARD
        .decode(encoded)
        .map_err(|_| IdentityRegistryError)?
        .try_into()
        .map_err(|_| IdentityRegistryError)
}

#[derive(Deserialize)]
struct IdentityRegistryHeader {
    format: String,
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRegistryFileV1 {
    format: String,
    version: u32,
    generation: u64,
    owner_id: String,
    owner_kind: String,
    callers: Vec<LegacyRegistryEntryFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRegistryFileV2 {
    format: String,
    version: u32,
    generation: u64,
    owner_id: String,
    owner_kind: String,
    callers: Vec<LegacyRegistryEntryFile>,
    authentication_throttle: AuthenticationThrottleFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRegistryFileV3 {
    format: String,
    version: u32,
    generation: u64,
    owner_id: String,
    owner_kind: String,
    callers: Vec<RegistryEntryFileV3>,
    authentication_throttle: AuthenticationThrottleFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRegistryEntryFile {
    caller_id: String,
    caller_kind: String,
    name: String,
    kdf: CredentialKdfFile,
    verifier: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryEntryFileV3 {
    caller_id: String,
    caller_kind: String,
    name: String,
    credential_issued_unix_time_millis: u64,
    credential_expires_unix_time_millis: u64,
    kdf: CredentialKdfFile,
    verifier: String,
}

struct DecodedRegistryEntry {
    caller_id: String,
    caller_kind: String,
    name: String,
    credential_issued_unix_time_millis: u64,
    credential_expires_unix_time_millis: u64,
    kdf: CredentialKdfFile,
    verifier: String,
}

impl DecodedRegistryEntry {
    fn from_legacy(entry: LegacyRegistryEntryFile) -> Self {
        Self {
            caller_id: entry.caller_id,
            caller_kind: entry.caller_kind,
            name: entry.name,
            credential_issued_unix_time_millis: 0,
            credential_expires_unix_time_millis: u64::MAX,
            kdf: entry.kdf,
            verifier: entry.verifier,
        }
    }

    fn from_v3(entry: RegistryEntryFileV3) -> Self {
        Self {
            caller_id: entry.caller_id,
            caller_kind: entry.caller_kind,
            name: entry.name,
            credential_issued_unix_time_millis: entry.credential_issued_unix_time_millis,
            credential_expires_unix_time_millis: entry.credential_expires_unix_time_millis,
            kdf: entry.kdf,
            verifier: entry.verifier,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialKdfFile {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

/// Safe failure for a malformed or invalid Identity Registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdentityRegistryError;

impl core::fmt::Display for IdentityRegistryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Identity Registry is invalid")
    }
}

impl std::error::Error for IdentityRegistryError {}

#[cfg(test)]
mod tests {
    use super::{
        CredentialVerifier, DEFAULT_CREDENTIAL_LIFETIME_MILLIS, IdentityRegistryDocument,
        RegisteredCaller,
    };
    use crate::identity::{
        AuthenticationDisposition, Caller, CallerId, CallerKind, CallerName,
        throttle::AUTHENTICATION_BUCKET_FAILURE_LIMIT,
    };

    #[test]
    fn registry_round_trips_in_canonical_caller_id_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut registry = IdentityRegistryDocument::new(4, CallerId::from_bytes([0x31; 16]));
        for (id, kind, name) in [
            (0x52, CallerKind::AiAgent, "agent"),
            (0x41, CallerKind::Application, "backend"),
        ] {
            registry.insert(
                RegisteredCaller::new(
                    Caller::new(CallerId::from_bytes([id; 16]), kind),
                    CallerName::new(name)?,
                ),
                CredentialVerifier::new(8192, 1, 1, [id; 16], [id; 32]),
                100,
                100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
            )?;
        }
        let encoded = registry.encode()?;
        let decoded = IdentityRegistryDocument::decode(&encoded)?;

        assert!(decoded == registry);
        assert_eq!(decoded.callers()[0].name().as_str(), "backend");
        assert_eq!(decoded.callers()[1].name().as_str(), "agent");
        Ok(())
    }

    #[test]
    fn rejects_human_credentials_and_duplicate_names() -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = IdentityRegistryDocument::new(1, CallerId::from_bytes([0x31; 16]));
        let verifier = CredentialVerifier::new(8192, 1, 1, [1; 16], [2; 32]);
        assert!(
            registry
                .insert(
                    RegisteredCaller::new(
                        Caller::new(CallerId::from_bytes([0x42; 16]), CallerKind::Human),
                        CallerName::new("human")?,
                    ),
                    verifier.clone(),
                    100,
                    100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
                )
                .is_err()
        );
        registry.insert(
            RegisteredCaller::new(
                Caller::new(CallerId::from_bytes([0x43; 16]), CallerKind::Application),
                CallerName::new("duplicate")?,
            ),
            verifier.clone(),
            100,
            100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
        )?;
        assert!(
            registry
                .insert(
                    RegisteredCaller::new(
                        Caller::new(CallerId::from_bytes([0x44; 16]), CallerKind::AiAgent,),
                        CallerName::new("duplicate")?,
                    ),
                    verifier,
                    100,
                    100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_v1_decodes_and_next_encoding_is_strict_v3() -> Result<(), Box<dyn std::error::Error>>
    {
        let legacy = br#"{
          "format":"envvault-identity-registry",
          "version":1,
          "generation":1,
          "owner_id":"31313131-3131-3131-3131-313131313131",
          "owner_kind":"human",
          "callers":[]
        }"#;
        let document = IdentityRegistryDocument::decode(legacy)?;
        let encoded_bytes = document.encode()?;
        assert!(encoded_bytes.len() < 4 * 1024);
        let encoded: serde_json::Value = serde_json::from_slice(&encoded_bytes)?;
        assert_eq!(encoded["version"], 3);
        assert_eq!(
            encoded["authentication_throttle"]["buckets"]
                .as_array()
                .ok_or("missing throttle buckets")?
                .len(),
            0
        );
        Ok(())
    }

    #[test]
    fn v2_credentials_are_grandfathered_until_rotation_and_v3_windows_are_strict()
    -> Result<(), Box<dyn std::error::Error>> {
        let v2 = br#"{
          "format":"envvault-identity-registry",
          "version":2,
          "generation":2,
          "owner_id":"31313131-3131-3131-3131-313131313131",
          "owner_kind":"human",
          "callers":[{
            "caller_id":"41414141-4141-4141-4141-414141414141",
            "caller_kind":"application",
            "name":"legacy-backend",
            "kdf":{"algorithm":"argon2id","version":19,"memory_kib":8192,"iterations":1,"parallelism":1,"salt":"AQEBAQEBAQEBAQEBAQEBAQ=="},
            "verifier":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
          }],
          "authentication_throttle":{
            "last_observed_unix_time_millis":0,
            "global":{"window_started_unix_time_millis":0,"failures":0,"blocked_until_unix_time_millis":0},
            "buckets":[]
          }
        }"#;
        let caller_id = CallerId::from_bytes([0x41; 16]);
        let document = IdentityRegistryDocument::decode(v2)?;
        assert!(document.credential_is_active(caller_id, CallerKind::Application, u64::MAX - 1));
        assert_eq!(
            document.callers()[0].credential_expires_unix_time_millis(),
            None
        );

        let encoded = document.encode()?;
        let mut v3: serde_json::Value = serde_json::from_slice(&encoded)?;
        assert_eq!(v3["version"], 3);
        assert_eq!(
            v3["callers"][0]["credential_expires_unix_time_millis"],
            u64::MAX
        );
        v3["callers"][0]["credential_issued_unix_time_millis"] = 100.into();
        v3["callers"][0]["credential_expires_unix_time_millis"] = 100.into();
        assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&v3)?).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_throttle_round_trips_and_rejects_duplicate_bucket_index()
    -> Result<(), Box<dyn std::error::Error>> {
        let caller = CallerId::from_bytes([0x22; 16]);
        let mut registry = IdentityRegistryDocument::new(1, CallerId::from_bytes([0x31; 16]));
        for attempt in 0..AUTHENTICATION_BUCKET_FAILURE_LIMIT {
            let now = 100 + u64::from(attempt);
            let disposition = registry.authentication_disposition(caller, now);
            registry.record_authentication_result(caller, now, false, disposition);
        }
        let encoded = registry.encode()?;
        let mut decoded = IdentityRegistryDocument::decode(&encoded)?;
        assert_eq!(
            decoded.authentication_disposition(caller, 50),
            AuthenticationDisposition::Blocked
        );

        let mut malformed: serde_json::Value = serde_json::from_slice(&encoded)?;
        let buckets = malformed["authentication_throttle"]["buckets"]
            .as_array_mut()
            .ok_or("missing throttle buckets")?;
        buckets.push(buckets.first().ok_or("missing used bucket")?.clone());
        assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&malformed)?).is_err());
        Ok(())
    }

    /// Adversarial tests for authentication throttling and the strict 90-day
    /// credential expiry window: clock rollback/forward attacks, shared-fate
    /// global availability attacks, persisted-state survival, tampered-file
    /// rejection, concurrency stress and simulated multi-process interleaving.
    /// All of them are value-free and filesystem-free.
    mod adversarial {
        use std::sync::{Arc, Mutex};

        use super::{
            CredentialVerifier, DEFAULT_CREDENTIAL_LIFETIME_MILLIS, IdentityRegistryDocument,
            RegisteredCaller,
        };
        use crate::identity::{
            AuthenticationDisposition, Caller, CallerId, CallerKind, CallerName,
            throttle::{
                AUTHENTICATION_BLOCK_MILLIS, AUTHENTICATION_BUCKET_FAILURE_LIMIT,
                AUTHENTICATION_GLOBAL_FAILURE_LIMIT,
            },
        };

        const OWNER: [u8; 16] = [0x31; 16];

        fn registry() -> IdentityRegistryDocument {
            IdentityRegistryDocument::new(1, CallerId::from_bytes(OWNER))
        }

        fn caller(byte: u8) -> CallerId {
            CallerId::from_bytes([byte; 16])
        }

        fn verifier(byte: u8) -> CredentialVerifier {
            CredentialVerifier::new(8192, 1, 1, [byte; 16], [byte; 32])
        }

        fn insert_caller(
            registry: &mut IdentityRegistryDocument,
            byte: u8,
            issued: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            registry.insert(
                RegisteredCaller::new(
                    Caller::new(caller(byte), CallerKind::Application),
                    CallerName::new(&format!("caller-{byte}"))?,
                ),
                verifier(byte),
                issued,
                issued + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
            )?;
            Ok(())
        }

        #[test]
        fn expiry_boundary_is_strict_and_clock_rollback_cannot_revive_it()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            let issued = 1_000;
            insert_caller(&mut registry, 0x41, issued)?;
            let id = caller(0x41);
            assert!(!registry.credential_is_active(id, CallerKind::Application, issued - 1));
            assert!(registry.credential_is_active(id, CallerKind::Application, issued));
            assert!(registry.credential_is_active(
                id,
                CallerKind::Application,
                issued + DEFAULT_CREDENTIAL_LIFETIME_MILLIS - 1,
            ));
            assert!(!registry.credential_is_active(
                id,
                CallerKind::Application,
                issued + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
            ));
            assert!(!registry.credential_is_active(id, CallerKind::Application, issued - 1));
            Ok(())
        }

        #[test]
        fn clock_forward_expires_the_credential_and_rotation_restores_access()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            insert_caller(&mut registry, 0x42, 1_000)?;
            let id = caller(0x42);
            assert!(!registry.credential_is_active(
                id,
                CallerKind::Application,
                1_000 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
            ));
            let rotated_issued = 2_000;
            registry.replace_credential(
                id,
                verifier(0x43),
                rotated_issued,
                rotated_issued + DEFAULT_CREDENTIAL_LIFETIME_MILLIS,
            )?;
            assert!(!registry
                .credential_is_active(id, CallerKind::Application, rotated_issued - 1));
            assert!(registry.credential_is_active(id, CallerKind::Application, rotated_issued));
            Ok(())
        }

        #[test]
        fn credential_windows_must_be_exactly_ninety_days()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            let name = CallerName::new("strict")?;
            let metadata = RegisteredCaller::new(
                Caller::new(caller(0x45), CallerKind::AiAgent),
                name,
            );
            assert!(registry
                .insert(
                    metadata.clone(),
                    verifier(0x45),
                    100,
                    100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS - 1,
                )
                .is_err());
            assert!(registry
                .insert(
                    metadata.clone(),
                    verifier(0x45),
                    100,
                    100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS + 1,
                )
                .is_err());
            assert!(registry.insert(metadata, verifier(0x45), 0, u64::MAX).is_ok());
            let id = caller(0x45);
            assert!(registry.credential_is_active(id, CallerKind::AiAgent, u64::MAX - 1));
            Ok(())
        }

        #[test]
        fn clock_rollback_cannot_clear_the_bucket_block_window()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            let id = caller(0x22);
            for attempt in 0..AUTHENTICATION_BUCKET_FAILURE_LIMIT {
                let now = 1_000 + u64::from(attempt);
                let disposition = registry.authentication_disposition(id, now);
                registry.record_authentication_result(id, now, false, disposition);
            }
            assert_eq!(
                registry.authentication_disposition(id, 999),
                AuthenticationDisposition::Blocked
            );
            assert_eq!(
                registry.authentication_disposition(id, 500),
                AuthenticationDisposition::Blocked
            );
            let encoded = registry.encode()?;
            let mut decoded = IdentityRegistryDocument::decode(&encoded)?;
            assert_eq!(
                decoded.authentication_disposition(id, 500),
                AuthenticationDisposition::Blocked
            );
            assert_eq!(
                decoded.authentication_disposition(
                    id,
                    1_004 + AUTHENTICATION_BLOCK_MILLIS + 1,
                ),
                AuthenticationDisposition::Proceed
            );
            Ok(())
        }

        #[test]
        fn global_failure_limit_is_a_bounded_shared_fate_denial_of_service()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            for attempt in 0..AUTHENTICATION_GLOBAL_FAILURE_LIMIT {
                let id = caller(u8::try_from(attempt).unwrap_or(u8::MAX));
                let disposition = registry.authentication_disposition(id, 200);
                assert_eq!(disposition, AuthenticationDisposition::Proceed);
                registry.record_authentication_result(id, 200, false, disposition);
            }
            let victim = caller(0xEE);
            assert_eq!(
                registry.authentication_disposition(victim, 201),
                AuthenticationDisposition::Blocked
            );
            assert_eq!(
                registry.authentication_disposition(caller(0x00), 201),
                AuthenticationDisposition::Blocked
            );
            assert_eq!(
                registry.authentication_disposition(
                    victim,
                    200 + AUTHENTICATION_BLOCK_MILLIS + 1,
                ),
                AuthenticationDisposition::Proceed
            );
            Ok(())
        }

        #[test]
        fn global_block_survives_restart_without_resetting_the_window()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            for attempt in 0..AUTHENTICATION_GLOBAL_FAILURE_LIMIT {
                let id = caller(u8::try_from(attempt).unwrap_or(u8::MAX));
                let disposition = registry.authentication_disposition(id, 200);
                registry.record_authentication_result(id, 200, false, disposition);
            }
            let encoded = registry.encode()?;
            let mut decoded = IdentityRegistryDocument::decode(&encoded)?;
            assert_eq!(
                decoded.authentication_disposition(caller(0xEE), 201),
                AuthenticationDisposition::Blocked
            );
            Ok(())
        }

        #[test]
        fn tampered_throttle_state_is_rejected_on_decode()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            for attempt in 0..AUTHENTICATION_GLOBAL_FAILURE_LIMIT {
                let id = caller(u8::try_from(attempt).unwrap_or(u8::MAX));
                let disposition = registry.authentication_disposition(id, 200);
                registry.record_authentication_result(id, 200, false, disposition);
            }
            let encoded = registry.encode()?;

            let mut unknown: serde_json::Value = serde_json::from_slice(&encoded)?;
            unknown["authentication_throttle"]["surprise"] = 1.into();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&unknown)?).is_err());

            let mut over_limit: serde_json::Value = serde_json::from_slice(&encoded)?;
            over_limit["authentication_throttle"]["global"]["failures"] =
                (AUTHENTICATION_GLOBAL_FAILURE_LIMIT + 1).into();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&over_limit)?).is_err());

            let mut over_bound: serde_json::Value = serde_json::from_slice(&encoded)?;
            over_bound["authentication_throttle"]["global"]["blocked_until_unix_time_millis"] =
                (200 + AUTHENTICATION_BLOCK_MILLIS + 1).into();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&over_bound)?).is_err());
            Ok(())
        }

        #[test]
        fn tampered_bucket_order_and_expiry_window_are_rejected()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            insert_caller(&mut registry, 0x01, 100)?;
            insert_caller(&mut registry, 0x02, 100)?;
            let first = caller(0x01);
            let disposition = registry.authentication_disposition(first, 105);
            registry.record_authentication_result(first, 105, false, disposition);
            let second = caller(0x02);
            let disposition = registry.authentication_disposition(second, 106);
            registry.record_authentication_result(second, 106, false, disposition);
            let encoded = registry.encode()?;

            let mut reordered: serde_json::Value = serde_json::from_slice(&encoded)?;
            let buckets = reordered["authentication_throttle"]["buckets"]
                .as_array_mut()
                .ok_or("missing throttle buckets")?;
            buckets.reverse();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&reordered)?).is_err());

            let mut short_window: serde_json::Value = serde_json::from_slice(&encoded)?;
            short_window["callers"][0]["credential_expires_unix_time_millis"] =
                (100 + DEFAULT_CREDENTIAL_LIFETIME_MILLIS - 1).into();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&short_window)?).is_err());

            let mut bad_kdf: serde_json::Value = serde_json::from_slice(&encoded)?;
            bad_kdf["callers"][0]["kdf"]["version"] = 18.into();
            assert!(IdentityRegistryDocument::decode(&serde_json::to_vec(&bad_kdf)?).is_err());
            Ok(())
        }

        #[test]
        #[ignore = "finding (defense-in-depth): V3 documents accept the legacy (0, u64::MAX) credential window, so a tampered caller entry would hold an immortal credential; exploiting it still requires breaking the Vault AEAD envelope first"]
        fn v3_documents_still_accept_the_legacy_immortal_credential_window()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut registry = registry();
            insert_caller(&mut registry, 0x41, 100)?;
            let encoded = registry.encode()?;
            let mut immortal: serde_json::Value = serde_json::from_slice(&encoded)?;
            immortal["callers"][0]["credential_issued_unix_time_millis"] = 0.into();
            immortal["callers"][0]["credential_expires_unix_time_millis"] = u64::MAX.into();
            let decoded = IdentityRegistryDocument::decode(&serde_json::to_vec(&immortal)?)?;
            assert!(decoded.credential_is_active(
                caller(0x41),
                CallerKind::Application,
                u64::MAX - 1,
            ));
            Ok(())
        }

        #[test]
        fn concurrent_authentication_stress_preserves_state_invariants()
        -> Result<(), Box<dyn std::error::Error>> {
            let shared = Arc::new(Mutex::new(registry()));
            let mut handles = Vec::new();
            for thread in 0..8_u8 {
                let shared = Arc::clone(&shared);
                handles.push(std::thread::spawn(move || {
                    let id = caller(0x10 + thread);
                    for iteration in 0..500_u64 {
                        let now = 10_000 + u64::from(thread) * 1_000 + iteration;
                        let mut guard = match shared.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        let disposition = guard.authentication_disposition(id, now);
                        let authenticated = iteration % 97 == 0;
                        guard.record_authentication_result(id, now, authenticated, disposition);
                    }
                }));
            }
            for handle in handles {
                let _ = handle.join();
            }
            let guard = match shared.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let encoded = guard.encode()?;
            let decoded = IdentityRegistryDocument::decode(&encoded)?;
            assert!(decoded == *guard);
            assert_eq!(decoded.last_observed_authentication_time(), 17_499);
            Ok(())
        }

        #[test]
        fn state_carries_across_simulated_process_boundaries_without_loss()
        -> Result<(), Box<dyn std::error::Error>> {
            let mut process_a = registry();
            let x = caller(0x11);
            for attempt in 0..AUTHENTICATION_BUCKET_FAILURE_LIMIT {
                let now = 1_000 + u64::from(attempt);
                let disposition = process_a.authentication_disposition(x, now);
                process_a.record_authentication_result(x, now, false, disposition);
            }
            let committed = process_a.encode()?;

            let mut process_b = IdentityRegistryDocument::decode(&committed)?;
            let y = caller(0x77);
            let disposition = process_b.authentication_disposition(y, 1_005);
            process_b.record_authentication_result(y, 1_005, false, disposition);
            let committed_b = process_b.encode()?;

            let mut process_c = IdentityRegistryDocument::decode(&committed_b)?;
            assert_eq!(
                process_c.authentication_disposition(x, 999),
                AuthenticationDisposition::Blocked
            );
            assert_eq!(
                process_c.authentication_disposition(y, 1_006),
                AuthenticationDisposition::Proceed
            );
            assert_eq!(
                process_c.authentication_disposition(
                    x,
                    1_004 + AUTHENTICATION_BLOCK_MILLIS + 1,
                ),
                AuthenticationDisposition::Proceed
            );
            Ok(())
        }
    }
}
