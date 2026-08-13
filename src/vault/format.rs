use std::{collections::BTreeMap, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{EncryptedEnvelope, KdfConfig, KdfLimits, KdfParams},
    secret::SecretId,
};

use super::{VaultError, payload::MAX_SECRET_VALUE_BYTES};

pub(super) const FORMAT_NAME: &str = "envvault";
pub(super) const FORMAT_VERSION: u32 = 1;
pub(super) const VAULT_ID_LENGTH: usize = 16;
pub(super) const MAX_VAULT_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_RECORDS: usize = 10_000;

const AEAD_ALGORITHM: &str = "xchacha20poly1305";
const MAX_METADATA_CIPHERTEXT_BYTES: usize = 512;
const MAX_VALUE_CIPHERTEXT_BYTES: usize = MAX_SECRET_VALUE_BYTES + 64;
const MAX_KEY_CHECK_CIPHERTEXT_BYTES: usize = 128;
const MAX_POLICY_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024 + 64;
const MAX_IDENTITY_CIPHERTEXT_BYTES: usize = 1024 * 1024 + 64;
const MAX_AUDIT_KEY_CIPHERTEXT_BYTES: usize = 128;
const MAX_AUDIT_EVENT_CIPHERTEXT_BYTES: usize = 4 * 1024 + 64;
pub(super) const MAX_AUDIT_EVENTS: usize = 100_000;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct VaultState {
    pub(super) generation: u64,
    pub(super) vault_id: [u8; VAULT_ID_LENGTH],
    pub(super) kdf: KdfConfig,
    pub(super) key_check: EncryptedEnvelope,
    pub(super) identity: StoredIdentity,
    pub(super) policy: StoredPolicy,
    pub(super) audit: StoredAudit,
    pub(super) records: BTreeMap<SecretId, StoredRecord>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredIdentity {
    pub(super) generation: u64,
    pub(super) envelope: EncryptedEnvelope,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredPolicy {
    pub(super) generation: u64,
    pub(super) envelope: EncryptedEnvelope,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredAudit {
    pub(super) key_envelope: EncryptedEnvelope,
    pub(super) head_authenticator: [u8; EncryptedEnvelope::TAG_LENGTH],
    pub(super) events: Vec<EncryptedEnvelope>,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StoredRecord {
    pub(super) revision: u64,
    pub(super) metadata_envelope: EncryptedEnvelope,
    pub(super) value_envelope: EncryptedEnvelope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultFile {
    format: String,
    version: u32,
    generation: u64,
    vault_id: String,
    kdf: KdfFile,
    aead: AeadFile,
    key_check: EnvelopeFile,
    identity: IdentityFile,
    policy: PolicyFile,
    audit: AuditFile,
    records: Vec<RecordFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFile {
    generation: u64,
    envelope: EnvelopeFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    generation: u64,
    envelope: EnvelopeFile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    key_envelope: EnvelopeFile,
    head_authenticator: String,
    events: Vec<EnvelopeFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfFile {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AeadFile {
    algorithm: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFile {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    secret_id: String,
    revision: u64,
    metadata_envelope: EnvelopeFile,
    value_envelope: EnvelopeFile,
}

pub(super) fn parse(bytes: &[u8]) -> Result<VaultState, VaultError> {
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_VAULT_FILE_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    let file: VaultFile = serde_json::from_slice(bytes).map_err(|_| VaultError::InvalidFormat)?;
    if file.format != FORMAT_NAME {
        return Err(VaultError::InvalidFormat);
    }
    if file.version != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion);
    }
    if file.generation == 0 || file.records.len() > MAX_RECORDS {
        return Err(VaultError::ResourceLimitExceeded);
    }
    if file.kdf.algorithm != KdfParams::ALGORITHM
        || file.kdf.version != KdfParams::VERSION
        || file.aead.algorithm != AEAD_ALGORITHM
    {
        return Err(VaultError::InvalidFormat);
    }
    if file.identity.generation == 0
        || file.policy.generation == 0
        || file.audit.events.len() > MAX_AUDIT_EVENTS
    {
        return Err(VaultError::InvalidFormat);
    }

    let kdf = KdfConfig::new(
        KdfParams {
            memory_kib: file.kdf.memory_kib,
            iterations: file.kdf.iterations,
            parallelism: file.kdf.parallelism,
        },
        decode_array(&file.kdf.salt)?,
    );
    kdf.params
        .validate(KdfLimits::default())
        .map_err(|_| VaultError::ResourceLimitExceeded)?;

    let mut records = BTreeMap::new();
    for record in file.records {
        if record.revision == 0 {
            return Err(VaultError::InvalidFormat);
        }
        let secret_id =
            SecretId::from_str(&record.secret_id).map_err(|_| VaultError::InvalidFormat)?;
        let stored = StoredRecord {
            revision: record.revision,
            metadata_envelope: decode_envelope(
                record.metadata_envelope,
                MAX_METADATA_CIPHERTEXT_BYTES,
            )?,
            value_envelope: decode_envelope(record.value_envelope, MAX_VALUE_CIPHERTEXT_BYTES)?,
        };
        if records.insert(secret_id, stored).is_some() {
            return Err(VaultError::InvalidFormat);
        }
    }

    Ok(VaultState {
        generation: file.generation,
        vault_id: decode_array(&file.vault_id)?,
        kdf,
        key_check: decode_envelope(file.key_check, MAX_KEY_CHECK_CIPHERTEXT_BYTES)?,
        identity: StoredIdentity {
            generation: file.identity.generation,
            envelope: decode_envelope(file.identity.envelope, MAX_IDENTITY_CIPHERTEXT_BYTES)?,
        },
        policy: StoredPolicy {
            generation: file.policy.generation,
            envelope: decode_envelope(file.policy.envelope, MAX_POLICY_CIPHERTEXT_BYTES)?,
        },
        audit: StoredAudit {
            key_envelope: decode_envelope(file.audit.key_envelope, MAX_AUDIT_KEY_CIPHERTEXT_BYTES)?,
            head_authenticator: decode_array(&file.audit.head_authenticator)?,
            events: file
                .audit
                .events
                .into_iter()
                .map(|event| decode_envelope(event, MAX_AUDIT_EVENT_CIPHERTEXT_BYTES))
                .collect::<Result<Vec<_>, _>>()?,
        },
        records,
    })
}

pub(super) fn serialize(state: &VaultState) -> Result<Vec<u8>, VaultError> {
    let records = state
        .records
        .iter()
        .map(|(secret_id, record)| RecordFile {
            secret_id: secret_id.to_string(),
            revision: record.revision,
            metadata_envelope: encode_envelope(&record.metadata_envelope),
            value_envelope: encode_envelope(&record.value_envelope),
        })
        .collect();
    let file = VaultFile {
        format: FORMAT_NAME.to_owned(),
        version: FORMAT_VERSION,
        generation: state.generation,
        vault_id: STANDARD.encode(state.vault_id),
        kdf: KdfFile {
            algorithm: KdfParams::ALGORITHM.to_owned(),
            version: KdfParams::VERSION,
            memory_kib: state.kdf.params.memory_kib,
            iterations: state.kdf.params.iterations,
            parallelism: state.kdf.params.parallelism,
            salt: STANDARD.encode(state.kdf.salt),
        },
        aead: AeadFile {
            algorithm: AEAD_ALGORITHM.to_owned(),
        },
        key_check: encode_envelope(&state.key_check),
        identity: IdentityFile {
            generation: state.identity.generation,
            envelope: encode_envelope(&state.identity.envelope),
        },
        policy: PolicyFile {
            generation: state.policy.generation,
            envelope: encode_envelope(&state.policy.envelope),
        },
        audit: AuditFile {
            key_envelope: encode_envelope(&state.audit.key_envelope),
            head_authenticator: STANDARD.encode(state.audit.head_authenticator),
            events: state.audit.events.iter().map(encode_envelope).collect(),
        },
        records,
    };
    let bytes = serde_json::to_vec_pretty(&file).map_err(|_| VaultError::InvalidFormat)?;
    if u64::try_from(bytes.len()).map_err(|_| VaultError::ResourceLimitExceeded)?
        > MAX_VAULT_FILE_BYTES
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(bytes)
}

fn encode_envelope(envelope: &EncryptedEnvelope) -> EnvelopeFile {
    EnvelopeFile {
        nonce: STANDARD.encode(envelope.nonce),
        ciphertext: STANDARD.encode(&envelope.ciphertext),
    }
}

fn decode_envelope(
    envelope: EnvelopeFile,
    maximum_ciphertext_bytes: usize,
) -> Result<EncryptedEnvelope, VaultError> {
    let ciphertext = STANDARD
        .decode(envelope.ciphertext)
        .map_err(|_| VaultError::InvalidFormat)?;
    if ciphertext.len() < EncryptedEnvelope::TAG_LENGTH
        || ciphertext.len() > maximum_ciphertext_bytes
    {
        return Err(VaultError::ResourceLimitExceeded);
    }
    Ok(EncryptedEnvelope {
        nonce: decode_array(&envelope.nonce)?,
        ciphertext,
    })
}

fn decode_array<const LENGTH: usize>(encoded: &str) -> Result<[u8; LENGTH], VaultError> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| VaultError::InvalidFormat)?;
    bytes.try_into().map_err(|_| VaultError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{StoredAudit, StoredIdentity, StoredPolicy, VaultState, parse, serialize};
    use crate::crypto::{EncryptedEnvelope, KdfConfig, KdfParams};

    #[test]
    fn empty_state_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let state = VaultState {
            generation: 1,
            vault_id: [0x11; 16],
            kdf: KdfConfig::new(KdfParams::recommended(), [0x22; 16]),
            key_check: EncryptedEnvelope {
                nonce: [0x33; 24],
                ciphertext: vec![0x44; 32],
            },
            identity: StoredIdentity {
                generation: 1,
                envelope: EncryptedEnvelope {
                    nonce: [0x45; 24],
                    ciphertext: vec![0x46; 32],
                },
            },
            policy: StoredPolicy {
                generation: 1,
                envelope: EncryptedEnvelope {
                    nonce: [0x55; 24],
                    ciphertext: vec![0x66; 32],
                },
            },
            audit: StoredAudit {
                key_envelope: EncryptedEnvelope {
                    nonce: [0x67; 24],
                    ciphertext: vec![0x68; 48],
                },
                head_authenticator: [0_u8; EncryptedEnvelope::TAG_LENGTH],
                events: Vec::new(),
            },
            records: BTreeMap::new(),
        };
        let encoded = serialize(&state)?;
        let decoded = parse(&encoded)?;

        assert!(decoded == state);
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields() {
        let bytes = br#"{
          "format":"envvault","version":1,"generation":1,
          "vault_id":"EREREREREREREREREREREQ==",
          "kdf":{"algorithm":"argon2id","version":19,"memory_kib":65536,"iterations":3,"parallelism":1,"salt":"IiIiIiIiIiIiIiIiIiIiIg=="},
          "aead":{"algorithm":"xchacha20poly1305"},
          "key_check":{"nonce":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz","ciphertext":"REREREREREREREREREREREREREREREREREREREREREQ="},
          "identity":{"generation":1,"envelope":{"nonce":"RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF","ciphertext":"RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkY="}},
          "policy":{"generation":1,"envelope":{"nonce":"VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV","ciphertext":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY="}},
          "audit":{"key_envelope":{"nonce":"Z2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dnZ2dn","ciphertext":"aGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGho"},"head_authenticator":"AAAAAAAAAAAAAAAAAAAAAA==","events":[]},
          "records":[],"unexpected":true
        }"#;

        assert!(parse(bytes).is_err());
    }
}
