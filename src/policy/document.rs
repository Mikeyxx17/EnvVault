use core::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::{
    identity::{Caller, CallerId, CallerKind},
    secret::SecretId,
};

use super::{
    Operation, PolicyEffect, PolicyRule, PolicySet, VaultOperation, VaultPolicyRule, VaultPolicySet,
};

const FORMAT_NAME: &str = "envvault-policy";
const FORMAT_VERSION: u32 = 1;
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RULES: usize = 10_000;

/// Versioned policy payload ready for authenticated persistence.
///
/// This type deliberately does not write an unauthenticated policy file. The
/// encoded bytes must be protected by the Broker/Vault integration before they
/// become a trusted policy source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    generation: u64,
    policy: PolicySet,
    vault_policy: VaultPolicySet,
}

impl PolicyDocument {
    /// Creates a policy document with a non-zero generation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyDocumentError::InvalidFormat`] for generation zero or
    /// [`PolicyDocumentError::ResourceLimitExceeded`] for too many rules.
    pub fn new(generation: u64, policy: PolicySet) -> Result<Self, PolicyDocumentError> {
        Self::new_with_vault_policy(generation, policy, VaultPolicySet::new())
    }

    /// Creates a document containing both per-Secret and Vault-scoped rules.
    ///
    /// # Errors
    ///
    /// Returns an error for generation zero or excessive total rule count.
    pub fn new_with_vault_policy(
        generation: u64,
        policy: PolicySet,
        vault_policy: VaultPolicySet,
    ) -> Result<Self, PolicyDocumentError> {
        if generation == 0 {
            return Err(PolicyDocumentError::InvalidFormat);
        }
        if policy
            .len()
            .checked_add(vault_policy.len())
            .ok_or(PolicyDocumentError::ResourceLimitExceeded)?
            > MAX_RULES
        {
            return Err(PolicyDocumentError::ResourceLimitExceeded);
        }
        Ok(Self {
            generation,
            policy,
            vault_policy,
        })
    }

    /// Strictly decodes a versioned policy payload.
    ///
    /// This verifies structure and limits, not authenticity. Callers must only
    /// use bytes obtained from an authenticated storage boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, unknown fields, unsupported
    /// versions, duplicate rules, unknown codes, or exceeded limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyDocumentError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(PolicyDocumentError::ResourceLimitExceeded);
        }
        let file: PolicyFile =
            serde_json::from_slice(bytes).map_err(|_| PolicyDocumentError::InvalidFormat)?;
        if file.format != FORMAT_NAME {
            return Err(PolicyDocumentError::InvalidFormat);
        }
        if file.version != FORMAT_VERSION {
            return Err(PolicyDocumentError::UnsupportedVersion);
        }
        if file.generation == 0 {
            return Err(PolicyDocumentError::InvalidFormat);
        }
        if file
            .rules
            .len()
            .checked_add(file.vault_rules.len())
            .ok_or(PolicyDocumentError::ResourceLimitExceeded)?
            > MAX_RULES
        {
            return Err(PolicyDocumentError::ResourceLimitExceeded);
        }

        let mut policy = PolicySet::new();
        for file_rule in file.rules {
            let effect = match file_rule.effect.as_str() {
                "allow" => PolicyEffect::Allow,
                "deny" => PolicyEffect::Deny,
                _ => return Err(PolicyDocumentError::InvalidFormat),
            };
            let caller_id = CallerId::from_str(&file_rule.caller_id)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            let caller_kind = CallerKind::from_str(&file_rule.caller_kind)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            let secret_id = SecretId::from_str(&file_rule.secret_id)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            let operation = Operation::from_str(&file_rule.operation)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            if !policy.insert(PolicyRule::new(
                Caller::new(caller_id, caller_kind),
                secret_id,
                operation,
                effect,
            )) {
                return Err(PolicyDocumentError::InvalidFormat);
            }
        }

        let mut vault_policy = VaultPolicySet::new();
        for file_rule in file.vault_rules {
            let effect = parse_effect(&file_rule.effect)?;
            let caller_id = CallerId::from_str(&file_rule.caller_id)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            let caller_kind = CallerKind::from_str(&file_rule.caller_kind)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            let operation = VaultOperation::from_str(&file_rule.operation)
                .map_err(|_| PolicyDocumentError::InvalidFormat)?;
            if !vault_policy.insert(VaultPolicyRule::new(
                Caller::new(caller_id, caller_kind),
                operation,
                effect,
            )) {
                return Err(PolicyDocumentError::InvalidFormat);
            }
        }

        Self::new_with_vault_policy(file.generation, policy, vault_policy)
    }

    /// Encodes this document in deterministic rule order.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or configured resource limits fail.
    pub fn encode(&self) -> Result<Vec<u8>, PolicyDocumentError> {
        let rules = self
            .policy
            .rules()
            .map(|rule| RuleFile {
                effect: rule.effect().as_str().to_owned(),
                caller_id: rule.caller_id().to_string(),
                caller_kind: rule.caller_kind().as_str().to_owned(),
                secret_id: rule.secret_id().to_string(),
                operation: rule.operation().as_str().to_owned(),
            })
            .collect();
        let file = PolicyFile {
            format: FORMAT_NAME.to_owned(),
            version: FORMAT_VERSION,
            generation: self.generation,
            rules,
            vault_rules: self
                .vault_policy
                .rules()
                .map(|rule| VaultRuleFile {
                    effect: rule.effect().as_str().to_owned(),
                    caller_id: rule.caller_id().to_string(),
                    caller_kind: rule.caller_kind().as_str().to_owned(),
                    operation: rule.operation().as_str().to_owned(),
                })
                .collect(),
        };
        let bytes =
            serde_json::to_vec_pretty(&file).map_err(|_| PolicyDocumentError::InvalidFormat)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(PolicyDocumentError::ResourceLimitExceeded);
        }
        Ok(bytes)
    }

    /// Returns the monotonic generation used for lost-update detection.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the decoded policy set.
    #[must_use]
    pub const fn policy(&self) -> &PolicySet {
        &self.policy
    }

    /// Returns the decoded Vault control-plane policy set.
    #[must_use]
    pub const fn vault_policy(&self) -> &VaultPolicySet {
        &self.vault_policy
    }

    /// Consumes the document and returns its policy set.
    #[must_use]
    pub fn into_policy(self) -> PolicySet {
        self.policy
    }

    /// Consumes the document and returns both independent policy sets.
    #[must_use]
    pub fn into_policies(self) -> (PolicySet, VaultPolicySet) {
        (self.policy, self.vault_policy)
    }
}

fn parse_effect(value: &str) -> Result<PolicyEffect, PolicyDocumentError> {
    match value {
        "allow" => Ok(PolicyEffect::Allow),
        "deny" => Ok(PolicyEffect::Deny),
        _ => Err(PolicyDocumentError::InvalidFormat),
    }
}

/// Safe failure category for policy payload parsing and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDocumentError {
    /// The payload is malformed or violates an invariant.
    InvalidFormat,
    /// The payload uses an unsupported version.
    UnsupportedVersion,
    /// The payload exceeds configured size or rule limits.
    ResourceLimitExceeded,
}

impl fmt::Display for PolicyDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFormat => "policy document is invalid",
            Self::UnsupportedVersion => "policy document version is unsupported",
            Self::ResourceLimitExceeded => "policy document exceeds resource limits",
        })
    }
}

impl std::error::Error for PolicyDocumentError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    format: String,
    version: u32,
    generation: u64,
    rules: Vec<RuleFile>,
    vault_rules: Vec<VaultRuleFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultRuleFile {
    effect: String,
    caller_id: String,
    caller_kind: String,
    operation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    effect: String,
    caller_id: String,
    caller_kind: String,
    secret_id: String,
    operation: String,
}

#[cfg(test)]
mod tests {
    use super::{PolicyDocument, PolicyDocumentError};
    use crate::{
        identity::{Caller, CallerId, CallerKind},
        policy::{
            Operation, PolicyEffect, PolicyRule, PolicySet, VaultOperation, VaultPolicyRule,
            VaultPolicySet,
        },
        secret::SecretId,
    };

    fn rule(effect: PolicyEffect) -> PolicyRule {
        PolicyRule::new(
            Caller::new(
                CallerId::from_bytes([0x11; CallerId::BYTE_LENGTH]),
                CallerKind::Application,
            ),
            SecretId::from_bytes([0x22; SecretId::BYTE_LENGTH]),
            Operation::Use,
            effect,
        )
    }

    #[test]
    fn policy_document_round_trips_canonically() -> Result<(), Box<dyn std::error::Error>> {
        let mut policy = PolicySet::new();
        assert!(policy.insert(rule(PolicyEffect::Allow)));
        assert!(policy.insert(rule(PolicyEffect::Deny)));
        let mut vault_policy = VaultPolicySet::new();
        assert!(vault_policy.insert(VaultPolicyRule::new(
            Caller::new(
                CallerId::from_bytes([0x11; CallerId::BYTE_LENGTH]),
                CallerKind::Human,
            ),
            VaultOperation::ManagePolicy,
            PolicyEffect::Allow,
        )));
        let document = PolicyDocument::new_with_vault_policy(7, policy, vault_policy)?;
        let first = document.encode()?;
        let decoded = PolicyDocument::decode(&first)?;
        let second = decoded.encode()?;

        assert_eq!(decoded, document);
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        let unknown = br#"{
          "format":"envvault-policy","version":1,"generation":1,
          "rules":[],"vault_rules":[],"unexpected":true
        }"#;
        let future = br#"{
          "format":"envvault-policy","version":2,"generation":1,"rules":[],"vault_rules":[]
        }"#;

        assert_eq!(
            PolicyDocument::decode(unknown),
            Err(PolicyDocumentError::InvalidFormat)
        );
        assert_eq!(
            PolicyDocument::decode(future),
            Err(PolicyDocumentError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_duplicate_and_unknown_rules() {
        let duplicate = br#"{
          "format":"envvault-policy","version":1,"generation":1,
          "rules":[
            {"effect":"allow","caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"application","secret_id":"22222222-2222-2222-2222-222222222222","operation":"use"},
            {"effect":"allow","caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"application","secret_id":"22222222-2222-2222-2222-222222222222","operation":"use"}
          ],"vault_rules":[]
        }"#;
        let unknown_operation = br#"{
          "format":"envvault-policy","version":1,"generation":1,
          "rules":[
            {"effect":"allow","caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"application","secret_id":"22222222-2222-2222-2222-222222222222","operation":"everything"}
          ],"vault_rules":[]
        }"#;
        let duplicate_vault_rule = br#"{
          "format":"envvault-policy","version":1,"generation":1,
          "rules":[],"vault_rules":[
            {"effect":"allow","caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"human","operation":"manage_policy"},
            {"effect":"allow","caller_id":"11111111-1111-1111-1111-111111111111","caller_kind":"human","operation":"manage_policy"}
          ]
        }"#;

        assert!(PolicyDocument::decode(duplicate).is_err());
        assert!(PolicyDocument::decode(unknown_operation).is_err());
        assert!(PolicyDocument::decode(duplicate_vault_rule).is_err());
    }
}
