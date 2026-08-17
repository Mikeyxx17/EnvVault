//! Durable compare-and-set evaluation for ADR 0015 server implementations.
//!
//! This module is the value-free server-side state machine. It does not
//! perform network I/O and never observes Secret Values.

use std::collections::{HashMap, VecDeque};

use crate::crypto::sha256;
use crate::vault::audit_v2::{parse_anchor, serialize_anchor};

/// Maximum idempotency-ledger entries retained per Vault.
const MAX_LEDGER_ENTRIES: usize = 256;

/// Required length of a client `request_id`.
pub(super) const REQUEST_ID_LENGTH: usize = 16;

/// Result of evaluating one compare-and-set request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CasDecision {
    /// The proposed canonical bytes were stored.
    Applied(Vec<u8>),
    /// The proposed bytes already matched the stored anchor.
    AlreadyApplied(Vec<u8>),
    /// The expected generation did not match current state.
    Conflict {
        /// Observed generation, or `0` when no anchor exists.
        generation: u64,
        /// Current canonical bytes, when any exist.
        current: Option<Vec<u8>>,
    },
    /// The request violated canonical, binding, or monotonicity rules.
    Invalid,
}

/// In-memory CAS state plus a bounded idempotency ledger.
#[derive(Debug, Default, Clone)]
pub(super) struct CasEngine {
    state: Option<(u64, Vec<u8>)>,
    ledger: HashMap<Vec<u8>, CasDecision>,
    ledger_order: VecDeque<Vec<u8>>,
}

impl CasEngine {
    /// Current generation and canonical bytes, if any.
    #[must_use]
    pub(super) fn state(&self) -> Option<&(u64, Vec<u8>)> {
        self.state.as_ref()
    }

    /// Restore engine state from durable storage.
    pub(super) fn restore(
        state: Option<(u64, Vec<u8>)>,
        ledger: Vec<(Vec<u8>, CasDecision)>,
    ) -> Self {
        let mut engine = Self {
            state,
            ledger: HashMap::new(),
            ledger_order: VecDeque::new(),
        };
        for (request_id, decision) in ledger {
            engine.remember(request_id, decision);
        }
        engine
    }

    /// Snapshot the ledger in insertion order for durable encoding.
    #[must_use]
    pub(super) fn ledger_entries(&self) -> Vec<(Vec<u8>, CasDecision)> {
        self.ledger_order
            .iter()
            .filter_map(|request_id| {
                self.ledger
                    .get(request_id)
                    .cloned()
                    .map(|decision| (request_id.clone(), decision))
            })
            .collect()
    }

    /// Evaluate GET: return the stored canonical bytes.
    #[must_use]
    pub(super) fn current_bytes(&self) -> Option<&[u8]> {
        self.state.as_ref().map(|(_, bytes)| bytes.as_slice())
    }

    /// Evaluate one compare-and-set, recording the first result for `request_id`.
    pub(super) fn compare_and_set(
        &mut self,
        path_vault: [u8; 16],
        request_id: &[u8],
        expected_generation: u64,
        anchor_bytes: &[u8],
    ) -> CasDecision {
        if request_id.len() != REQUEST_ID_LENGTH {
            return CasDecision::Invalid;
        }
        if let Some(previous) = self.ledger.get(request_id) {
            return previous.clone();
        }
        let decision = evaluate_cas(
            self.state.as_ref(),
            path_vault,
            expected_generation,
            anchor_bytes,
        );
        if let CasDecision::Applied(bytes) = &decision {
            let Ok(parsed) = parse_anchor(bytes) else {
                return CasDecision::Invalid;
            };
            self.state = Some((parsed.anchor_generation(), bytes.clone()));
        }
        self.remember(request_id.to_vec(), decision.clone());
        decision
    }

    fn remember(&mut self, request_id: Vec<u8>, decision: CasDecision) {
        if self.ledger.contains_key(&request_id) {
            return;
        }
        while self.ledger_order.len() >= MAX_LEDGER_ENTRIES {
            if let Some(oldest) = self.ledger_order.pop_front() {
                self.ledger.remove(&oldest);
            }
        }
        self.ledger.insert(request_id.clone(), decision);
        self.ledger_order.push_back(request_id);
    }
}

fn evaluate_cas(
    current: Option<&(u64, Vec<u8>)>,
    path_vault: [u8; 16],
    expected_generation: u64,
    anchor_bytes: &[u8],
) -> CasDecision {
    let Ok(proposed) = parse_anchor(anchor_bytes) else {
        return CasDecision::Invalid;
    };
    let Ok(canonical) = serialize_anchor(&proposed) else {
        return CasDecision::Invalid;
    };
    if canonical != anchor_bytes
        || proposed.vault_id() != path_vault
        || proposed.anchor_generation() != expected_generation.saturating_add(1)
    {
        return CasDecision::Invalid;
    }
    match current {
        None if expected_generation == 0 && proposed.previous_anchor_digest() == [0_u8; 32] => {
            CasDecision::Applied(anchor_bytes.to_vec())
        }
        None => CasDecision::Conflict {
            generation: 0,
            current: None,
        },
        Some((_, stored)) if stored == anchor_bytes => CasDecision::AlreadyApplied(stored.clone()),
        Some((generation, stored)) if *generation != expected_generation => CasDecision::Conflict {
            generation: *generation,
            current: Some(stored.clone()),
        },
        Some((_, stored)) => {
            let Ok(stored_anchor) = parse_anchor(stored) else {
                return CasDecision::Invalid;
            };
            if proposed.previous_anchor_digest() != sha256(stored)
                || proposed.segment_id() <= stored_anchor.segment_id()
                || proposed.sequence() <= stored_anchor.sequence()
            {
                return CasDecision::Invalid;
            }
            CasDecision::Applied(anchor_bytes.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CasDecision, CasEngine};
    use crate::crypto::sha256;
    use crate::vault::audit_v2::{AuditAnchorV2, serialize_anchor};

    const VAULT: [u8; 16] = [0x11; 16];

    fn anchor(
        generation: u64,
        terminal: [u8; 16],
        previous: [u8; 32],
    ) -> Result<Vec<u8>, crate::vault::VaultError> {
        serialize_anchor(&AuditAnchorV2::new(
            VAULT, generation, generation, generation, terminal, previous, 0,
        )?)
    }

    #[test]
    fn apply_retry_and_conflict_follow_exact_generation_cas()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut engine = CasEngine::default();
        let first = anchor(1, [0x21; 16], [0_u8; 32])?;
        let request = [0x01; 16];
        assert_eq!(
            engine.compare_and_set(VAULT, &request, 0, &first),
            CasDecision::Applied(first.clone())
        );
        assert_eq!(
            engine.compare_and_set(VAULT, &request, 0, &first),
            CasDecision::Applied(first.clone())
        );
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x02; 16], 0, &first),
            CasDecision::AlreadyApplied(first.clone())
        );
        let fork = anchor(1, [0x22; 16], [0_u8; 32])?;
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x03; 16], 0, &fork),
            CasDecision::Conflict {
                generation: 1,
                current: Some(first.clone()),
            }
        );
        let second = anchor(2, [0x23; 16], sha256(&first))?;
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x04; 16], 1, &second),
            CasDecision::Applied(second)
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_vault_non_canonical_and_generation_gaps()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut engine = CasEngine::default();
        let first = anchor(1, [0x21; 16], [0_u8; 32])?;
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x01; 16], 0, &first),
            CasDecision::Applied(first.clone())
        );
        let skipped = anchor(3, [0x33; 16], sha256(&first))?;
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x02; 16], 1, &skipped),
            CasDecision::Invalid
        );
        let other = serialize_anchor(&AuditAnchorV2::new(
            [0x99; 16],
            2,
            2,
            2,
            [0x55; 16],
            sha256(&first),
            0,
        )?)?;
        assert_eq!(
            engine.compare_and_set(VAULT, &[0x03; 16], 1, &other),
            CasDecision::Invalid
        );
        Ok(())
    }
}
