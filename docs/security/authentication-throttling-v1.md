# Authentication Throttling V1

## Scope

Phase 7P adds persistent abuse throttling to local Application and AI Agent
credential authentication. It does not create a capability, short-lived token,
Human Approval flow or any other Phase 8 mechanism.

The state lives inside the authenticated and encrypted Identity Registry V2.
Identity Registry V1 remains readable; the first successful persistence of an
authentication result or later identity-management update writes strict V2.
The wire document stores only non-empty buckets as a strictly increasing,
unique index list capped at 64 entries; runtime lookup still uses a fixed
64-element array. This keeps the common payload bounded without accepting an
attacker-controlled unbounded map.

## Limits

- CallerId claims map to 64 fixed buckets using the low six bits of the first
  random CallerId byte. Registered and unknown claims use the same mapping.
- Five failed attempts in one bucket within 60 seconds block that bucket for 60
  seconds.
- Fifty failed attempts across buckets within 60 seconds block machine-identity
  authentication globally for 60 seconds.
- A successful authentication clears its bucket, but never clears the global
  failure window.
- Attempts received while blocked do not extend the block indefinitely.

The bucket design avoids persisting an attacker-controlled unbounded map and
does not require revealing whether a claimed CallerId is registered. Different
CallerIds can share a bucket, and the global limit can temporarily deny valid
machine callers; the Human Owner Master Password path is not throttled by this
state.

## Broker ordering

For a structurally valid Application/AI Agent claim:

1. Clone the authenticated Registry state and apply monotonic wall-clock
   observation using `max(current, last_observed)`.
2. If the bucket/global scope is not blocked, run the real or dummy bounded
   Argon2id verifier and constant-time comparison. A blocked scope skips the
   expensive KDF.
3. Persist the same value-free allow/deny authentication Audit event used by
   Phase 7M, then submit it to the configured external Audit sink.
4. Record the result in the Registry candidate, increment its generation and
   atomically replace the encrypted Identity payload.
5. Return `VerifiedCaller` only if the credential matched and every Audit and
   throttle persistence step succeeded.

Wrong, unknown, wrong-kind, blocked and throttle-persistence-conflict attempts
still return `caller identity is unavailable`. Audit does not contain the
credential, verifier, bucket index or an explicit lockout reason.

## Clock and concurrency behavior

The persisted last-observed timestamp prevents a backward wall-clock change
from expiring a block early. An administrator-controlled forward jump can still
expire a window; V1 does not claim a trusted hardware clock.

Each machine authentication advances Identity generation. Concurrent Broker
instances opened from the same generation race through exact generation/full
state comparison: one may succeed and a stale update fails closed. This favors
security over availability and remains a multi-process stress-test item.

## Remaining boundary

- Restoring an older complete Vault can also restore older throttle state until
  a truly external monotonic AnchorSink is deployed.
- A same-user attacker able to read the credential file does not need online
  guessing; file isolation and platform acceptance remain separate controls.
- Global throttling can be used for availability attacks, though it is bounded
  and does not lock out Owner Master Password management.
- Credential expiry is implemented by Phase 7Q with the same persisted
  last-observed clock; a trusted hardware clock is still not implemented.
- Multi-process load, clock manipulation and real platform operational
  acceptance remain Phase 7 gates.
