# Caller Credential Expiry V1

## Scope

Phase 7Q completes the bounded lifecycle for newly registered and rotated
Application/AI Agent credentials. Expiry is enforced by the authenticated
Identity Registry and Broker, not by a caller-controlled credential file or a
CLI-only pre-check.

## Policy

- Identity Registry V3 stores an issuance timestamp and expiry timestamp beside
  each Argon2id verifier inside the encrypted/authenticated identity payload.
- Every new or rotated credential has an exact 90-day lifetime.
- The validity interval is `[issued, expires)`: authentication at the expiry
  millisecond is denied.
- There is no grace period. Rotation is the recovery path and preserves the
  stable CallerId, CallerKind, name and Policy rules.
- `identity list` prints the enforced expiry timestamp. A migrated V1/V2 entry
  prints `legacy-unbounded` until the Owner rotates it.

The V3 parser accepts only the exact 90-day window or the explicit legacy
sentinel `(issued=0, expires=u64::MAX)`. Missing, reversed, shortened, extended
or unknown lifecycle fields fail closed.

## Authentication ordering

The Broker first advances the persisted last-observed authentication time using
`max(current, last_observed)`. It then performs the real bounded Argon2id check
for a known expired credential and combines the constant-time verifier result
with the lifecycle decision. Expired, wrong, unknown, wrong-kind and throttled
claims therefore keep the same value-free Audit shape and the same
`caller identity is unavailable` result.

A successful rotation uses at least the persisted last-observed time as its new
issuance time. Moving the wall clock backward cannot revive an expired
credential or create a replacement that is already expired relative to the
Registry clock.

## Migration and limits

V1 and V2 Registry documents remain readable. Their existing credentials did
not carry trustworthy issuance data, so silently inventing a historical expiry
would either revoke them unpredictably or extend them without evidence. They
are migrated with an explicit legacy-unbounded sentinel and must be rotated by
the Owner to enter the V3 90-day policy.

An administrator-controlled forward clock jump can expire credentials early.
Restoring an older complete Vault can restore older lifecycle and clock state
until an external monotonic anchor is operational. Credential files remain
bearer evidence and old files are not deleted automatically after rotation.
