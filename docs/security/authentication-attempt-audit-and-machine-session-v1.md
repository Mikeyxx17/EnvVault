# Authentication Attempt Audit and Machine Session V1

## Scope

Phase 7M closes the registered machine-identity authentication boundary. An
Application or AI Agent credential check now creates a value-free authenticated
Audit event before the Broker returns either a `VerifiedCaller` or the same
`caller identity unavailable` error used for wrong, unknown and wrong-kind
credentials.

The CLI exposes a minimal session command:

```powershell
envvault --vault .\team.vault session `
  --credential-file .\backend.credential.json `
  --machine-unlock `
  whoami
```

Without `--machine-unlock`, the same command uses the interactive Master Password
unlock flow. `whoami` prints only CallerId, CallerKind and AuthenticationMethod.
It has no Profile option, does not authorize or load a Secret, and does not start
a child process.

## Audit format and ordering

Secret and Vault authorization events retain AuditEvent wire version 1.
Authentication attempts use wire version 2 with target `authentication` and no
SecretId, Secret Operation, or VaultOperation. Reusing the existing event envelope
keeps Audit V2 segment encryption, ordering, rotation, recovery and value-free
invariants unchanged while preventing old version-1 parsers from interpreting a
new target.

For Application and AI Agent credentials, Broker ordering is:

1. Resolve the stored verifier, or use the dummy verifier for an unknown subject.
2. Run the bounded Argon2id derivation and constant-time verifier comparison.
3. Persist an allow/deny authentication event to the Vault Audit backend.
4. Submit the same event to the configured external Audit sink.
5. Only then return `VerifiedCaller` or the uniform identity error.

If either Audit write fails, authentication fails closed with Audit unavailable.
The event records the claimed CallerId/CallerKind and attempted mechanism, never
the credential, verifier, Master Password, Master Key, Profile or Secret Value.
Malformed credential files and the unsupported Human credential kind are rejected
at their structural boundary before they become a cryptographic authentication
attempt.

## Security boundary

Successful `session whoami` proves possession of a currently registered local
credential after the Vault has been unlocked. It grants no Secret or Vault
operation. `run` still performs exact per-Secret `use` authorization after the
same authentication step.

Phase 7M itself did not provide credential expiry, process attestation, Human
Approval, short-lived capability tokens, remote identity, or an OS sandbox.
Phase 7O adds explicit Owner-controlled credential rotation, Phase 7P adds
persistent bucket/global throttling, and Phase 7Q adds Registry-enforced expiry
without changing the value-free authentication Audit format. Their additional
persistence ordering and limits are documented separately.
