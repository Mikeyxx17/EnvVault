# Caller Credential Rotation V1

## Scope

Phase 7O adds explicit credential rotation for a registered Application or AI
Agent without creating a new policy subject:

```powershell
envvault --vault .\team.vault identity rotate `
  --caller-id <CALLER_ID> `
  --credential-file .\backend.rotated.credential.json
```

The Owner authenticates interactively and must have the exact
`manage_identity` Vault permission. The destination must not exist. Credential
material is never accepted through argv, an environment variable, stdout or
stderr.

## Security properties

- CallerId, CallerKind, display name and existing Policy rules are preserved.
- A CSPRNG creates a new 32-byte credential and independent 16-byte salt.
- Only the new Argon2id verifier is committed to the encrypted Registry.
- The Registry update compares the expected generation and increments it once.
- After the commit, the old credential cannot create a `VerifiedCaller`.
- The new credential is written once to a protected `create_new` file.
- The old credential file is not removed or overwritten automatically.

## Crash recovery

The recovery document is synchronized before the empty destination and Registry
commit. On the next Owner open, EnvVault derives the recovery credential with
the currently stored verifier:

- mismatch or missing Caller: the Registry commit did not install that
  credential, so only a missing or private empty destination may be cleaned;
- match: the Registry commit installed it, so a missing/private empty
  destination may be completed, or an exact existing file accepted;
- unsafe or non-empty mismatching destination: recovery fails closed and keeps
  the evidence.

Checking the current verifier is required for rotation because the CallerId
exists both before and after the commit. This also strengthens registration
recovery by proving the exact credential rather than only Caller existence.

## Remaining boundary

Rotation limits the lifetime of a leaked static credential only after the Owner
acts. Phase 7O itself does not add expiry, automatic scheduling, process
attestation or protection from another process that can read the new credential
file; Phase 7P separately adds persistent authentication throttling. Real
power-loss and adversarial concurrent-file replacement testing remain Phase 7
acceptance gates.
