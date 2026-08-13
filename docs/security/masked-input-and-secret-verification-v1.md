# Masked Input and Secret Verification V1

## Scope

Phase 7N adds usability feedback without adding a plaintext reveal command.
Sensitive terminal input remains fully hidden by default. The explicit global
flag below displays one `*` for every typed character:

```powershell
envvault --masked-input --vault .\demo.vault set TEST_TOKEN
```

This option controls terminal rendering only. It does not change storage,
authorization, Audit, input source, or cryptography. Because the number of stars
reveals input length, it is never enabled implicitly through configuration or an
environment variable. A non-terminal input still fails and never falls back to
argv, stdin pipes, or environment variables.

New Master Passwords and Secret Values are entered twice and must match before
any Vault write. Existing Master Password unlock remains a single entry. Escape,
Ctrl+C, terminal loss, or mismatch cannot commit a partially entered value.

## Value verification

```powershell
envvault --vault .\demo.vault verify TEST_TOKEN
```

The CLI reads an expected value from the protected terminal and prints only
`match` or `mismatch`. It never prints either plaintext. The expected and stored
values are compared through ephemeral fixed-length SHA-256 digests with a
constant-time comparison; no digest or reusable verifier is persisted.

`verify` is an independent exact Secret Operation. New managed Secrets grant
their creator `verify` alongside `list`, `exists`, `write`, and `delete`. For an
older Vault, the authenticated Owner may add only its own exact
`Caller × SecretId × verify` grant on first verification. This compatibility
upgrade requires the existing Owner `manage_policy` grant and refuses an explicit
deny. Non-Owner callers never receive an implicit grant.

Audit records the `verify` authorization decision before the stored value is
read. The expected value, stored value, digests, and match/mismatch result are not
Audit fields. Missing or unauthorized Secrets do not reveal plaintext.

## Program consumption

`examples/secret-consumer.ps1` demonstrates the intended consumer boundary. It
checks whether `TEST_TOKEN` was injected and outputs only `received: yes/no`.
The child does not open or decrypt the Vault. EnvVault authenticates its
credential, authorizes the Profile's exact `use` operations, records Audit,
decrypts the approved values, and injects only those environment variables.

This remains environment injection, not a sandbox: an authorized or compromised
child can read and leak the value it receives.
