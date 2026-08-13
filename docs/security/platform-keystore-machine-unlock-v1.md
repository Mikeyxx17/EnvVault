# Platform Keystore Machine Unlock V1

## Scope

Phase 7K/7L add an explicit non-interactive unlock path for registered
Application and AI Agent callers on Windows, Linux and macOS:

```text
platform credential-store wrapping key
        + private authenticated binding sidecar
        -> Vault Master Key
        -> authenticated caller credential
        -> exact per-Secret `use` policy
        -> child process injection
```

The platform store never receives the Master Password or the Vault Master Key.
It stores one random 32-byte wrapping key. The Master Key is encrypted with
XChaCha20-Poly1305 in `<vault>.machine-unlock-v1.json`; AAD binds the Vault ID,
credential generation, backend, service and exact account name.

## Commands

All management commands require an interactive Master Password and exact Owner
authorization for `manage_keystore`:

```powershell
envvault --vault .\team.vault keystore enable
envvault --vault .\team.vault keystore status
envvault --vault .\team.vault keystore rotate
envvault --vault .\team.vault keystore disable
```

The first `enable` on an older Vault performs an authenticated policy update
that grants only its existing Owner the new `manage_keystore` operation. It does
not grant any data-plane permission.

Machine execution remains explicit and still requires a registered caller
credential file and exact `use` grants:

```powershell
envvault --vault .\team.vault run `
  --machine-unlock `
  --profile .\backend.profile.json `
  --credential-file .\backend.credential.json `
  -- cargo run
```

No Master Password, wrapping key or Master Key is accepted through argv,
environment variables or stdin. Without `--machine-unlock`, `run` retains the
interactive Master Password flow.

## Rotation and recovery

Rotation is generation based:

1. Create a new platform credential account and random wrapping key.
2. Write a new authenticated Master Key envelope.
3. Atomically replace the binding sidecar.
4. Remove the retired platform credential.

A crash before step 3 leaves the previous generation active. A crash after
step 3 leaves the new generation active and records the old account for retryable
cleanup. `cleanup_pending` exposes only the number of retired entries.

Disable first writes a disabled binding, so machine unlock fails closed before
credential cleanup. If platform deletion fails, the disabled tombstone retains
the retired account names and `keystore disable` can be retried. The sidecar is
removed only after all known credential entries are deleted.

The Master Password remains the recovery root. Loss or corruption of either the
platform entry or sidecar never changes the encrypted Vault; the Owner can open
with the Master Password, disable the broken binding, then enable it again.

## Threat boundary

The platform backend is Windows Credential Manager, Linux Secret Service, or the
macOS Keychain. The authenticated sidecar records the exact backend name, so a
binding cannot silently move between backends. Unsupported targets fail closed.
These stores support unattended execution under the current OS user/session; the
design does not isolate secrets from another malicious process already running
as that user, a debugger, a compromised target program, or an AI Agent that can
modify the launched program. `run` authorization and environment minimization
still apply, but they are not an operating-system sandbox. A locked or unavailable
Secret Service collection or Keychain is reported as credential unavailable; it
never falls back to a file-stored wrapping key.

The Linux adapter stores the random wrapping key as canonical Base64 text inside
Secret Service so backends such as KDE Wallet that only preserve UTF-8 values do
not corrupt arbitrary binary key bytes. The decoded key is still length-checked
by the authenticated binding path before use.

## Verification boundary

Automated tests cover canonical parsing, unknown-field rejection, authenticated
Master Key wrapping, wrong/tampered binding rejection, enable/rotate/disable and
retired-entry cleanup using an in-memory credential-store adapter. The CI
regression matrix builds/tests the target-selected Windows, Linux and macOS
adapters.

Automated tests do not prove Credential Manager, Secret Service, or Keychain
behavior across account logon/logoff, locked sessions/collections, enterprise
policy, low-privilege users, OS upgrades, real power loss, concurrent processes,
or installer/service contexts. These remain per-platform manual acceptance gates.
