# Security

EnvVault is security-sensitive software. The current codebase implements an encrypted local Vault, exact per-Secret authorization, authenticated caller identities, value-free Audit V2, platform-keystore-backed machine unlock, persistent authentication throttling, and bounded caller-credential lifetime.

Passing automated checks is not a production-security certification. External monotonic anchoring, adversarial crash/power-loss testing, full Linux/macOS platform acceptance, long-running fuzzing, and independent security review are still required before using EnvVault for production Secrets.

## Security invariants

- One Secret is one independent storage and authorization unit.
- Authorization is `Caller × Secret × Operation`; authentication never grants the whole Vault.
- Vault control-plane operations are separately authorized and default-deny.
- Secret Values, passwords, caller credentials, and key material must not enter argv, normal logs, Audit events, or error rendering.
- Broker ordering is Identity → Policy → Audit → Vault/operation; required persistence failures fail closed.
- `run -- command` is environment injection, not a sandbox for untrusted code or AI Agents.
- Local credential stores do not isolate EnvVault from every malicious process running as the same OS user.

## Supported security reporting

Do not open a public issue containing an exploit, real Secret, Vault file, credential file, recovery sidecar, or sensitive system details. Report privately through GitHub's private vulnerability reporting feature when enabled for the repository.

Include:

- affected commit or release;
- operating system and filesystem;
- minimal reproduction using fake values only;
- expected and observed security behavior;
- whether Secret disclosure, authorization bypass, Audit loss, rollback, or denial of service is involved.

## Required validation

The repeatable local gate is:

```powershell
.\scripts\security-check.ps1 -Release -IncludeWindowsCredentialStore
.\scripts\security-check.ps1 -IncludeFuzz -SecondsPerFuzzTarget 60
```

The second command requires nightly Rust, `cargo-fuzz`, and the Visual Studio x64 ASan runtime. See [Security Design](./docs/security/README.md) and the active [follow-up plan](./docs/roadmap/next-plan.md) for evidence boundaries and remaining production acceptance.
