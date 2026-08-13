# Security Design

本目录用于维护 Threat Model、信任边界、攻击面、安全假设和待验证事项。

- [EnvVault Threat Model](./threat-model.md)
- [Vault Format V1](./vault-format-v1.md)
- [Key Lifecycle V1](./key-lifecycle.md)
- [Policy Engine V1](./policy-engine-v1.md)
- [Secret Broker V1](./secret-broker-v1.md)
- [Identity Registry V1/V2/V3](./identity-registry-v1.md)
- [Management CLI V1](./management-cli-v1.md)
- [Dotenv Migration V1](./dotenv-migration-v1.md)
- [Runtime Injection V1](./runtime-injection-v1.md)
- [Sensitive Files and Credential Recovery V1](./sensitive-files-and-credential-recovery-v1.md)
- [Parser Fuzzing and Security Properties V1](./parser-fuzzing-v1.md)
- [Dependency and Supply-chain Policy V1](./supply-chain-v1.md)
- [Audit V2 Canonical Format](./audit-v2-format.md)
- [Audit V2 Rotation Fault-injection Matrix](./audit-rotation-fault-matrix.md)
- [Audit Rotation Recovery Manifest V2](./audit-rotation-recovery-v2.md)
- [Audit V2 Segment Store V1](./audit-segment-store-v1.md)
- [Audit V2 Vault Descriptor V3](./audit-vault-descriptor-v3.md)
- [Audit V2 Segment Builder and Key Rotation](./audit-segment-builder-v2.md)
- [Audit V2 Anchor and Runtime Integration](./audit-anchor-and-runtime-v2.md)
- [Platform Keystore Machine Unlock V1](./platform-keystore-machine-unlock-v1.md)
- [Authentication Attempt Audit and Machine Session V1](./authentication-attempt-audit-and-machine-session-v1.md)
- [Masked Input and Secret Verification V1](./masked-input-and-secret-verification-v1.md)
- [Caller Credential Rotation V1](./credential-rotation-v1.md)
- [Authentication Throttling V1](./authentication-throttling-v1.md)
- [Caller Credential Expiry V1](./credential-expiry-v1.md)

当前威胁模型是实现约束，不是安全能力证明。`crypto`、`identity`、`policy`、`broker`、`vault` 和 `process` 模块只有经过实现与分层验收后，才能声明对应能力。
