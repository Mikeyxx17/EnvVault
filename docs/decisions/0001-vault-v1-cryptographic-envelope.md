# ADR 0001: Vault V1 Cryptographic Envelope

- Status: Accepted for initial implementation
- Date: 2026-08-12

## Context

EnvVault 需要独立保护每条 Secret，并允许 Broker 只读取经过授权的记录。整个 `.env` 或整个 Vault 作为单个密文会破坏逐 Secret 授权边界。

第一版还需要在不引入复杂 KEK/DEK 层级的情况下，提供密码派生、认证加密、格式版本和原子持久化基线。

## Decision

1. 使用 Argon2id v19 从 Master Password 派生 32-byte Master Key。
2. 使用 XChaCha20-Poly1305，并由 OS CSPRNG 为每个 envelope 生成 24-byte nonce。
3. 一个 Secret 对应一个稳定 `SecretId` 和两个 envelope：加密名称的 metadata envelope 与加密 Value 的 value envelope。
4. AAD 绑定格式版本、Vault ID、Secret ID、revision 和 envelope kind。
5. 空 Vault 使用独立 key-check envelope 验证派生 key。
6. V1 直接使用 Master Key 加密各 envelope，不引入 per-record DEK/KEK。
7. Vault 文件使用严格、版本化 JSON；二进制字段使用标准 Base64。
8. 使用同目录临时文件、同步和原子提交更新 Vault，并使用锁与 state 比较防止协作进程丢失更新。
9. File Vault 实现保持 crate-private；即使 Policy/Broker 已集成，也不作为可绕过 Broker 的外部 API 暴露。

## Consequences

优点：

- Secret 是独立密文和独立权限对象。
- `list` 只解密名称，不解密 Secret Value。
- 修改 Secret ID、revision、Vault ID 或 envelope kind 会导致认证失败。
- 格式具有明确版本和资源上限。

代价与限制：

- 修改 Master Password 必须重新加密全部记录。
- 文件中的 Secret 数量、ID、revision 和密文长度仍可见。
- V1 不能可靠检测整个旧 Vault 或旧记录的离线回滚。
- 原子替换不等于 Windows ACL、安全删除、备份或同步软件安全。
- 设计和自动化测试通过不等于独立密码学审计完成。

## Revisit when

- 实现 Master Password 修改或系统 Keystore 集成。
- 需要大规模记录、独立轮换或更小的重新加密范围。
- 实现可信 rollback protection。
- 开始公开稳定的 Vault 文件兼容性承诺。
