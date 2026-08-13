# Key Lifecycle V1

## 创建 Vault

```text
Master Password
      │
      ├── Argon2id + random salt + stored parameters
      ▼
32-byte Master Key
      │
      ├── encrypt key-check envelope
      └── independently encrypt each Secret payload
```

Master Password 不得进入 CLI 参数、环境变量、日志或错误。后续 CLI 必须从受控 TTY/stdin 输入构造可清零的密码容器。

## 解锁

1. 严格解析公开文件头并验证资源上限。
2. 用文件中的 Argon2id 参数和 salt 派生候选 Master Key。
3. 验证 key-check AEAD envelope。
4. 验证失败时丢弃候选 key，并返回统一失败。
5. 验证成功后，Master Key 只保存在 unlocked Vault 对象中。

解锁不代表任何 Caller 获得 Secret 权限。Broker 仍必须对每条 Secret 和 Operation 调用 Policy Engine。

## 使用期间

- Master Key 使用 `Zeroizing<[u8; 32]>` 包装并在 unlocked Vault drop 时清零。
- Secret Value 和解密中间缓冲区使用可清零容器。
- 敏感类型不实现 `Display`、普通 `Debug` 或 `Clone`。
- 每条 Secret 按需解密，不批量构造整个明文 Vault。
- Policy、Identity 和 Audit 不接收 Master Key 或 Secret Value。

Master Key 还保护 Identity Registry envelope 和随机生成的 Audit key envelope。Audit event 不直接使用 Master Key，而是使用每个 V2 segment 独立的 Audit key；Descriptor V3 为 active 与 sealed segment 保存 context-bound encrypted envelope，Manifest V2 只暂存下一 active envelope。解封后的 key 使用 zeroizing 类型，并在 builder/验证路径 drop 时清零。

Application/AI Agent credential 是 OS CSPRNG 生成的 32-byte 随机值，由受限类型持有并在 drop 时清零。Registry 使用独立 salt 和 Argon2id 生成 verifier；原始 credential 不持久化。验证派生缓冲区使用 `Zeroizing`，比较使用常量时间实现。

内存清零不能保证清除寄存器、交换文件、崩溃转储或已被其他进程复制的数据。

## Nonce 与 ID

- Vault ID、Secret ID、salt 和每个 nonce 都由 OS CSPRNG 生成。
- XChaCha20-Poly1305 nonce 长度固定为 24 bytes。
- 每次新建、更新、重命名或轮换记录都生成新 nonce。
- 代码不得提供调用者指定 nonce 的公开生产接口。

## 密码变更

V1 直接用 Master Key 加密每条记录，因此修改 Master Password 需要：

1. 用旧 key 验证并逐条解密。
2. 生成新 salt 并派生新 Master Key。
3. 使用全新 nonce 逐条重新加密。
4. 生成新的 key-check envelope。
5. 原子提交完整新 Vault。

这一功能尚未实现。未来采用 KEK + per-record DEK 后可以减少密码变更时的数据重加密，但在第一版不提前增加复杂度。

## 错误和 Drop

- 派生、加密、解密或序列化失败时，已创建的敏感缓冲区必须按作用域 drop 并清零。
- 错误值只能包含安全类别，不能持有密码、key、明文或解密缓冲区。
- panic 不是正常错误处理路径；生产代码继续禁止 `unwrap`、`expect` 和显式 `panic`。
