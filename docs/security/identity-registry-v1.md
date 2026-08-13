# Identity Registry V1/V2/V3

## 状态

状态：内部实现和自动化验证完成；CLI 私有文件交付、Windows 专用 DACL、崩溃恢复、三平台 keystore adapter 与机器身份会话第一版已接入，真实平台验收仍待完成。

Identity Registry 是 Vault 内经过认证加密的严格文档。它保存稳定 Owner CallerId、Application/AI Agent 的非秘密元数据和 credential verifier，V2 有界认证限流状态，以及 V3 强制 credential 生命周期。它不保存原始 credential。V1/V2 只读兼容，下一次身份更新会严格写为 V3。

## 调用者类型

- Human Owner：由 Master Password 成功解锁和 Identity envelope 认证建立。
- Application：使用注册时签发的随机 credential。
- AI Agent：使用相同凭证机制，但产生 `AgentCredential` authentication method，Policy 默认仍拒绝。

V1 不允许通过 credential 注册额外 Human。Caller name 只是管理标签，Policy 始终匹配稳定 CallerId 与 CallerKind。

## Registry 文档

解密后的逻辑格式：

```json
{
  "format": "envvault-identity-registry",
  "version": 3,
  "generation": 2,
  "owner_id": "11111111-1111-1111-1111-111111111111",
  "owner_kind": "human",
  "callers": [
    {
      "caller_id": "22222222-2222-2222-2222-222222222222",
      "caller_kind": "application",
      "name": "backend",
      "credential_issued_unix_time_millis": 1700000000000,
      "credential_expires_unix_time_millis": 1707776000000,
      "kdf": {
        "algorithm": "argon2id",
        "version": 19,
        "memory_kib": 65536,
        "iterations": 3,
        "parallelism": 1,
        "salt": "base64(16 bytes)"
      },
      "verifier": "base64(32 bytes)"
    }
  ]
}
```

规则：

- 文档最大 1 MiB，最多 256 个注册 Caller。
- CallerId 和 caller name 都不能重复。
- caller name 最大 128 UTF-8 bytes，不允许控制字符或首尾空白。
- KDF 参数必须通过资源上下界验证，防止恶意参数导致资源耗尽。
- 文档 generation 必须等于 Identity envelope generation。
- V3 新凭据只能使用严格 90 天窗口；V1/V2 迁移条目使用显式 legacy sentinel，轮换后进入有限生命周期。
- 未知字段、未知版本、Human credential、错误 Base64 或重复记录全部拒绝。

## 凭证生命周期

注册：

1. Actor 必须通过 `manage_identity` Vault policy。
2. Broker 先完成认证 Audit 写入。
3. OS CSPRNG 生成随机 CallerId、32-byte credential 和 16-byte salt。
4. Argon2id 生成 32-byte verifier。
5. 原子、generation-checked 地替换加密 Registry。
6. 原始 credential 只通过不可 `Debug`/`Clone` 的签发结果返回一次。

认证：

1. 调用方提交 CallerId、CallerKind 和 credential evidence。
2. Broker 使用注册参数重新执行 Argon2id。
3. 使用常量时间比较验证结果。
4. 未知 CallerId、错误 CallerKind 和错误 credential 返回同一安全错误；未知 ID 仍执行同成本 dummy KDF。
5. 成功后创建 `VerifiedCaller`，但不会自动增加任何 Policy grant。
6. Phase 7P 的每次机器凭据认证会在 Audit 成功后持久化有界 bucket/global 限流结果并推进 Identity generation；任何持久化冲突都失败关闭。
7. Phase 7Q 在同一 Registry 时钟下强制 `[issued, expires)`，过期与其他认证失败使用相同错误和 Audit 形状。

轮换：

- Owner 必须拥有 `manage_identity`，并显式指定一个不存在的新 credential 文件。
- Broker 保留 CallerId、CallerKind、名称及现有 Policy，只生成新的随机 credential、salt 和 verifier。
- Registry generation-checked 提交后旧 credential 立即失效；新 credential 仍只交付一次。
- recovery 重新计算恢复文档中的 credential 是否与当前 Registry verifier 匹配，从而区分提交前与提交后崩溃，不能只根据 CallerId 仍存在作判断。

撤销：

- Actor 必须拥有 `manage_identity`。
- Registry 原子更新后，旧 credential 立即无法建立 `VerifiedCaller`。
- 已存在的 Policy rules 可以继续保留，但没有可验证身份就无法使用这些规则。

## 明确限制

- Phase 7O 已加入显式 credential rotation；旧 credential 文件不会自动删除，用户应在新文件验证可用后自行安全处理旧文件。
- CLI 已提供不覆盖目标、专用 DACL/`0600` 和 recovery 文档交付边界，但文件保存的仍是明文认证证据。
- Phase 7K/7L 已接入 Windows Credential Manager、Linux Secret Service 与 macOS Keychain wrapping-key adapter；真实平台验收仍是独立门禁。
- Phase 7M 已把成功/失败凭据校验写入独立 wire-version 的 authentication-attempt Audit；事件归因于被提交的 Caller claim，不把失败主体误写成已验证身份。
- Phase 7P 已实现 64 bucket 与全局窗口的持久化认证限流；完整 Vault 回滚、系统时间前跳、并发可用性和同用户 credential 文件读取仍不由该机制解决。
- Phase 7Q 已实现新注册/轮换 credential 的严格 90 天有效期；旧 V1/V2 credential 必须由 Owner 显式轮换，不能伪造历史签发时间后自动过期。
- 同权限恶意进程如果能读取调用方保存的 credential，仍可冒充该调用方。
