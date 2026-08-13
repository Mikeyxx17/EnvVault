# Audit V2 Vault Descriptor V3

状态：严格 canonical parser/store、generation 条件提交、active/sealed key envelopes 和 authenticated local recovery 已实现；Phase 7J 已将它接入新 Vault 的 Broker/CLI Audit 路径，历史 V1 Vault 不静默迁移。

## 文件与内容

Descriptor 固定为 `<vault>.audit-descriptor-v3.json`，format/version 为 `envvault-vault-descriptor`/`3`。文件使用 `secure_fs` 私有权限、主 Vault 的 `<vault>.lock` 和同目录原子替换。

根字段保存 vault id、非零 generation，以及 Audit 状态：

- `sealed_segments`：连续的 segment id/sequence、predecessor/terminal、canonical SHA-256、精确文件名和该 segment 的加密 key envelope；
- `active_segment`：segment id、start/next sequence、predecessor/head 和当前 active key envelope。

Key envelope 固定为 XChaCha20-Poly1305、24-byte nonce 和 48-byte ciphertext。它不包含明文 Audit key、Secret Value、credential 或 password。具体 envelope 用 Master Key 认证；单纯 parser 只验证结构，已解锁恢复/读取路径必须解封并验证 context。

## 密钥生命周期

Active key envelope 的 AAD 是：

```text
"envvault:audit-active-key:v3\0"
|| u32_be(3)
|| vault_id[16]
|| u64_be(segment_id)
|| u64_be(start_sequence)
|| previous_segment_authenticator[16]
```

只绑定 active segment 生命周期内不变的字段，因此追加事件不会要求重包 key。轮换提交时：

1. 当前 active key envelope 原样移动到新增 sealed reference；
2. Manifest V2 中经过 Master Key 认证的下一 key envelope成为新的 active envelope；
3. descriptor generation 精确加一；
4. 新 active id/start/predecessor 精确接续旧 segment terminal。

这样历史 sealed segment 仍能解封对应 key 并逐事件认证，新 active segment 则使用独立随机 key。错误 context、错误 Master Key、修改 ciphertext 或断裂 continuity 都失败关闭。

## Canonical 与并发规则

Parser 拒绝未知字段、非 version 3、错误 Base64/长度、未知算法、不连续 segment/sequence、错误文件名和资源超限。磁盘 Store 还要求 canonical bytes 逐字节匹配。Descriptor 最多 8 MiB、16,384 个 sealed references。

提交必须在主 Vault lock 内比较 expected generation 和完整 active state；陈旧、领先、回退、重复 segment 或 next-key envelope 不一致均不覆盖磁盘状态。固定向量为 `tests/fixtures/audit_v2/vault-descriptor-v3.json`。

## 未完成边界

- sidecar 与 Secret/Policy/Identity 主 Vault state 的统一文件级事务；
- 真正 remote/hardware external anchor CAS 和完整文件 rollback protection；
- 父目录 durability、强制终止、断电及独立安全评审。
