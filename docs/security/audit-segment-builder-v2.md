# Audit V2 Segment Builder and Key Rotation

状态：V2 event encryption、segment build/verify、active-key wrap/unwrap、轮换准备与 authenticated recovery 已实现，并已由 Phase 7J 接入新 Vault、Broker 和 CLI 的默认 Audit backend；历史 V1 Vault 仍要求显式迁移。

## Segment 构建

`AuditSegmentBuilderV2` 接收 value-free `AuditEvent`、独立 32-byte `AuditKey` 和 segment identity。每次 append：

1. 使用严格 Audit Event V1 canonical JSON；
2. 按 start sequence 连续分配 sequence，最多 4096 项；
3. 使用 Audit V2 event AAD 绑定 vault id、segment id、sequence 和前一 authenticator；
4. XChaCha20-Poly1305 加密，并把 tag 作为下一事件 predecessor；
5. seal 时建立 canonical Audit Segment V2，并复核 terminal authenticator。

验证路径重新解析 canonical bytes，用对应 sealed/active key 逐事件解密和验证 AAD，再严格解析每个 value-free AuditEvent。错误 key、nonce/ciphertext 篡改、sequence gap、错误 predecessor 或 terminal 均返回 `CorruptedAudit`/格式错误，不返回部分事件。

## 轮换准备

`prepare_rotation_for_vault` 是 crate-private 内部入口。它在 Vault lock 内：

- 加载 canonical Descriptor V3；
- 检查待封存 segment 与 descriptor active identity/head 完全一致；
- 用 Master Key 和 immutable context 解封当前 active key；
- 逐事件认证待封存 segment；
- 生成新的随机 Audit key，并构造下一 active-key envelope；
- 创建不覆盖的 Recovery Manifest V2。

后续 `AuditRotationCoordinator::step` 使用 Master Key 再认证 pending/current key envelopes，执行 operation-owned staging、hard-link sealing、manifest advance 和 descriptor generation commit。当前 active key envelope 被保留到 sealed reference，下一 key envelope进入新 active state。

## 固定与自动化证据

- V2 event AAD 与 segment canonical 固定向量；
- V3 active-key AAD 固定向量 `active-key-aad-v3.hex`；
- 两事件连续加密/解密 round-trip；
- 错误 Audit key 和错误 key context 失败；
- rotation prepare → manifest → staging → sealed → descriptor commit；
- sealed key 仍可验证旧 segment，新 active key 可构建下一 segment；
- pending key ciphertext 篡改在任何 staging 写入前停止。

这些测试使用真实 AEAD 与本机文件 API，但不是远端 CI、长时 fuzz、多进程、进程强杀或断电证据。
