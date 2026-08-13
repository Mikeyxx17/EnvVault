# Audit Rotation Recovery Manifest V2

状态：严格 canonical schema、私有原子 store、单向状态机、下一 active-key envelope、Master Key 认证恢复、本地 anchor CAS 和 Broker/CLI 启动恢复已实现；远程/硬件 anchor 和断电级 durability 尚未实现。

## Schema 与版本边界

Manifest 固定为 `<vault>.audit-rotation-recovery.json`，format/version 为 `envvault-audit-rotation-recovery`/`2`。V2 保留 V1 的 operation id、expected/committed Vault generation、segment identity、sequence 区间、terminal authenticator、canonical SHA-256、精确 staging/sealed 文件名和 anchor generations，并新增：

```text
next_active_key_envelope:
  algorithm = xchacha20poly1305
  nonce = 24-byte Base64
  ciphertext = 32-byte key + 16-byte tag
```

Envelope 明文是随机 32-byte Audit key。它以 Master Key 加密，AAD 精确绑定下一 active segment 的 vault id、segment id、start sequence 和 predecessor authenticator。Manifest 不含明文 key；错误日志和 Debug 只显示 envelope 长度，不显示 nonce/ciphertext。

磁盘 Store 只接受重新 canonical serialize 后逐字节相同的文档。未知字段、V1/future version、未知算法、错误长度、generation/sequence overflow、错误文件名和非 canonical 磁盘 bytes 全部失败关闭。固定向量为 `tests/fixtures/audit_v2/rotation-recovery-v2.json`。

## 状态与恢复

唯一合法状态序列仍是：

```text
prepared → sealed-file-synced → vault-committed → anchor-confirmed
```

轮换准备在 Vault 协作锁内完成：验证 Descriptor V3、解封当前 active key、认证解密完整 segment、生成新 key、创建下一 key envelope，然后以私有 `create_new` 写入 V2 manifest。已有 manifest 不被覆盖。

恢复协调器在同一 Vault 锁内收集 manifest、staging/sealed segment 和 descriptor evidence。正式 `step` 必须接收已解锁 Master Key，并在任何 staging 写入或 descriptor commit 前认证：

- descriptor 当前 active/sealed key envelope 的 immutable context；
- manifest 中下一 active key envelope 的下一 segment context；
- actual segment predecessor、terminal、digest 与 descriptor/manifest 的交叉一致性。

篡改但长度合法的待提交 key ciphertext 会在创建 staging 前失败。Descriptor 已提交而 manifest 未前进时，exact reference、generation 和 next-key envelope 相同才允许幂等推进。

## 未完成边界

- 远程/硬件 mandatory/optional anchor sink；当前本地镜像只验证 CAS 协议；
- 父目录 handle flush、进程强杀、VM/真实磁盘断电；
- 多进程压力与恶意同账户 race；
- 外部备份、retention 和恢复演练。

因此 V2 manifest 是内部轮换恢复原语，不是完整生产轮换入口或回滚保护证明。
