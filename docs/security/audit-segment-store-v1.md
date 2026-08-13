# Audit V2 Segment Store V1

状态：canonical segment SHA-256、私有 staging、不可覆盖封存、磁盘证据收集、Descriptor V3 authenticated 本地轮换协调和 Broker/CLI 自动轮换入口已实现；真实断电与目录 durability 仍未验收。

## 职责边界

`SegmentStore` 位于 `vault`，只处理已经由 Audit V2 parser 验证的密文 segment bytes。SHA-256 实现在 `crypto` 的窄接口内，Store 不直接依赖具体 hash crate。它不能构造 `AuditEvent`、决定授权、解密事件或修改 Vault descriptor。

Store 从 Vault 路径推导相邻父目录，并使用 manifest 中经过重算验证的精确 leaf names：

- operation-owned staging：`.envvault-audit-<operation-id>.segment.tmp`；
- final sealed segment：`envvault-audit-segment-<20-digit-id>.json`。

父目录在规范化前先经过 symlink/reparse-point 检查；每次打开和删除仍复用 `secure_fs` 的私有文件、no-follow 和路径约束。

## Digest 与匹配

Digest 是 canonical compact segment bytes 的 SHA-256。`SegmentStore` 只有在以下条件全部成立时才返回 `MatchesDigest`：

1. 文件是私有普通文件，且不超过 32 MiB；
2. Audit V2 严格 parser 接受；
3. 重新序列化后的 canonical bytes 与磁盘 bytes 完全相等；
4. vault id、segment id、起止 sequence 和 terminal authenticator 与 manifest 一致；
5. SHA-256 与 manifest 的 32-byte digest 一致。

因此只有 digest 相同但 segment identity 不同仍会失败。空文件单独返回 `Empty`；超限、非 canonical、损坏、语义不匹配或 digest 不匹配返回 `Mismatch`；不安全路径返回错误而不是伪装为普通 mismatch。

固定 `segment-v2.json` canonical bytes 的 SHA-256 为：

```text
c4f16e203930891a55fb3ec328a334893041ca5d189a010aad81d543e92e939e
```

同时使用标准 SHA-256 `abc` 向量验证 hash wrapper。

## Staging 与封存

重建 staging 前必须确认 final sealed file 不存在。缺失 staging 使用私有 `create_new`；空或不匹配 staging 只能删除这一条由 manifest operation id 精确拥有的路径，然后重新 `create_new`、写入、`sync_all` 并复核。匹配 staging 幂等返回。

封存不使用可能覆盖目标的普通 rename：

1. staging 必须已同步且完全匹配；
2. final 必须不存在；若 final 已匹配则视为先前封存成功，若为空/不匹配则失败关闭；
3. 同目录创建 staging→final hard link。目标已存在时 hard-link API 失败，不会覆盖；
4. 重新打开 final，复核私有权限、canonical bytes、identity 和 digest；
5. 复核成功后只删除 operation-owned staging link。

该协议要求支持同卷 hard link 的文件系统；不支持时失败，不回退为可覆盖 rename 或 copy-overwrite。Final 一旦出现就不会由 SegmentStore 删除或替换。

## Deterministic file tests

本机自动化实际覆盖：

- staging/final 都缺失；
- staging 私有空文件；
- staging 半写导致 mismatch；
- operation-owned staging 删除并完整重建；
- hard-link 封存、复核和重复调用幂等；
- prepared manifest 遇到已封存 final 时前进到 `sealed-file-synced`；
- 预先存在的不匹配 final 不被覆盖；
- 已封存 final 被篡改后，committed recovery 停止；
- digest 正确但 segment id 不匹配时拒绝写 staging。

这些是同进程、真实文件 API 的 deterministic tests，不是强制终止或断电测试。

## 未完成边界

- Broker/CLI 事件追加、阈值判断与自动轮换；
- sidecar 与主 Secret/Policy/Identity Vault state 的统一 V2 提交；
- hard-link/删除后的父目录 durability flush；
- 不支持 hard link 的安全替代协议；
- 多进程 race、磁盘写错误、进程强杀和 VM/真实设备断电；
- 外部 anchor CAS 与 mandatory degraded gating。

完成这些项目以前，sealed segment 文件能力不能等同于完整 Audit rotation 或回滚保护。
