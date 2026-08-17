# Audit V2 Canonical Format

状态：严格 segment/anchor/Manifest V2/Descriptor V3 parser、canonical serializer、固定测试向量/AAD、V2 event builder、canonical SHA-256、私有 SegmentStore 和 authenticated 本地恢复已实现；Phase 7J 已将新 Vault、Broker 和 CLI 接入该路径，历史 V1 Vault 只允许显式迁移。

## 边界

Audit V2 线格式属于 `vault`，因为它包含加密 envelope。`audit` 模块继续只拥有不含 Secret Value 的 `AuditEvent`。Broker 仍必须先持久化本地 Audit，再读取获准 Secret；本格式不能成为绕过 Broker 的公开存储 API。

V2 当前定义三种 UTF-8 JSON record：

- `envvault-audit-segment`：不可覆盖的 sealed segment；
- `envvault-audit-anchor`：提交给单调 compare-and-set sink 的公开完整性记录。
- `envvault-vault-descriptor` version 3：绑定 generation、sealed segment 引用、active 连续性及 Master-Key-encrypted segment key envelopes 的私有 Vault sidecar。

Canonical bytes 使用紧凑 JSON、固定字段顺序、无 BOM、无尾随空白，字符串不作 Unicode 规范化。整数只能是 JSON 的无符号十进制整数。所有二进制字段使用带 padding 的 RFC 4648 standard Base64。Parser 拒绝未知字段、未知版本、错误长度和资源上限；接收到的 JSON 可以有非 canonical 空白，但参与 digest、签名或 CAS 的字节必须先由 serializer 重建。

## Sealed segment schema

字段按 canonical 顺序排列：

| 字段 | 约束 |
|---|---|
| `format` | 固定 `envvault-audit-segment` |
| `version` | 固定 `2` |
| `vault_id` | 16 bytes Base64 |
| `segment_id` | 从 1 开始，单调增加 |
| `start_sequence` / `end_sequence` | 非零、闭区间、事件数必须等于区间长度 |
| `created_unix_time_millis` | 创建时 wall-clock metadata；不承担单调性证明 |
| `previous_segment_authenticator` | 第一段为 16 个零字节；后续绑定前一段 terminal authenticator |
| `terminal_authenticator` | 必须等于最后一个 event envelope 的 16-byte AEAD tag |
| `aead.algorithm` | 固定 `xchacha20poly1305` |
| `events` | 1～4096 个连续事件；每个含 sequence、24-byte nonce、16～4112-byte ciphertext |

完整 segment 最大 32 MiB。该宽松文件上限用于拒绝资源消耗，不代表轮换阈值；实现应在接近 4096 事件或更低的配置字节阈值时轮换。

Event AAD 的 exact byte layout 为：

```text
"envvault:audit-event:v2\0"
|| u32_be(2)
|| vault_id[16]
|| u64_be(segment_id)
|| u64_be(sequence)
|| previous_authenticator[16]
```

历史 sealed-context `segment_key_aad` 向量绑定 domain、version、vault id、segment id、起止 sequence、创建时间、前段和 terminal authenticator。Phase 7H 的实际 active key envelope 使用 V3 immutable AAD，只绑定 vault id、segment id、start sequence 和 predecessor，允许同一 active key 随事件追加而不反复重包；轮换后该 envelope 移入 sealed reference。

## Anchor schema

字段按 canonical 顺序排列：`format`、`version`、`vault_id`、`anchor_generation`、`segment_id`、`sequence`、`terminal_authenticator`、`digest_algorithm`、`previous_anchor_digest`、`created_unix_time_millis`。

- format/version 固定为 `envvault-audit-anchor`/`2`；
- generation、segment id、sequence 均非零；
- digest algorithm 固定 `sha256`；
- terminal authenticator 为 16 bytes；previous anchor digest 为 32 bytes；
- generation 1 使用全零 predecessor；后续 generation 必须引用前一 canonical anchor bytes 的 SHA-256，不能使用全零占位；
- record 最大 4 KiB，不能包含 Secret Value、credential、password、key 或密文 event。

本地同盘 anchor 只能检测误损坏。只有具备服务端单调 CAS、append-only/WORM 或可信平台单调状态的 sink 才提供回滚防护。

## 固定向量

- `segment-v2.json`：单事件 sealed segment canonical bytes；
- `anchor-v2.json`：非 genesis anchor canonical bytes；
- `event-aad-v2.hex`：event AAD exact bytes；
- `segment-key-aad-v2.hex`：segment key AAD exact bytes。
- `vault-descriptor-v2.json`：不含 key envelope 的历史 descriptor；
- `vault-descriptor-v3.json`：含 active key envelope 的当前 descriptor canonical bytes；
- `rotation-recovery-v2.json`：含下一 active key envelope 的当前 recovery manifest；
- `active-key-aad-v3.hex`：实际 active key AAD exact bytes。

向量使用公开重复字节，不含真实 Secret，也不是有效生产密钥材料。修改格式字段顺序、domain、整数端序或 Base64 约定必须新增版本，不能静默更新 V2 向量。

## V1 → V2 迁移边界

迁移必须显式执行，不能在普通 `open` 时静默发生：

1. 在 V1 文件锁内完成密码验证和全部 Audit event 认证/解码；任何损坏立即停止。
2. 创建私有迁移标记，绑定 vault id、事件数和 length-prefixed canonical event bytes 的 SHA-256；V1 原文件保持不变。
3. 以原 sequence 1 开始重新加密到 V2 segment；迁移事件使用新的随机 segment key，不复用 V1 Audit key。
4. 中断重试先验证源摘要和已复制 V2 前缀，只继续缺失事件；每个 segment、descriptor、anchor 和事件数量均需认证验证。
5. 全量逐项相同后删除迁移标记并切换；主 Vault 内 V1 链保留为冻结历史副本，后续不再双写。

自动降级 V2→V1 被禁止。Phase 7E～7J 已实现 recovery manifest、segment store、Descriptor V3 key lifecycle、authenticated 本地轮换、Broker/CLI 接入、本地 anchor CAS、degraded 原语和显式迁移；loopback 明文参考 CAS 与 last-confirmed 持久化已接入。真正远程/硬件单调 sink 与断电级一致性测试仍未完成。
