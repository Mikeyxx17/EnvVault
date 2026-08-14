# Item 2: AnchorSink 参考实现与协议故障测试（ADR 0015）

## 交付物

- `anchor_protocol.rs`：ADR 0015 参考实现（客户端 + 内存 test double），位于 `src/vault/anchor_protocol.rs`
- `002-anchor-protocol.patch`：可直接应用到真实仓库的 git patch（含 `src/vault/mod.rs` 的模块注册）

## 实现范围

- `AnchorTransport` 边界（HTTPS 实现在真实部署阶段提供）
- `ProtocolAnchorClient<Transport>`：实现现有 `AnchorSink` trait
  - 精确 expected-generation CAS、canonical bytes 校验、vault_id 绑定
  - 有界重试（默认 5 次，可注入 backoff）、CSPRNG request_id 幂等
  - last-confirmed `(generation, bytes)` 持久化接口 + 服务端回滚检测（generation 倒退 / 同代不同 bytes → fail-closed `AuditAnchorDegraded`）
  - 409 冲突验证返回链、不自动对账；404/422 立即失败关闭
- `TestDoubleServer`：CAS 状态机 + 去重账本 + 故障旋钮（503/429/响应损坏/强制回滚）

## 故障矩阵测试（12 个，全部通过）

| 故障 | 验证 |
|---|---|
| 响应丢失 | 同一 request_id 重试后仅应用一次 |
| 重复请求 | `already_applied`，generation 不前进 |
| 冲突（同代不同 bytes） | `Conflict` |
| 持续 503 | 预算耗尽 → `AuditAnchorDegraded` |
| 持续 429 | 预算耗尽 → fail-closed |
| 服务端回滚（generation 倒退） | load 检测 → degraded |
| 服务端回滚（同代不同 bytes） | load 检测 → degraded |
| 冲突响应中回滚 | degraded 而非 Conflict |
| 重启恢复 | 新客户端 load 恢复链并继续 gen+1 |
| generation 跳变/prev digest 错误/跨 vault | 服务端 422 |
| 非 canonical anchor | 客户端发送前拒绝 |
| 200 响应损坏 | 客户端 fail-closed |

## 验证证据

- `cargo test --lib anchor_protocol`：12 passed / 0 failed
- `cargo clippy --lib`：零警告（新模块）
- 全量 lib 测试：110 passed（+12）/ 75 failed（与本会话环境基线一致，均为沙箱 token 禁止 DACL API 导致的既有失败，非本项引入）

## 声明

未部署原型，不发布任何生产声明；真实 TLS 传输、令牌存储与真实服务验收不在本项范围（见 ADR 0015 复审条件）。
