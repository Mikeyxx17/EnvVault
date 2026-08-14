# Item 3: 认证限流与 90 天 Credential Expiry 对抗性测试套件（M1.4）

## 交付物

- `registry.rs`：在 `src/identity/registry.rs` 追加 `#[cfg(test)] mod adversarial`（10 个用例 + 1 个发现记录）
- `003-throttle-expiry-adversarial.patch`：可直接应用回真实仓库的 git patch

## 覆盖矩阵

| 攻击面 | 用例 | 结论 |
|---|---|---|
| 时钟回拨 | `clock_rollback_cannot_clear_the_bucket_block_window` | 回拨不能清除 bucket 封禁窗口（blocked_until 为绝对时间）|
| 时钟回拨 | `expiry_boundary_is_strict_and_clock_rollback_cannot_revive_it` | 回拨不能复活未签发/已过期 credential（issued ≤ now < expires 严格）|
| 时钟前跳 | `clock_forward_expires_the_credential_and_rotation_restores_access` | 前跳导致过期；轮换（replace_credential）恢复访问 |
| 窗口篡改 | `credential_windows_must_be_exactly_ninety_days` | insert 仅接受恰好 90 天窗口 |
| 全局可用性攻击 | `global_failure_limit_is_a_bounded_shared_fate_denial_of_service` | 50 次跨 bucket 失败封禁所有 caller（共享命运 DoS），窗口有界（60s）|
| 重启绕过 | `global_block_survives_restart_without_resetting_the_window` | encode/decode 后封禁持续，无法靠重启绕过 |
| 文件篡改 | `tampered_throttle_state_is_rejected_on_decode` | 未知字段 / failures 超限 / blocked_until 越界均拒绝 |
| 文件篡改 | `tampered_bucket_order_and_expiry_window_are_rejected` | bucket 顺序颠倒 / 过期窗口缩短 / KDF 版本篡改均拒绝 |
| 并发压力 | `concurrent_authentication_stress_preserves_state_invariants` | 8 线程 × 500 次竞争访问后状态仍可编码/解码且不变量成立 |
| 多进程模拟 | `state_carries_across_simulated_process_boundaries_without_loss` | 跨"进程"（encode/decode 快照）封禁状态不丢失 |

## 发现（已在用例中记录，未修复）

- **纵深防御缺口**：V3 Identity Registry 文档仍接受 legacy `(0, u64::MAX)` credential 窗口，被篡改的 caller 条目可携带"永不过期"credential 且通过解码（用例 `v3_documents_still_accept_the_legacy_immortal_credential_window`，标记 `#[ignore]`）。
- 实际利用前提：攻击者必须已能修改 Vault 内的 Identity payload（即已破坏 AEAD 完整性），因此是纵深防御问题而非直接可利用漏洞。
- 建议（供评审后决定）：V3 解码路径拒绝 legacy 窗口，仅 V2 遗留文档保留 grandfather 语义。

## 验证证据

- `cargo test --lib adversarial`：10 passed / 0 failed / 1 ignored（发现记录）
- `cargo clippy --lib`：零警告（本模块）
- 全量 lib：120 passed（+10）/ 75 failed（与本会话环境基线一致，均为沙箱 token 禁止 DACL API 的既有失败，非本项引入）

## 声明

自动化测试通过不构成生产安全验收；真实多进程（跨独立进程共享 Vault 事务）、时钟操纵的系统级实测仍需在完整权限环境由用户执行（见 M1.4 与第 4 项故障注入 harness）。
