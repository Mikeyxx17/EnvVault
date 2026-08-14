# Fix: V3 Registry 拒绝 legacy 永不过期 credential 窗口

## 背景

第 3 项对抗性测试记录的纵深防御缺口：V3 Identity Registry 文档曾接受 legacy `(0, u64::MAX)` credential 窗口，被篡改的 caller 条目可携带"永不过期"credential 且通过解码（实际利用需先破坏 Vault AEAD 完整性）。

## 修复内容（`src/identity/registry.rs`）

- `decode_fields` 新增 `legacy_windows_allowed` 参数：V1/V2 解码路径传 `true`（保留 V2 grandfather 语义），V3 路径传 `false`。
- V3 解码遇到 `issued == 0` 或 `expires == u64::MAX` 的条目直接拒绝。
- 原 `#[ignore]` 发现用例转为正式回归测试 `v3_documents_reject_the_legacy_immortal_credential_window`（断言解码失败）。
- V2 grandfather 语义不变（现有 `v2_credentials_are_grandfathered_until_rotation_and_v3_windows_are_strict` 测试仍通过）。

## 验证

- `cargo test --lib registry`：16/16 通过（含新回归测试与 V2 grandfather 测试）
- `cargo clippy --lib`：零警告
- 全量 lib：121 passed / 75 failed / 1 ignored —— 与修复前基线（120/75/2）相比新增 1 个正式测试通过、1 个发现记录转为测试；75 个失败与本会话环境基线完全一致（沙箱 token 拒绝 DACL API 的既有失败，非本修复引入）

## 应用

```powershell
git apply --check 007-v3-legacy-window-fix.patch
git apply 007-v3-legacy-window-fix.patch
```

> 应用后请在你的完整权限环境跑一次 `cargo test --workspace --all-features` 确认 75 个环境性失败在真实环境全部恢复为通过。
