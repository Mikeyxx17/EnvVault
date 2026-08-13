# ADR 0012: Isolated Parser Fuzzing and Security Properties

状态：Accepted，2026-08-13。

## 背景

Vault、Identity Registry、Policy、Profile、Audit Event 与 dotenv 都处理不可信字节。示例单元测试不能系统探索畸形 JSON、边界长度、Unicode、重复字段和组合状态，也不能持续证明精确授权与 value-free 输出不变量。

## 决策

- `fuzz/` 作为独立 `cargo-fuzz` package，不加入普通 workspace，也不改变主 crate 的 stable Rust 1.97 基线。
- 主 crate 只有启用非默认 `fuzzing` feature 时才公开 parser-only harness；入口丢弃内部结果，不公开 Vault/Identity 内部持久化类型。
- 四个 target 分别覆盖 Vault、Identity/Audit、Policy/Profile 和 dotenv。
- Windows smoke runner 显式定位 Visual Studio x64 AddressSanitizer runtime；找不到时失败，不静默降级为无 sanitizer 执行。
- 普通测试使用 `proptest` 验证 identifier canonical round-trip、精确 tuple 不扩权、Profile 确定编码/value-free 等不变量。
- Audit、dotenv error 和 Broker error 使用唯一 sentinel 做负向泄漏测试。

## 影响

短时 smoke fuzz 只证明 harness 可执行且在该时间窗口没有发现 crash；不代表覆盖率收敛或 parser 已通过长期 fuzzing。CI 后续应运行稳定时长并保存 corpus/artifact。独立安全评审仍然必要。
