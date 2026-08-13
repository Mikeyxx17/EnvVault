# Contributing

## 开发原则

1. 先更新或确认架构与威胁模型，再实现安全敏感功能。
2. 模块之间通过明确类型和接口协作，禁止绕过 Broker 直接向应用发放 Secret。
3. 新增操作时必须同时定义授权语义、默认拒绝行为和审计语义。
4. 测试数据只能使用明确的假凭证，不能提交真实 Secret。

## 本地检查

```powershell
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

这些检查只能证明对应的格式、编译、静态检查和自动化测试层，不代表生产安全性或真实环境验收完成。
