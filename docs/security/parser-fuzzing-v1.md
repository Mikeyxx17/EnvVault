# Parser Fuzzing and Security Properties V1

状态：四个 libFuzzer target 已构建；2026-08-13 在 Windows x64 ASan 下完成两轮每 target 60 秒 campaign，四项均正常退出且未产生 crash artifact；第二轮包含 Identity Registry V3 credential-expiry seed。定时 CI 已配置为每个 target 运行五分钟，但远端尚未实际执行，因此仍不是长期 fuzz 验收。

## Targets

| Target | 入口 |
|---|---|
| `vault` | Vault V1 严格 JSON、Base64、资源限制与 envelope 结构 |
| `identity_audit` | Identity Registry、认证 Audit Event、Audit V2 segment、anchor、recovery manifest 与 Vault descriptor |
| `policy_profile` | Policy Document 与 value-free Profile |
| `dotenv` | 严格 UTF-8、引用、escape、key 和资源限制 |

执行：

```powershell
cargo +nightly fuzz build
.\scripts\fuzz-smoke.ps1 -SecondsPerTarget 15
```

主工程仍使用 stable。Windows runner 会把 Visual Studio 的 `clang_rt.asan_dynamic-x86_64.dll` 目录加入该进程 `PATH`。仅提交经过评审的 `seed-*` 初始语料；运行时生成的 corpus 和 crash artifact 不进入普通源码提交。

本机脚本和定时 CI 显式使用 `-max_len=32768`，使 Identity Registry V2 的合法稀疏限流状态和多 Caller 文档能进入深层语义解析，同时继续由各 parser 自身的更高资源上限负责拒绝超大输入。

每个 multiplex target 会先消费一个 selector byte，再把剩余字节交给目标 parser；提交的合法 seed 因此能进入语义校验深层，而不是永远停在首字节 JSON 失败。`identity_audit` 当前使用 selector 低三位的 0～5，覆盖 Identity、Audit Event、Audit V2 segment/anchor、Recovery Manifest V2 和 Vault Descriptor V3，并保留旧版本拒绝 seed 与当前 canonical seed。

Phase 7P/7Q 新增紧凑 Identity Registry V2/V3 seed；V2 曾以 `-runs=1 -max_len=32768` 精确执行，V3 已进入第二轮 `identity_audit` 60 秒 campaign。固定输入执行只证明它能够进入 parser，不等同于一次 fuzz campaign。

## Properties and negative tests

- 任意 128-bit CallerId/SecretId 的 canonical display/parse round-trip；
- 一个 Allow rule 不能授权另一 Caller、Secret 或 Operation；
- Profile 顺序规范化、encode/decode 幂等且不出现 Value 字段；
- 实际 Secret sentinel 不进入 Audit encode/Debug 或 Broker error；
- 畸形 dotenv 的错误不回显原始 Value。

每项 property 当前执行 512 cases。Fuzz smoke、property tests 和普通回归是不同证据，不能互相替代。

## 尚未完成

- 小时级/持续 CI fuzz campaign 与覆盖率趋势；
- corpus 审核、最小化和跨平台复用；
- 本机生成 corpus 保留为忽略的工作数据，提交前仍需最小化、去重和恶意内容审查；
- OOM/超长输入、故障注入和差分 parser 测试；
- 独立 parser、安全边界与供应链评审；自动依赖审计不能替代这些评审。
