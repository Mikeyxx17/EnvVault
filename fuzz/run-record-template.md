# EnvVault Fuzz Run Record

本文件是 fuzz campaign 的正式运行记录模板。`scripts/fuzz-campaign.ps1` 会在
`fuzz/runs/<timestamp>/run.md` 与 `run.json` 自动产出同构记录；本模板用于人工补全
自动记录无法覆盖的评审、处置与关闭信息。自动记录与人工评审都必须满足：不包含任何
Secret Value。

## 1. Run 身份

- Run：`<YYYYMMDD-HHmmss>`
- Started (UTC)：`<ISO-8601>`
- Duration：`<seconds>`
- Toolchain：`<rustc --version>`
- cargo-fuzz：`<cargo-fuzz --version>`
- Host：`<os / arch / ASan runtime（Windows）>`

## 2. 参数

- seconds_per_target：`<N>`
- max_len：`<N>`
- targets：`<vault, identity_audit, policy_profile, dotenv>`
- minimize：`<true|false>`
- coverage：`<true|false>`

## 3. 逐 Target 结果

| Target | Status | Corpus before | Corpus after | New artifacts | Coverage total | Log |
|---|---|---:|---:|---:|---|---|
| vault | clean | 1 | 1 | 0 | - | logs/vault.log |
| identity_audit | clean | 10 | 10 | 0 | - | logs/identity_audit.log |
| policy_profile | clean | 2 | 2 | 0 | - | logs/policy_profile.log |
| dotenv | clean | 1 | 1 | 0 | - | logs/dotenv.log |

- Status 取值：`clean`（无 crash/timeout/OOM）、`artifacts_found`、`run_failed`。
- `artifacts_found` 表示 libFuzzer 产出了 crash/timeout/OOM artifact，必须逐个复核。

## 4. 覆盖率趋势

- 本次报告：`coverage/<target>.txt` / `coverage/<target>-html/`
- 上一次记录：`<链接或 run id>`
- 行覆盖率变化：`<target>: x.xx% → y.yy%`

覆盖率只覆盖 `envvault` crate 源码，第三方依赖与标准库已被过滤。

## 5. 发现项

按 crash、OOM、超长输入、差分 parser 结果分别登记：

- [ ] `<target>` / `<类别>` / `<artifact 文件名>` / `<影响与初步判断>` / `<处置状态>`

## 6. Corpus 处置

- [ ] 已执行 `cargo fuzz cmin` 最小化；
- [ ] 已去重；
- [ ] 已审查新增 corpus 不含恶意内容；
- [ ] 已决定是否将最小化 corpus 提交到 `fuzz/corpus/<target>`。

运行时生成的 corpus 与 crash artifact 默认被 `fuzz/.gitignore` 忽略，只有经过审查的
`seed-*` 或明确决定保留的最小化 corpus 才进入提交。

## 7. 评审与关闭

- 评审人：`<name>`
- 结论：`<通过 / 需修复 / 仅记录>`
- 关联 issue：`<#issue>`
- 关闭时间 (UTC)：`<ISO-8601>`

> 任何自动化通过都不能代替真实操作系统、真实断电或独立安全评审。
