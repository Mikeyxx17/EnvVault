# Development Scripts

本目录用于可审查、可重复的开发辅助脚本。任何脚本都不得输出、收集或提交 Secret Value。

## 卸载

- `uninstall.sh`：删除 `~/.local/bin/envvault`。可选 `--purge-project <dir>` 删除该项目的 `.envvault/` 和 `envvault.json`（需在终端输入 `uninstall` / `purge`）。不删除源码仓库，也不安全擦盘。
- CLI 等价命令：`envvault uninstall` 与 `envvault uninstall --purge-project`。

## 安全门禁

- `security-check.ps1`：依次执行 RustSec、cargo-deny、严格 Clippy 和 locked tests；`-Release` 增加 Release tests，`-IncludeWindowsCredentialStore` 在真实登录会话创建并清理临时 Windows Credential Manager 条目，`-IncludeFuzz` 追加指定时长 fuzz。

## Fuzz

- `fuzz-smoke.ps1`：定位 Windows x64 ASan runtime 并短时运行四个 fuzz target。
- `fuzz-campaign.ps1`：按给定时长运行 fuzz target，最小化持久 corpus，可选生成覆盖率，并产出 value-free 的 JSON/Markdown 运行记录到 `fuzz/runs/<timestamp>/`。
- `fuzz-campaign.sh`：`fuzz-campaign.ps1` 的 Linux/macOS 移植。需要 nightly 工具链和 `cargo-fuzz` 在 PATH 上（运行前确保 `cargo +nightly fuzz build` 可用，或设置 `RUSTUP_TOOLCHAIN=nightly`）。

## 崩溃 / 断电故障注入

- `fault-injection.ps1`：Windows 故障注入 harness（`taskkill /T /F` 击杀进程树），把 `docs/security/audit-rotation-fault-matrix.md` 的注入点变成可复现的"运行 → 精确击杀 → 重启验证 → 留证"流程。
- `fault-injection.sh`：`fault-injection.ps1` 的 Linux/macOS 移植，使用 `setsid` + `kill -9` 击杀进程组。产出与 Windows 版同构的 `envvault-fault-injection-run-v1` 记录到 `fault-injection-runs/<timestamp>/`。
- `fault-injection-scenarios/synthetic/`：合成冒烟场景（无凭证、无 TTY），用于验证 harness 本身；`.ps1` 与 `.sh` 同构，覆盖六个注入点。
- `fault-injection-scenarios/envvault-migrate-v2/`：真实 EnvVault `audit migrate-v2` 场景模板（`.ps1` 与 `.sh`）。必须用 harness 的 `--interactive` 运行以通过 Master Password TTY 提示，且必须使用一次性测试 Vault（绝不能用保存真实 Secret 的 Vault）。

运行合成冒烟（Linux/macOS）：

```bash
bash scripts/fault-injection.sh \
  --scenario scripts/fault-injection-scenarios/synthetic/scenario.sh \
  --recovery scripts/fault-injection-scenarios/synthetic/recovery.sh \
  --work-root /tmp/envvault-fault-work \
  --inject-at before-manifest,manifest-written,segment-half,segment-written,vault-committed,anchor-confirmed
```

运行真实 EnvVault migrate-v2（需要在有 TTY 的 Linux VM/真机，且先交互式创建一次性 Vault）：

```bash
export FAULT_VAULT_PATH=/path/to/test.vault
export FAULT_VAULT_DIR=/path/to
bash scripts/fault-injection.sh --interactive \
  --scenario scripts/fault-injection-scenarios/envvault-migrate-v2/scenario.sh \
  --recovery scripts/fault-injection-scenarios/envvault-migrate-v2/recovery.sh \
  --work-root /path/to/work \
  --inject-at prepared-manifest,sealed-segment,vault-committed,anchor-confirmed
```

自动化通过不构成任何断电安全声明；每个注入点仍须在 Windows VM、Linux VM 与至少一种真实磁盘上跑一遍并留档（前置状态、终止方式、磁盘状态、恢复结果）。
