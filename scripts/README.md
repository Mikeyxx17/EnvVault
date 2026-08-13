# Development Scripts

本目录用于可审查、可重复的开发辅助脚本。任何脚本都不得输出、收集或提交 Secret Value。

- `fuzz-smoke.ps1`：定位 Windows x64 ASan runtime并短时运行四个 fuzz target。
- `fuzz-campaign.ps1`：按给定时长运行 fuzz target，最小化持久 corpus，可选生成覆盖率，并产出 value-free 的 JSON/Markdown 运行记录到 `fuzz/runs/<timestamp>/`。
- `security-check.ps1`：依次执行 RustSec、cargo-deny、严格 Clippy 和 locked tests；`-Release` 增加 Release tests，`-IncludeWindowsCredentialStore` 在真实登录会话创建并清理临时 Windows Credential Manager 条目，`-IncludeFuzz` 追加指定时长 fuzz。
