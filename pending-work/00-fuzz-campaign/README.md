# Fuzz Campaign 总结（小时级，M1.4）

## 运行信息

- Run ID：`20260813-173217`（完整记录见 `run.md` / `run.json`）
- 时间：2026-08-13 17:32:17 UTC 起，总时长 14449s（≈4 小时）
- 工具链：rustc 1.99.0-nightly (2026-07-31)，cargo-fuzz 0.13.2，Windows + AddressSanitizer
- 参数：3600s/target × 4 target，max_len 32768，执行了 corpus 最小化（cmin）与覆盖率生成
- 执行位置：本会话对仓库只读（跨用户 ACL），故在可写暂存副本中执行同一脚本；脚本与参数与原仓库完全一致

## 结果

| Target | 状态 | Corpus 前 | Corpus 后（最小化） | 新增 crash | 行覆盖率（envvault crate） |
|---|---:|---:|---:|---|
| vault | clean | 1 | 2334 | 0 | 1.27% |
| identity_audit | clean | 10 | 5729 | 0 | 7.21%* |
| policy_profile | clean | 2 | 2044 | 0 | 1.99% |
| dotenv | clean | 1 | 436 | 0 | 1.87% |

- **Overall：clean** —— 0 crash、0 OOM、0 超时、0 新 artifact。
- 覆盖率报告文本见本目录 `*.txt`；HTML 报告与原始日志在暂存副本 `fuzz/runs/20260813-173217/` 下。

\* `identity_audit` 的覆盖率最初由脚本生成失败，原因已查明并补跑成功，见下。

## 发现的问题（脚本缺陷，非代码缺陷）

1. **`scripts/fuzz-campaign.ps1` 的 coverage 步骤对大体量 corpus 会失败**：
   `cargo fuzz coverage` 把每个 corpus 文件路径都放进子进程 argv；`identity_audit` 最小化后仍有 5729 个文件，超出 Windows 命令行长度限制，子进程以 `0xc0000135` 失败。
   补跑方案：直接以**目录模式**调用带 coverage 的二进制（`<bin> -runs=0 fuzz/corpus/<target>`，无 argv 膨胀），再用 `llvm-profdata merge` + `llvm-cov report` 生成报告（结果 `identity_audit.txt`，行覆盖 7.21%）。
   **建议**：把脚本 coverage 段改为目录模式或分批调用，避免大 corpus 再次触发该限制。
2. **脚本失败时丢弃覆盖率输出**：`identity_audit` 首次失败没有留下任何日志（只有成功路径才写 log）。**建议**：失败路径也保存 stderr，便于诊断。

## Corpus 处置说明

- campaign 按脚本设计对 `fuzz/corpus/<target>` 做了原位 cmin（种子被并入最小化结果）。
- 最小化后的 corpus（约 10.5k 个文件）保存在暂存副本 `%TEMP%\envvault-campaign-stage\fuzz\corpus\`，与真实仓库完全一致地受 `fuzz/.gitignore` 保护。
- **若决定采纳**：需人工审查后把 `fuzz/corpus/<target>` 的最小化结果复制回真实仓库并 `git add -f` 有意提交；不采纳则保持现有 `seed-*` 不变（本次未触碰真实仓库 corpus）。
- 任何 corpus 采纳都必须遵守 `fuzz/run-record-template.md` 的处置流程。

## 结论与后续

- 本次 campaign 达到 M1.4 要求的"小时级"运行：4 target × 1 小时无故障，可进入定时 campaign 与覆盖率趋势跟踪（CI 已有每日 scheduled 任务）。
- 自动化通过不构成生产安全声明；M1.4 剩余部分（限流/过期攻击实测、独立评审）另行推进。
