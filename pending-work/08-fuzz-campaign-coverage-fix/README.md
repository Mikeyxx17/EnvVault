# Fix: fuzz-campaign.ps1 覆盖率生成修复（argv 超限 + 失败日志）

## 背景（第 0 项记录的脚本缺陷）

1. `cargo fuzz coverage` 把每个 corpus 文件路径展开为子进程 argv 条目；大 corpus（如 identity_audit 最小化后 5729 个文件）超出 Windows 命令行限制，运行以 `0xc0000135` 失败。
2. 失败路径不保留任何输出日志（只有成功才写 log），无法诊断。

## 修复内容（`scripts/fuzz-campaign.ps1`）

- **构建与运行分离**：`cargo fuzz coverage` 改为仅用**单种子迷你语料目录**做构建（其自带运行结果不再使用），真正的覆盖率采集改为**目录模式**：直接调用 coverage 二进制 `-runs=0 <corpus 目录>`（libFuzzer 接受目录参数，无 argv 膨胀），配合 `LLVM_PROFILE_FILE` + `llvm-profdata merge` + `llvm-cov report/show`，与原来报告输出路径完全兼容。
- **失败日志**：覆盖段所有步骤的输出累积写入 `logs/<target>.coverage.log`；任何失败在 catch 中把累积输出 + 错误信息一并落盘。
- 顺带把 `llvm-profdata` 的查找与 `llvm-cov` 统一为一次 sysroot 扫描。

## 验证

- **大 corpus 压力**：dotenv 语料膨胀到 3000+ 文件，完整跑 `fuzz-campaign.ps1`（含覆盖率）：`Overall: clean`，覆盖率 TOTAL 行正常产出（此前同规模会 argv 爆炸失败）。
- **全 4 目标回归**：15s/target 冒烟全部 `clean`，四个覆盖率报告全部产出（含此前失败的 identity_audit：6.42% 行覆盖）。
- 覆盖率日志现在完整记录各步骤输出。

## 应用

```powershell
git apply --check 008-fuzz-campaign-coverage-fix.patch
git apply 008-fuzz-campaign-coverage-fix.patch
```
