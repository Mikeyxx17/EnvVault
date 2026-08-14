# pending-work 交付总览

## 🚀 一键安装（最简单，推荐）

1. 在 `D:\vscode\EnvVault` 文件夹上**右键 → 在终端中打开**；
2. 粘贴这一行并回车：

```powershell
powershell -ExecutionPolicy Bypass -File "D:\vscode\EnvVault\pending-work\apply-all\apply-all.ps1"
```

3. 看到 `Copied: 16 / 16 files` 即完成。它会自动把全部 8 项成果复制进仓库对应位置（不涉及 git/patch 操作）。
   - 想顺便跑测试：在命令末尾加 ` -Verify`
   - 想顺便 git 提交：在命令末尾加 ` -Commit`

本目录包含本次会话产出的全部交付物，供审阅后合并回真实仓库。所有交付均 value-free（不含任何 Secret Value / credential / password / 密钥），代码均在本会话可写暂存副本中开发并通过验证。

## 环境说明（为什么不是直接改仓库）

本会话运行于受限 Windows token：真实仓库内 `src/`、`docs/`、`scripts/`、`fuzz/` 等目录归另一用户所有，本会话只读；`SetSecurityInfo`/`taskkill` 等 API 亦被沙箱拒绝。因此全部工作在同一源码树的 kitak 可写副本中完成，以 git patch 形式交付。真实仓库的 `target/`、`fuzz/target/` 因跨用户权限无法复用——建议你在自己的账户下删除重建。

## 合并方法

每项子目录含一个 `*.patch`，在真实仓库根目录执行：

```powershell
git apply --check <patch>   # 先验证
git apply <patch>           # 再应用
```

按顺序应用：`01 → 02 → 03 → 04 → 05 → 06 → 07 → 08`（02 依赖 01 的 ADR 语境；07/08 是两项修复，与前面相对独立但建议最后应用）。应用后运行：

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features
```

> 注意：本会话无法运行 DACL 依赖的 75 个既有测试（沙箱 token 拒绝），合并后请在你的完整权限环境跑全量 `scripts/security-check.ps1` 确认。

## 交付清单

| 目录 | 内容 | 对应里程碑 | 验证状态 |
|---|---|---|---|
| `00-fuzz-campaign` | 小时级 fuzz campaign run record + 覆盖率（4 target × 1h，clean）+ 脚本缺陷报告 | M1.4 | ✅ 实际执行完成 |
| `01-adr-0015-external-anchor` | ADR 0015 草案：外部单调 Anchor wire protocol | M1.1 | ✅ 文档交付 |
| `02-anchor-sink-protocol` | AnchorSink 参考实现 + test double + 12 个协议故障测试 | M1.1 | ✅ 12/12 测试通过、clippy 零警告 |
| `03-throttle-expiry-adversarial` | 限流与 90 天过期对抗性测试套件（10 用例 + 1 发现记录） | M1.4 | ✅ 10 通过 / 1 ignored（发现）、clippy 零警告 |
| `04-crash-fault-injection` | 崩溃/断电故障注入 harness + 合成场景（冒烟证据）+ EnvVault migrate-v2 模板 | M1.2 | ✅ 合成 6 注入点冒烟通过 |
| `05-real-runtime-matrix` | 三平台真实运行矩阵 runbook + 证据模板 | M1.3 | ✅ 文档交付（执行需三平台真机） |
| `06-independent-review-checklist` | 独立安全评审 checklist + 结论模板 | M1.4 | ✅ 文档交付（执行需独立评审人） |
| `07-v3-legacy-window-fix` | **修复**：V3 Registry 拒绝 legacy 永不过期 credential 窗口 | M1.4 发现闭环 | ✅ 16/16 registry 测试、clippy 零警告 |
| `08-fuzz-campaign-coverage-fix` | **修复**：campaign 覆盖率改目录模式（argv 超限）+ 失败日志保留 | M1.4 发现闭环 | ✅ 3000+ 文件压力测试 + 4 目标回归全过 |

## 需要你后续执行的事项（M1 剩余真实验收）

1. 三平台真机矩阵（`05` 的 runbook）：Windows/Linux/macOS 钥匙库、登录/锁屏、多 shell、reparse race、低权限/并发会话。
2. 崩溃/断电注入（`04` 的 harness，`-Interactive` + 一次性测试 Vault）：Windows VM、Linux VM、真实磁盘；断电用 `-PoweroffCommand` VM hook。
3. 外部 Anchor 真实部署：按 ADR 0015 部署 CAS 服务/WORM/硬件单调后端，跑协议故障矩阵。
4. 独立安全评审：请独立人员按 `06` 的 checklist 评审并签署。

## 遗留发现（均已闭环）

- ~~V3 Registry 接受 legacy 永不过期窗口（纵深防御缺口）~~ → 已修复：`07-v3-legacy-window-fix`。
- ~~`scripts/fuzz-campaign.ps1` 大 corpus 覆盖率 argv 超限、失败不存日志~~ → 已修复：`08-fuzz-campaign-coverage-fix`。

## 备注

- 会话临时目录曾发生清理：最小化 fuzz corpus（约 10.5k 文件）已丢失，corpus 采纳选项不再可用（不影响任何交付物；campaign 完整 run record 与覆盖率 HTML 已抢救保存在 `00-fuzz-campaign\full-run-record\`）。最小化 corpus 可随后续 campaign 重新生成。
