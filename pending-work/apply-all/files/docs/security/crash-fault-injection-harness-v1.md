# Crash / Power-loss Fault-injection Harness V1

状态：Harness 与合成场景已实现并在本会话冒烟验证（6 个注入点全部通过）；真实 EnvVault 场景模板已就绪。真实 Vault 的强制终止与断电验证必须在 Windows VM、Linux VM 和真实磁盘的完整权限环境执行——本 harness 只提供可复现的执行与留证框架，不构成任何断电安全声明。

## 定位

`scripts/fault-injection.ps1` 是 M1.2 的工程前置件：把 `docs/security/audit-rotation-fault-matrix.md` 中的每个注入点变成可复现的"运行 → 精确击杀 → 重启验证 → 留证"流程。

```text
fault-injection.ps1
  ├── scenario.ps1（操作 + checkpoint 观察者，子进程）
  │      ├─ 写 checkpoint 标记（注入窗口开始）
  │      └─ 执行操作（EnvVault 命令或合成目标）
  ├── 击杀：taskkill /T /F（Windows 进程树）或 VM poweroff hook
  └── recovery.ps1（重启验证器，独立子进程）
         └─ 输出 value-free JSON verdict + exit 0/2/3
```

## Verdict 语义

| Verdict | Exit | 含义 |
|---|---|---|
| `recovered` | 0 | 重启后状态一致、链可验证 |
| `fail_closed` | 2 | 无可用的损坏状态，失败关闭（可接受）|
| `data_loss` | 3 | 不变量被破坏（例如已发放 Secret 对应 Audit 丢失）——必须调查 |
| `error` | 其他 | 无法分类——必须调查 |

## 使用

合成冒烟（无 TTY、无凭证）：

```powershell
pwsh scripts\fault-injection.ps1 `
  -ScenarioScript scripts\fault-injection-scenarios\synthetic\scenario.ps1 `
  -RecoveryScript scripts\fault-injection-scenarios\synthetic\recovery.ps1 `
  -WorkRoot <临时目录> `
  -InjectAt before-manifest,manifest-written,segment-half,segment-written,vault-committed,anchor-confirmed
```

真实 EnvVault（需要交互式 Master Password，务必使用一次性测试 Vault）：

```powershell
$env:FAULT_VAULT_PATH = 'D:\fault-test\test.vault'
$env:FAULT_VAULT_DIR  = 'D:\fault-test'
pwsh scripts\fault-injection.ps1 -Interactive `
  -ScenarioScript scripts\fault-injection-scenarios\envvault-migrate-v2\scenario.ps1 `
  -RecoveryScript scripts\fault-injection-scenarios\envvault-migrate-v2\recovery.ps1 `
  -WorkRoot D:\fault-test\work `
  -InjectAt prepared-manifest,sealed-segment,vault-committed,anchor-confirmed
```

断电模式（VM poweroff hook，本机收集随即停止，重启后手动运行 recovery 脚本补录）：

```powershell
pwsh scripts\fault-injection.ps1 ... -PoweroffCommand 'VBoxManage controlvm envvault-test poweroff'
```

## 注入点与故障矩阵对应

| 注入点（合成） | 注入点（EnvVault 模板） | 矩阵条目 |
|---|---|---|
| before-manifest | prepared-manifest 出现 | 建 manifest 前 / prepared 落盘后 |
| manifest-written | —（manifest 已存在） | prepared 后、segment 前 |
| segment-half | sealed-segment 出现 | segment 写一半 |
| segment-written | — | segment 已写、sync 前 |
| vault-committed | Vault 内容变化 | Vault commit 前后 |
| anchor-confirmed | anchor sidecar 更新 | anchor CAS 前后 / confirmed 清理 |

EnvVault 模板的 checkpoint 由 sidecar 文件名/内容观察驱动（`<vault>.audit-rotation-recovery.json`、新出现的 segment 文件、Vault 长度变化、`<vault>.audit-anchor-v2.json`），不读取任何 Secret Value。

## 边界与必须补做的验收

- harness 的击杀是 `taskkill /T /F`，不等于断电；断电必须用 VM poweroff/真实拔电执行。
- 目录级 durability（rename 后目录 fsync）只能通过真实断电观察。
- 每个注入点还必须在 Windows VM、Linux VM 与至少一种真实磁盘各跑一遍，并留档：前置状态、终止方式、磁盘状态、恢复结果。
- 自动化通过不构成生产安全声明。
