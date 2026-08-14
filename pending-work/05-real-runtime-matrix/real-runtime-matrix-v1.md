# Three-platform Real-runtime Matrix Runbook V1

状态：Runbook 草案，尚未执行。本文件把 M1.3 的真实运行验收拆成可勾选、可留证的检查项。全部自动化通过都不能替代本矩阵在 Windows、Linux、macOS 真实会话中的执行；证据按 [证据模板](./real-runtime-matrix-evidence-template-v1.md) 逐项留档。

## 执行前提

- 三平台各至少一台机器（Windows 11 建议 + Windows Server 亦可、Debian/Ubuntu LTS、macOS 当前支持版本）。
- Release 构建（`cargo build --release`）与对应平台的依赖齐全（keyring 后端、PowerShell 7、bash/zsh、Node.js、Python）。
- 所有测试 Vault 均为一次性创建，绝不含真实 Secret；结束后按平台删除 Credential Manager / Secret Service / Keychain 中的测试项。
- 每台机器记录：OS 版本、补丁级别、文件系统类型、是否域加入、权限级别。

## A. 平台钥匙库生命周期

| ID | 检查项 | 步骤 | 判定标准 |
|---|---|---|---|
| A1 | Windows Credential Manager 完整生命周期 | `keystore enable` → `status` → `session --machine-unlock whoami` → `keystore rotate` → `session` 再次 → `keystore disable` | 每步 value-free 成功；disable 后 credential 项消失；rotate 后旧项被替换且 unlock 仍可用 |
| A2 | Linux Secret Service 完整生命周期 | 同上，在登录会话 DBus 下执行 | 同上；记录 keyring daemon 版本与加密后端 |
| A3 | macOS Keychain 完整生命周期 | 同上 | 同上；记录 `security` 项归属与 ACL |
| A4 | 登录/注销/锁屏/解锁 | 各平台 enable 后：注销再登录、锁屏解锁、休眠唤醒 | 登录会话恢复后 machine unlock 可用；锁屏不解锁不可用（如平台如此设计）|
| A5 | OS 更新与重启 | 各平台 enable 后安装系统更新并重启 | 重启后 `keystore status` 与 `session whoami` 正常，无降级提示 |
| A6 | 低权限账户 | 以非管理员账户执行 A1 全部步骤 | 全部成功或明确拒绝且不泄露；记录与管理员账户的行为差异 |
| A7 | 并发会话 | 两个终端同时 machine unlock 同一 Vault | 两者均成功或明确串行化；不出现 credential 项损坏 |
| A8 | 卸载/清理 | disable 后检查平台存储 | 测试项被完整移除，无残留 credential、日志或侧车文件 |

## B. 终端与子进程

| ID | 检查项 | 步骤 | 判定标准 |
|---|---|---|---|
| B1 | PowerShell 7 / Windows PowerShell | `run --profile ... -- cmd /c set` 只读环境验证 | 只注入授权项，无 Vault 明文落盘；退出码透传 |
| B2 | cmd.exe | 同上 | 同上 |
| B3 | bash | Linux/macOS 下 `run -- env` | 同上 |
| B4 | zsh | macOS 下 `run -- env` | 同上 |
| B5 | Cargo 子进程 | `run --profile ... -- cargo run` 示例程序打印环境键名 | 键名集合精确等于 Profile ∩ Policy 授权 |
| B6 | Node.js 子进程 | `run -- node -e "console.log(Object.keys(process.env).sort())"` | 同上 |
| B7 | Python 子进程 | `run -- python -c "import os; print(sorted(os.environ))"` | 同上 |
| B8 | 环境继承 | run 内再起子进程并检查环境 | 授权项不扩散到无关后代（项目策略允许的继承除外）|
| B9 | 退出码与信号 | 目标程序 exit 7 / 被信号终止 | envvault 透传退出码/信号，不留锁文件 |

## C. 路径与文件系统对抗

| ID | 检查项 | 步骤 | 判定标准 |
|---|---|---|---|
| C1 | junction 拒绝（Windows） | Vault 路径任一层为 junction → 全部命令 | 明确拒绝（UnsafePath），不写入目标 |
| C2 | symlink 拒绝（Unix） | 同上，symlink | 同上 |
| C3 | reparse point race（Windows） | 创建 Vault 后把目录换成 junction 再操作 | 第二次操作拒绝；已打开句柄安全 |
| C4 | 跨卷移动 | Vault 与侧车文件跨卷（如 C:→D:、/tmp→/home）| 打开成功或明确拒绝；绝不半写 |
| C5 | 网络文件系统 | Vault 置于 SMB/NFS 共享 | 拒绝或显式风险提示；不允许静默降级保护 |
| C6 | 大小写/Unicode 路径 | 含中文/空格/emoji 的路径 | 全部命令正常或明确拒绝，无歧义解析 |

## D. 恶意同用户进程对抗（记录边界，不要求"防住"）

| ID | 检查项 | 步骤 | 判定标准 |
|---|---|---|---|
| D1 | 锁文件抢占 | 第二个进程并发打开同一 Vault | lost-update 被阻止，绝不覆盖 |
| D2 | 侧车文件替换 | 打开 Vault 后替换 descriptor/anchor/manifest 之一 | 完整性校验拒绝并进入 degraded/fail-closed |
| D3 | 目录删除 | 打开 Vault 后删除所在目录 | 后续写入失败关闭，不留半写文件 |

## E. 判定与留档

- 每个检查项判定：`pass` / `fail` / `blocked`（环境限制）。`blocked` 必须写明原因，且不得折算为 `pass`。
- 证据按模板留档：前置状态、执行日志、退出码、观察到的行为、判定与备注。
- 全部 `pass` 后由执行人签字，并附机器指纹（OS/版本/文件系统）；`fail` 项必须转 issue 并阻塞 M1.3 关闭。
- 本矩阵不覆盖：管理员/内核攻击、物理攻击、目标程序主动泄漏——这些属于 threat model 明确不保证的边界。
