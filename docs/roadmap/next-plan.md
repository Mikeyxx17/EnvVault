# EnvVault 后续计划

状态：Active
起点：Phase 7A～7Q 的工程实现与本机自动化验证已经完成。本文是唯一有效的后续计划，不重复记录已经完成的旧阶段。

## 目标

后续工作分成两条严格分离的路线：

1. 先取得可以支撑真实 Secret 使用声明的生产安全证据。
2. 在安全门禁通过后，构建 AI-aware Capability Broker，尽量避免把通用明文 Secret 直接交给不可信 Agent。

任何自动化通过都不能代替真实操作系统、真实断电或独立安全评审。

## 里程碑 1：生产安全验收

这是进入新功能开发前的硬门禁。

### 1.1 外部单调 Audit Anchor

工程前置件已落地：loopback 参考 CAS（默认 rustls，明文仅显式测试开关）、HTTP 客户端、持久化 last-confirmed、mandatory CLI 接入、按 Vault 绑定 token、value-free 访问审计、回滚证据 sidecar，以及针对真实 HTTP/HTTPS 服务的跨 Vault / 回滚 / 访问日志自动化测试。仍缺：

- 部署独立于本机回环域的 CAS 服务、WORM 存储或硬件单调状态。
- 在真实 HTTPS 或硬件路径上验证 generation、sequence、predecessor digest 和 canonical bytes。
- 覆盖响应丢失、重复请求、冲突、服务不可用、服务端回滚和恢复的部署级记录。
- mandatory 模式在真实部署异常时必须保持 degraded/fail-closed，不能继续发放 Secret。

完成证据：部署配置、协议测试、故障记录和恢复记录全部可复现。当前参考服务不能计入该项完成。

### 1.2 崩溃与断电耐久性

工程前置件已落地：合成轮换场景、远程锚点文件场景、真实 Vault 轮换进程击杀（feature `fault-injection`）、Unix 父目录 fsync，以及损坏 CAS store 失败关闭测试。本机 Linux `kill -9` 已覆盖 prepared-manifest / sealed-segment / vault-committed / anchor-confirmed。本机 Windows `taskkill /T /F` 已覆盖合成 6 点、远程锚点 4 点、真实轮换 4 点（见 `docs/security/m1.2-windows-process-kill-record-v1.md`）。仍缺：

- 在 Windows VM、Linux VM 和至少一种真实磁盘上执行完整 rotation/recovery 故障矩阵（含断电）。
- 在目录同步边界断电。交互式 `audit migrate-v2` 的本机 Windows TTY 进程击杀已留下 `20260817-082541`（prepared / sealed / vault-committed；`anchor-confirmed` 因 migrate 不写该 sidecar 未命中），断电未做。
- 重启后不得丢失已经发放 Secret 对应的 Audit（当前击杀场景不发放 Secret）。

完成证据：每个注入点的前置状态、终止方式、磁盘状态和恢复结果均留档。本机 `kill -9` 或 `taskkill /T /F` 通过不能计入断电完成。只完成了进程击杀，断电未做。

### 1.3 三平台真实运行矩阵

- Windows Credential Manager、Linux Secret Service、macOS Keychain。
- 登录、注销、锁屏/锁库、OS 更新、低权限账户和并发会话。
- Cargo、Node.js、Python 子进程；PowerShell、cmd、bash、zsh 终端。
- 路径 junction/reparse/symlink race、跨卷和网络文件系统拒绝行为。

完成证据：三平台 Release 构建、真实会话测试和失败场景记录。

### 1.4 持续安全验证

- 四个 fuzz target 进行小时级和定时 campaign，保存经过审核与最小化的 corpus。
- 跟踪覆盖率、crash、OOM、超长输入和差分 parser 结果。
- 对认证限流和 90 天 expiry 进行多进程压力、时钟前跳/回拨和全局可用性攻击测试。本机自动化已覆盖：expiry 在到期毫秒拒绝、时钟前跳使凭证失效、回拨不能复活、bucket 限流持久化且回拨不能绕过、并发打开失败关闭。全局限流（50 次失败）有 throttle 单元测试；小时级多进程压力和独立评审仍缺。
- 由独立人员复核密码学使用、格式、Broker 顺序、Policy、文件权限和恢复逻辑。

完成证据：持续任务历史、覆盖率趋势、问题清单和独立评审关闭记录。

## 里程碑 2：可发布的本地开发工具

仅在里程碑 1 的高优先级问题关闭后开始。

- Windows 安装包与卸载/升级策略；Linux/macOS 可复现安装方式。
- `doctor`/诊断能力，只输出 value-free 状态、权限和恢复提示。
- 备份与恢复流程必须验证 Vault、Audit segments、descriptor、anchor 和 keystore sidecar 的一致性。
- 建立版本兼容、数据迁移、Release 签名和安全公告流程。

完成标准：新机器安装、升级、备份恢复和卸载矩阵通过，发布物可验证来源且不包含本地 Vault/credential/corpus。

## 里程碑 3：AI-aware Capability Broker

该里程碑不复用 `run -- command` 作为 Agent 隔离方案。

### 3.1 Capability 模型

- 定义不可伪造、短期、可撤销、作用域精确的 Capability。
- Capability 必须绑定 Caller、Secret、Operation、有效期、次数和请求上下文。
- 默认拒绝；一次授权不能扩大为其他 Secret 或其他 Operation。

### 3.2 Human Approval

- 明确什么请求必须由 Human 批准。
- 批准内容必须显示 Caller、目标 Secret、Operation、持续时间和风险，但不显示 Secret Value。
- 拒绝、超时、重复使用和状态恢复均需可审计并失败关闭。

### 3.3 Credential Proxy

- 优先代理受限 API 操作，而不是向 Agent 返回通用明文 Secret。
- 研究短期上游凭证、请求签名和单用途代理。
- 明确代理无法阻止的目标服务侧泄漏、同用户进程攻击和恶意项目代码风险。

完成标准：Agent 在没有 `read_plaintext` 权限时能完成至少一种真实受限任务，并证明不能将该授权复用于其他 Secret、目标或操作。

## 里程碑 4：SDK 与受控集成

- Rust SDK 先行，随后根据真实需求评估 Node.js/Python binding。
- SDK 只能调用 Broker，不得直接解密 Vault 或绕过 Policy/Audit。
- 为 IDE/Agent 集成建立明确身份、能力请求、审批和撤销协议。
- 所有协议先稳定 wire format、资源限制和 threat model，再开放第三方集成。

## 暂不进入范围

- 团队多租户、云同步、Web UI 和服务器集群。
- AWS/Azure/GCP/Kubernetes 全面集成。
- 动态数据库账户、复杂 PKI 和企业级 IAM。
- 对不可信 Agent 作“绝对不会泄露 Secret”的承诺。

这些内容只有在本地单用户安全边界和 Capability Broker 经真实验收后才重新评估。

## 执行顺序

```text
生产安全验收
  → 可发布的本地开发工具
  → Capability + Human Approval
  → Credential Proxy
  → SDK 与受控集成
```

每个里程碑都必须同时交付：实现、自动化测试、真实环境证据、文档和明确限制。缺少其中任意一项时，不得把该里程碑标记为生产完成。
