# EnvVault Threat Model

## 1. 状态和范围

版本：初始架构基线，更新于 2026-08-13。

本文描述目标设计及后续实现必须验证的安全边界。当前工程已实现 Vault/Crypto、Secret/Vault Policy Engine、Identity Registry、Policy/Identity 认证持久化、内部 Broker、管理 CLI、严格 Profile/运行时注入、私有敏感文件/credential 恢复、parser fuzz/property/供应链策略，以及 Phase 7D～7J Audit V2 格式、Manifest V2、SegmentStore、Descriptor V3 key envelopes、Broker/CLI 活动段、自动轮换/启动恢复、本地镜像 CAS、显式迁移和 mandatory degraded 原语。Phase 7K～7M 已加入 Windows Credential Manager/Linux Secret Service/macOS Keychain machine unlock adapter、认证 Master Key sidecar、代次轮换和禁用恢复，以及成功/失败 authentication-attempt Audit 与 value-free machine session；Phase 7N～7P 已加入可选星号反馈、值验证、可恢复的 Caller credential 轮换和持久化 bucket/global 认证限流。所有控制面和逐 Secret 权限仍来自精确 rules。真正外部单调 anchor、长期 fuzz campaign、真实平台 credential-store 与对抗性崩溃/断电注入、限流运行验收和独立安全验收尚未完成。因此 machine unlock 不能描述为同用户进程隔离，本地镜像不能描述为完整文件回滚保护，自动化通过也不能整体视为已交付生产安全能力。

第一阶段范围是单机、单用户、本地开发环境。云服务、团队共享、远程控制平面、Kubernetes 和复杂 PKI 不在范围内。

## 2. 受保护资产

- Secret plaintext。
- 从 Master Password 派生的密钥、Master Key、DEK 和 KEK。
- 加密 Vault 的完整性、版本和可恢复性。
- Caller 身份及其认证材料。
- Policy 的完整性和默认拒绝语义。
- Audit 的完整性，以及其中不包含 Secret Value 的约束。
- Secret 名称、存在性、使用时间等可能敏感的元数据。

## 3. 潜在攻击者

- 能读取项目目录的 AI Coding Agent。
- 能修改并运行项目代码的 AI Coding Agent。
- 与用户同权限运行的恶意或被入侵进程。
- 获得 Vault 文件、备份或磁盘副本的离线攻击者。
- 能修改 Vault、Policy、Config 或 Audit 文件的本地攻击者。
- 诱导用户运行恶意命令、插件、构建脚本或目标程序的攻击者。
- 获得管理员权限、调试权限或物理设备控制权的攻击者。

## 4. 信任边界

### Boundary A：调用入口到 Identity

CLI 参数、父进程环境、工作目录、可执行文件路径和进程名称都是攻击者可影响的数据，不能单独视为可信身份。

Identity 必须产生经过验证的 Caller，而不是接受调用者自报的 CallerId。

### Boundary B：Identity 到 Broker

Broker 只接受可信身份结果。身份验证失败、身份数据缺失或提供者异常时必须拒绝。

### Boundary C：Broker 到 Policy

每个请求必须完整携带 CallerId、CallerKind、SecretId 和 Operation。Profile、命令名称或“已经解锁 Vault”不能替代 PolicyDecision。

### Boundary D：Broker 到 Vault

Broker 只有在对应 Secret 获得 Allow 后才能读取该记录载荷。批量请求不得一次读取整个 Vault 再在内存中过滤。

### Boundary E：Vault 到 Crypto/Keystore

Vault 文件及其元数据是不可信输入。解密前必须验证格式、长度、版本和认证标签。密钥库失败不能回退到明文密钥文件。

### Boundary F：Broker 到消费方

明文离开 Broker/Vault 后，EnvVault 对目标程序行为的控制显著下降。环境变量注入尤其不是隔离边界。

## 5. 关键威胁与设计要求

| ID | 威胁 | 影响 | 必须采取的设计措施 |
|---|---|---|---|
| T01 | `.env` 或导入文件长期保留明文 | Agent 或本地进程直接读取 | 已按 key 整批拆分为独立记录；成功信息明确 `source_preserved`；绝不修改源文件，也不声称自动安全删除 |
| T02 | 未授权调用者读取整个 Vault | 大范围 Secret 泄露 | 每条 Secret 独立授权；Broker 按 ID 获取；默认拒绝 |
| T03 | Profile 被当成授权 | 应用通过声明扩大权限 | Profile 只生成请求集合；Policy 逐条决定 |
| T04 | `Use` 被等同于 `ReadPlaintext` | 调用者获得不必要明文 | Operation 类型明确区分；不同 Broker 消费路径 |
| T05 | CLI 参数包含 Secret | Shell 历史、进程列表和遥测泄露 | 当前 Master Password 和 `set` 的 Secret Value 只接受关闭回显的交互 TTY；禁止位置参数、flag value、环境变量和非终端 stdin fallback |
| T06 | 日志、错误或 Audit 输出 Secret | 持久化泄露和二次扩散 | 明文类型不实现普通 Debug/Display；结构化脱敏；负向测试 |
| T07 | Vault 被篡改 | 错误解密、数据替换或破坏 | 使用认证加密；绑定记录 ID、版本和必要元数据作为 AAD |
| T08 | Vault 文件回滚 | 恢复旧 Secret 或旧 Policy | generation/segment/anchor 链和本地 CAS 已实现；同盘整体回滚仍需真正外部/硬件单调 sink，未部署前必须明确限制 |
| T09 | 写入中断或并发覆盖 | Vault 损坏或更新丢失 | 同目录临时文件、完整校验、原子替换、锁和失败恢复测试 |
| T10 | 弱 Master Password 离线爆破 | 全部 Secret 泄露 | Argon2id、随机 salt、可迁移参数；不自创 KDF |
| T11 | Nonce 重用或密钥使用错误 | 机密性与完整性失效 | CSPRNG、清晰 envelope 版本、测试 nonce 唯一性；使用成熟 AEAD crate |
| T12 | 明文或密钥残留内存 | 内存转储或错误复制泄露 | 最小生命周期、受限类型、zeroize/secrecy；避免 Clone 和隐式格式化 |
| T13 | 通过名称/exists 枚举 Secret | 元数据泄露 | `list`、`exists` 也是授权操作；统一未找到与未授权的外部语义 |
| T14 | 身份伪造 | 攻击者冒充已授权应用 | 不信任自报 ID、路径或进程名；Application/Agent 使用随机 credential、Argon2id verifier、常量时间比较和撤销；平台 machine-unlock adapter 已接入但 credential 文件和真实平台验收仍待加固 |
| T15 | Policy 文件被修改或解析失败 | 权限扩大或不可用 | 完整性保护、严格解析、显式拒绝优先、失败关闭 |
| T16 | 批量请求错误复用一次 Allow | 获得未授权 Secret | 每条记录建立 AuthorizationRequest 和 PolicyDecision；部分结果测试 |
| T17 | `run` 目标程序输出或上传 Secret | Runtime Secret 泄露 | 在产品和文档中明确边界；后续使用代理、短期凭证或能力令牌 |
| T18 | 子进程环境被无关后代继承 | Secret 扩散 | 构造最小环境；只注入授权项；清理父进程临时状态；平台测试 |
| T19 | 恶意路径、符号链接或权限配置 | Vault、credential 或 recovery 文件被替换、暴露或写入错误位置 | `secure_fs` 检查全路径组件、拒绝 symlink/reparse point，Unix 强制 `0600`，Windows 设置并复核 protected DACL；恶意同账户 race 和独立真实平台验收仍待完成 |
| T20 | Audit 本身泄密或被删除 | 泄露与不可追责 | 固定安全字段；不接收 Value 类型；完整性/轮换策略；记录失败策略 |
| T21 | 导出和剪贴板长期保留明文 | Secret 离开控制边界 | 独立 `Export` 权限、明确确认、最小输出渠道和风险提示 |
| T22 | 备份、崩溃转储、交换文件包含材料 | 控制边界外泄露 | 文档化平台限制；最小明文生命周期；真实环境验收 |
| T23 | 用户认为删除记录会物理擦除旧磁盘块 | 旧密文或历史副本长期存在 | 不承诺 secure delete；依赖全盘加密、备份治理和介质生命周期 |

## 6. `run -- command` 的明确边界

以下场景在第一阶段不被阻止：

1. Agent 修改目标源码，让程序打印环境变量。
2. 目标程序主动上传注入的凭证。
3. 同权限进程通过调试、内存读取或平台接口观察目标进程。
4. 恶意构建脚本、动态库、插件或子进程继承凭证。

因此，`run` 只能描述为“减少长期明文落盘并进行最小集合注入”，不能描述为“AI Agent 无法获得 Secret”。

要提高该边界，需要让 Agent 获得“执行某个受限操作的能力”，而不是获得通用凭证本身，例如：

- Credential Proxy。
- Human Approval。
- 单用途、短期 Capability。
- 短期云凭证。
- 受限 API Broker。

## 7. 明确不保证的事项

第一阶段不保证抵抗：

- 已获得管理员、内核或物理控制权的攻击者。
- 已控制 EnvVault 进程地址空间的攻击者。
- 用户主动复制、打印或上传 Secret。
- 目标应用自身的恶意行为。
- 未经验证的平台备份、崩溃转储和休眠文件泄露。
- 完整的 Vault rollback protection，除非后续实现并通过独立验收。

## 8. 安全验收要求

功能实现后，至少需要分别提供：

- 单元测试：类型不变量、默认拒绝、操作区分、日志脱敏。
- 集成测试：逐 Secret 授权、批量部分拒绝、损坏 Vault、原子更新。
- 属性或模糊测试：解析器、序列化格式和策略匹配。
- 平台测试：文件权限、进程环境继承、锁、替换和恢复。
- 人工审查：密码学 envelope、密钥生命周期、身份机制和安全文案。

自动化测试通过不等于密码学或真实设备安全验收完成。

## 9. 待决安全问题

- Application 与 AI Agent credential 仍由不覆盖私有文件和 recovery 协议管理；是否迁移到独立平台项，以及 machine-unlock sidecar/凭据项如何完成真实断电级恢复证明？
- authentication attempt 已统一记录、保留 dummy KDF 并加入持久化 bucket/global 限流；如何完成多进程、时钟操纵、全局可用性攻击和 Audit 容量滥用的真实运行验收？
- 当前 Vault 与 Policy 使用同一 Master Key、不同 AAD 域；何时需要独立子密钥？
- Audit V2 已轮换并支持本地 CAS、loopback 参考 HTTPS CAS 与 last-confirmed 回滚检测；如何完成真实远程 WORM/硬件 AnchorSink 的服务端回滚与可用性验收？
- 是否在第一版支持 `ReadPlaintext` 和 `Export`，还是只为 Human 管理路径保留？
- Windows 上如何处理进程身份、文件 ACL、重解析点和内存保护？
- Vault 回滚检测的可信状态保存在哪里？
