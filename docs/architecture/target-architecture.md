# Target Architecture

## 架构目标

EnvVault 采用本地优先的模块化单体架构。第一阶段保持单个 Rust package，以便统一安全审查、错误处理和测试；只有出现明确的独立发布、独立权限或编译隔离需求时，才拆分为多个 crate。

系统的核心决策始终是：

```text
Caller × Secret × Operation → PolicyDecision
```

身份认证只建立“调用者是谁”，授权决策才回答“该调用者能否对该 Secret 执行该操作”。

## 逻辑组件

```text
Human / Application / AI Agent
                 │
          CLI or local adapter
                 │
                 ▼
             Identity
                 │ verified caller
                 ▼
              Broker
         ┌───────┼────────┐
         ▼       ▼        ▼
       Policy   Vault    Audit
         │       │
         │       ├── Crypto
         │       └── Keystore
         │
         └── CallerId + CallerKind + SecretId + Operation
```

`process` 和 `dotenv` 是受限适配器：

- `dotenv` 只负责解析迁移输入，将每个键值转换成独立写入请求。
- `process` 只负责在 Broker 授权后启动目标进程，并承认环境注入无法隔离可修改目标程序的 Agent。

## 数据边界

领域层中的 `SecretRecord` 是可安全用于授权和审计的记录描述，只包含稳定 ID、名称等非明文信息。它不携带 plaintext，也不携带加密载荷。

Vault V1 已定义独立的持久化记录，把以下内容绑定在一起：

```text
SecretRecord metadata
+ encrypted payload envelope
+ integrity/version metadata
```

这样 Policy Engine 永远不需要接触 Secret Value，Audit 也没有接收 Secret Value 的理由。

## 单条请求流程

1. 入口接收 Secret ID 或名称以及 Operation。
2. Identity 边界验证调用者并产生可信 Caller Identity。
3. Broker 将可信 Caller（CallerId + CallerKind）、SecretId 和 Operation 组成授权请求。
4. Policy Engine 返回明确的 Allow 或 Deny；没有匹配规则时必须 Deny。
5. Broker 为 Allow 或 Deny 都先将不含 Value 的事件提交到 Vault 内认证 Audit 链；持久化或外部 Audit Sink 失败时 fail closed。
6. Deny 时 Broker 不读取记录载荷；Allow 时仅向 Vault 请求这一条 Secret。
7. Vault 在需要时调用 Crypto 解密对应载荷，不解锁无关 Secret。
8. Broker 通过受限消费边界发放结果。

## 批量请求流程

批量请求只是多次单条授权的组合，不能产生“整个 Profile 已授权”的隐式权限。

```text
requested: A, B, C

A → policy check → allow
B → policy check → deny
C → policy check → allow

result: A, C
```

是否允许部分成功由具体命令显式声明；无论采用部分成功还是整体失败，每条 Secret 都必须产生独立决策。

## 管理操作

设置、删除、轮换、导出和 Policy 管理不是普通的读取捷径。它们需要独立 Operation 和独立策略，不能因为调用者是 Human 就在代码中硬编码为自动允许。

初始化和恢复等 Vault 级操作不适配单 Secret 授权。当前已建立独立 `Caller × VaultOperation → PolicyDecision` 控制面，用于 `create_secret`、`manage_policy`、`manage_identity` 和 `read_audit`，不能伪装成某条 Secret 的操作。

bootstrap 只为随机生成的精确 Owner Caller 写入初始 Vault grants；它不是“所有 Human 自动管理员”。当前 Broker 已实现受控 Secret 创建、generation-checked Policy 替换、Policy/Audit 读取，以及 Application/AI Agent credential 注册、认证、列出和撤销。

## 运行时注入

`envvault run` 的目标是减少 Secret 长期明文落盘，并按授权集合构造子进程环境。它不提供以下保证：

- 防止目标程序主动打印或上传 Secret。
- 防止同权限调试器、内存读取工具或恶意动态库获取 Secret。
- 防止能够修改目标代码的 AI Agent 让目标程序泄露 Secret。

更强的 Agent 场景需要 Credential Proxy、短期凭证、限定操作的 Capability 或 Human Approval，而不是继续扩大环境变量注入的安全声明。

## 失败原则

- 身份无法验证：拒绝。
- Policy 缺失、损坏或无法读取：拒绝。
- Secret ID 不明确：拒绝，且避免通过错误差异泄露存在性。
- 当前 Broker 的 Audit 写入失败：拒绝，不解密 Secret；未来如引入不同失败策略必须新增明确 ADR 和测试。
- Vault 完整性校验失败：停止读取，不尝试返回部分明文。
