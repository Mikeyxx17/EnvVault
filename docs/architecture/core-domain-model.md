# Core Domain Model

## 标识类型

`SecretId` 和 `CallerId` 是不同的强类型，底层均为不透明的 128-bit 标识。它们不能互换，也不提供不安全的默认值。

当前领域层只负责保存和展示既有 ID，不负责随机生成。后续生成器必须使用 CSPRNG，并在持久化格式确定后补充解析和兼容性测试。

Policy 与 Audit 必须使用稳定 ID 建立关系；可修改的名称只用于显示和查找。

## SecretRecord

`SecretRecord` 当前表示 Secret 的非明文领域记录：

```text
SecretRecord
├── SecretId
└── SecretName
```

它刻意不包含 plaintext 或 encrypted payload。加密载荷属于 Vault 的持久化模型，避免 Policy 和 Audit 为了读取名称而被迫接触不需要的数据。

`SecretName` 拒绝空白名称、首尾空白、控制字符和过长输入，以减少名称混淆及日志注入风险。`.env` 键名的更严格语法由 `dotenv` 模块单独处理。

## Caller

`CallerId` 表示稳定调用者身份，`CallerKind` 区分：

- Human
- Application
- AiAgent

CallerKind 只是策略输入，不能替代身份验证，也不能硬编码为授权结果。Policy V1 同时绑定 CallerId 与 CallerKind，防止身份类别混淆，但不支持对整个 CallerKind 的通配授权。

## Operation

第一组 Operation 包含：

- `List`
- `Exists`
- `Use`
- `ReadPlaintext`
- `Write`
- `Delete`
- `Export`
- `Rotate`

`Use` 与 `ReadPlaintext` 保持不同语义。`List` 返回候选记录时仍需要逐记录过滤，不能暴露未授权名称。

## PolicyDecision

`PolicyDecision` 只有 Allow 或带安全原因码的 Deny。默认值必须是 Deny，缺少匹配规则也是 Deny。

`AuthorizationRequest` 将 Caller（CallerId + CallerKind）、SecretId 和 Operation 绑定为一次不可缺项的决策输入。`PolicyEvaluator` 接口只接收此请求，不接收 Secret Value。
