# Secret Broker V1

## 状态

状态：内部实现与自动化验证完成；Owner bootstrap、Application/Agent credential Identity、Vault 内认证 Audit 链，以及基础 Identity/Secret 管理 CLI 已接入。

Broker 是授权决策与 Secret 发放之间的编排边界。面向调用方的流程不得直接调用 Vault plaintext read 或 Crypto decrypt。

## 输入身份

Broker 接受 `VerifiedCaller`，不接受裸 `CallerId`、进程名、路径或调用方自报的 Caller。`VerifiedCaller` 的字段和构造器不向 crate 外部开放，因此外部库使用者不能直接伪造该 token。

Master Password Owner bootstrap 会在新 Vault 内原子创建随机 Human CallerId、显式 Owner Vault rules 和 Audit key。再次对同一路径 bootstrap 会失败。成功解锁并认证 Identity Registry envelope 后，内部 Owner provider 才创建 `VerifiedCaller(MasterPassword)`。

Application 与 AI Agent 通过 Identity Registry 中的 Argon2id verifier 验证随机 credential，成功后分别创建 `VerifiedCaller(ApplicationCredential)` 或 `VerifiedCaller(AgentCredential)`。错误、未知 ID 和错误 CallerKind 统一失败。Owner 权限来自 Policy Document 中绑定其 CallerId/CallerKind 的规则，不来自身份类别的隐式绕过。

## 请求顺序

对每一条 `(Caller, SecretId, Operation)`：

1. Policy Engine 计算独立 `PolicyDecision`。
2. Broker 构造不含 Secret Value 的严格版本化 `AuditEvent`。
3. 新 Vault 的事件写入 Audit V2 active segment；活动文件和 Descriptor V3 认证失败、轮换恢复失败或 mandatory anchor degraded 都返回 `AuditUnavailable`。
4. 可选外部 Audit Sink 也必须接受事件，否则 fail closed。
5. Deny 返回结构化拒绝，不读取对应记录载荷。
6. Allow 才读取这一条记录所需的 metadata 或 value envelope。

`list` 先读取不含名称和值的 Secret ID 索引；只为获得 `List` Allow 的 ID 解密 metadata。`exists`、`verify`、`use` 和 `read_plaintext` 是互不蕴含的 Operation。

`create_secret` 和 Policy 替换走独立 Vault authorization。新 Secret 创建成功不会自动给创建者增加 `list`、`use` 或 `read_plaintext`；Policy 替换使用 expected generation 拒绝过期写入。

管理 CLI 使用更窄的 `create_managed_secret` 工作流：同时要求 `create_secret` 和 `manage_policy`，并将新 Secret 与精确 Owner `list/exists/verify/write/delete` rules 在同一 Vault commit 中落盘。该工作流不授予 `use`、`read_plaintext` 或 `export`，也不改变原始 `create_secret` 的无隐式授权语义。

按名称执行 `exists/write/delete` 时，Broker 对每个 SecretId 先评估对应 Operation，只对 Allow 项解密 metadata 做精确名称比较，因此不会把这些操作转化成 `list` 权限。

Policy 读取复用 `manage_policy` 权限，Audit 读取需要独立 `read_audit` 权限。读取 Audit 本身会先写入一条 Vault-scoped Audit event，因此返回结果包含这次读取决策。

## 批量语义

V1 的批量 `use` 对每个 Secret 单独授权、单独审计、单独读取。结果将原 SecretId、Decision 和可选 Value 绑定在一起；只有该项 Allow 且读取成功时才携带 Value。

当前批量流程在 Audit 或 Vault 运行错误时停止并返回错误；Policy Deny 是正常逐项结果，不会阻止其他项继续评估。

## 已验证安全属性

- Policy envelope 被篡改时 Broker 保持可报告的 `Invalid` 状态并默认拒绝。
- 无效但已认证的 Policy payload 同样默认拒绝。
- Deny 的 `list` 项不会解密 metadata。
- `use` Allow 不会隐式允许 `read_plaintext`。
- 批量请求只返回各自 Allow 的 Value。
- Audit Sink 失败发生在允许的 Secret 解密之前。
- Owner bootstrap 只能执行一次，重新打开得到同一个 CallerId。
- 其他 Human 不会继承 Owner 的 Vault grant；新 Secret 也不会自动授予 Owner 数据面权限。
- Audit 失败阻止 Secret 创建，过期 Policy generation 不会覆盖当前规则。
- Identity 注册/列出/撤销需要 `manage_identity`；Audit 失败阻止注册。
- 撤销持久化后旧 credential 无法认证；认证成功仍需每条 Secret 的精确 grant。
- Audit payload 不以明文落盘；V2 活动/封存段修改、重排、断链或 descriptor 不一致使 Broker 打开失败。
- Broker error 不携带 Secret Value。

这些是自动化代码证据，不包含真实 Windows 身份、ACL、磁盘恢复或独立安全评审。
