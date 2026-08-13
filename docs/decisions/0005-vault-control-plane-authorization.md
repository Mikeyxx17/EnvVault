# ADR 0005: Separate Vault Control-Plane Authorization

## 状态

Accepted，2026-08-13。

## 背景

创建第一条 Secret、管理全局 Policy、管理 Identity 和读取 Audit 都没有自然的 SecretId。如果为这些操作伪造保留 SecretId，会污染数据面模型；如果直接判断 `CallerKind::Human` 或 Owner 身份，则会形成隐式授权绕过。

## 决策

- 保留数据面核心模型：`Caller × SecretId × Operation → PolicyDecision`。
- 增加独立控制面模型：`Caller × VaultOperation → PolicyDecision`。
- 第一版 VaultOperation 包含 `create_secret`、`manage_policy`、`manage_identity` 和 `read_audit`。
- Vault rules 精确绑定 CallerId、CallerKind、VaultOperation 和 Effect；无 wildcard，显式 Deny 优先，缺失规则默认拒绝。
- Policy Document 在同一个认证 payload 中分别保存 `rules` 与 `vault_rules`，两类规则合计受 10,000 条上限约束。
- bootstrap 为随机生成的精确 Owner Caller 写入四条显式 Allow；不是所有 Human 或所有 Owner 的代码级特权。
- Broker 在 Vault policy Allow 且 Audit 成功后才能创建 Secret 或替换 Policy。
- 新 Secret 创建不自动授予任何数据面权限；Policy 更新使用 expected generation 拒绝过期覆盖。

## 影响

- 身份认证与管理授权继续分离；另一个 Human 不会继承 Owner grant。
- Owner 可以通过显式 Policy 更新撤销自己的管理权限，系统不会隐式恢复。
- `read_audit` 已有受控 Broker 读取服务；`manage_identity` 已由 ADR 0006 用于 Application/AI Agent 注册、列出和撤销。
- Policy V1 payload 增加必需的 `vault_rules` 字段；项目尚未开放真实数据使用，因此当前调整仍处于 Initial implementation format。

## 复审条件

- 引入多 Owner、恢复密钥、紧急 break-glass 或 Human Approval。
- 引入删除 Vault、修改 Master Password、Audit 轮换等新控制面操作。
- 需要委派式管理、临时 Capability 或条件规则。
