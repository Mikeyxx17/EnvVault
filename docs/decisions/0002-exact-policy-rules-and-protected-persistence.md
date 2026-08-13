# ADR 0002: Exact Policy Rules and Protected Persistence

- Status: Accepted for Policy V1
- Date: 2026-08-12

## Context

EnvVault 必须实现 `Caller × Secret × Operation → PolicyDecision`，并防止身份认证、Profile 声明或 Human 类型被误当成 Vault 全局授权。

Policy 自身也是安全资产。只做严格 JSON 解析不能阻止攻击者加入语法合法的 `allow`。

## Decision

1. Policy V1 使用 `(CallerId + CallerKind) × SecretId × Operation` 精确规则。
2. 同时匹配 allow 和 deny 时，deny 优先。
3. 没有匹配 grant 时默认拒绝。
4. Policy source 缺失或无效时全部默认拒绝，并暴露 availability 状态供审计。
5. 批量请求保留逐请求、逐 Secret 决策对象。
6. Policy 文档使用严格、版本化、确定性编码，但不提供未认证文件存储。
7. Broker 只有在 payload 经过 Vault/等价完整性保护后才能激活文档。
8. 第一版没有 wildcard、角色继承、Profile grant 或 Human bypass。

## Consequences

- 权限配置较冗长，但最小权限语义明确、易于测试。
- AI Agent 无法仅通过 CallerKind 或 Profile 扩大权限。
- Policy Engine 已可独立验证，但在 Broker 完成认证存储集成前不能形成端到端安全授权。
- 未来加入 group、role 或 wildcard 必须重新定义冲突优先级并单独评审。
