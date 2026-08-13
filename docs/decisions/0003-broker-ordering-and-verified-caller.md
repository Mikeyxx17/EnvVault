# ADR 0003: Broker Ordering and Verified Caller Boundary

## 状态

Accepted，2026-08-13。

## 背景

Broker 如果接受调用方自报身份、在授权前读取 Vault，或在审计不可用时继续发放 Secret，就会绕过 EnvVault 的核心安全边界。批量请求还可能错误复用一次 Allow。

## 决策

- Broker 仅接受字段私有、构造受 crate 限制的 `VerifiedCaller`。
- Identity Provider 必须验证凭证后才能创建该 token；Master Password Owner 与 Application/Agent credential provider 均已实现，且没有后门式公共构造器。
- 每个 Secret 的固定顺序是 Policy decision、Audit record、按 Decision 读取。
- Audit Sink 失败时统一 fail closed，不读取允许的 Secret。
- Deny 不读取 metadata 或 value envelope。
- 批量请求逐项建立请求、决策和结果绑定。
- Policy 只从 Vault 的认证 envelope 加载；认证或结构错误进入 `Invalid` 并默认拒绝。

## 影响

- 审计可用性会影响 Secret 可用性，这是当前有意选择的安全优先级。
- `VerifiedCaller` 只防止 API 层的直接身份注入，不能替代真实凭证验证。
- Audit 目前只有接口和内存测试实现；持久化、完整性和轮换仍需单独设计。
- CLI 在 Identity Provider 与应用服务完成前不能调用内部 Broker。

## 复审条件

- 引入允许在 Audit 故障时继续的操作。
- 引入进程身份、应用凭证或 Agent 凭证提供者。
- 引入流式、并行或全有全无的批量语义。
- 引入可绕过 Broker 的新 Secret 消费路径。
