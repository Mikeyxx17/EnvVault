# ADR 0014: Bounded Caller Credential Lifetime

状态：Accepted，2026-08-13。

## 背景

Application/AI Agent credential 是长期 bearer evidence。显式轮换和撤销能让旧 verifier 失效，但如果 Owner 从不操作，凭据会无限有效。只在 CLI 或 credential 文件中检查时间可被其他调用路径绕过，也不能保护 Registry 恢复与 machine-unlock 路径。

## 决策

- Identity Registry V3 在每个 verifier 旁认证保存 `credential_issued_unix_time_millis` 与 `credential_expires_unix_time_millis`。
- 新注册和轮换一律使用严格 90 天窗口，有效区间为 `[issued, expires)`，无宽限期。
- Broker 在创建 `VerifiedCaller` 前强制到期判断；过期仍执行真实 KDF，并与错误、未知和 wrong-kind credential 返回相同错误及 value-free Audit 形状。
- 签发、轮换和认证共同使用 Registry 持久化的 last-observed wall clock；回拨不能复活旧凭据或创建相对 Registry 时钟已经过期的新凭据。
- V1/V2 无可信签发时间，迁移时使用显式 legacy-unbounded sentinel。Owner 必须轮换才能进入 V3 有限生命周期；系统不得伪造历史时间并静默撤销。
- 生命周期是 Registry/Broker 规则，不信任 credential 文件或 CLI 预检查。

## 影响

新凭据最多使用 90 天，过期后的恢复动作是 Owner 轮换。管理员将时钟大幅前跳可能导致提前失效；完整 Vault 回滚仍可能回滚时钟与生命周期状态，直到外部单调 anchor 通过生产验收。旧 credential 文件不会自动删除。
