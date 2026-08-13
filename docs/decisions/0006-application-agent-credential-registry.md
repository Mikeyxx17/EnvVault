# ADR 0006: Application and Agent Credential Registry

## 状态

Accepted，2026-08-13。

## 背景

进程名、可执行文件路径、工作目录、环境变量或调用方自报 CallerId 都不能证明 Application/AI Agent 身份。Broker 需要一种本地、可撤销且不把原始凭证写入 Vault 的第一版身份机制。

## 决策

- `manage_identity` 保护 Application/AI Agent 注册、列出、轮换和撤销。
- 注册使用 OS CSPRNG 生成随机 128-bit CallerId、256-bit credential 和独立 128-bit salt。
- 原始 credential 由不可 `Debug`/`Clone` 的 zeroizing 类型返回一次；Registry 只保存 Argon2id 32-byte verifier。
- Identity Registry 位于独立 AEAD envelope，文档与 envelope generation 必须一致，更新采用 expected generation。
- Caller name 只用于管理显示；Policy 和认证始终使用 CallerId + CallerKind。
- V1 不允许凭证注册 Human。
- 验证使用注册 KDF 参数和常量时间比较；未知 CallerId 仍执行相同参数级别的 dummy Argon2id，并与错误 credential/CallerKind 返回同一错误。
- 撤销删除 Registry verifier。残留 Policy rule 不会重新建立身份。
- 轮换保留稳定 CallerId/CallerKind/名称与 Policy，只 generation-checked 替换 salt/verifier；旧 credential 在提交后立即失效，新 credential 使用可恢复且不覆盖的文件交付。
- Phase 7P 将有界 64-bucket/global 认证限流状态加入严格 Identity Registry V2；Phase 7Q 的 V3 再加入严格 90 天 credential 生命周期。V1/V2 可读，下一次认证结果或身份管理提交写为 V3。认证只在 Audit 和身份状态均持久化后成功返回。
- 成功认证只创建 `VerifiedCaller`，不授予任何 Secret 或 Vault 权限。

## 影响

- 高熵 credential 仍使用 Argon2id，增加认证成本，但在 Registry 被解密或误暴露时保留防御纵深。
- Registry 最大 1 MiB、最多 256 个注册 Caller；这符合本地单用户第一阶段范围。
- Phase 7M 已用独立 wire-version authentication target 记录成功/失败认证尝试，且未知主体仍执行 dummy KDF、对外错误保持一致；Phase 7P/7Q 已加入持久化限流和到期强制，但更强进程证明和真实对抗性运行验收仍未完成。
- ADR 0007 已增加第一批 CLI 文件交付边界；ADR 0011 后续实现了 Windows 专用 DACL 和 recovery 文档。Phase 7K/7L 已实现三平台 machine-unlock keystore adapter，但独立真实平台验收仍未完成。

## 复审条件

- 引入 Windows Credential Manager、TPM、平台签名或进程证明。
- 引入 credential 过期时间、短期 token 或 Human Approval。
- 需要多个 Human、远程调用者、团队共享或集中 Identity Provider。
- Argon2id 认证成本不适合目标调用频率。
