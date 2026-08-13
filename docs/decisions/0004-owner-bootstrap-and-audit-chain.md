# ADR 0004: Owner Bootstrap and Embedded Authenticated Audit Chain

## 状态

Accepted，2026-08-13；bootstrap Policy 部分由 ADR 0005 演进。

## 背景

新 Vault 需要建立稳定 Owner Identity，但成功输入 Master Password 不能等同于全部授权。Audit 还必须在 Secret 解密前持久化，并检测本地文件中的事件修改、重排与局部删除。

## 决策

- 新 Vault 创建时生成随机 Human CallerId，并在同一个原子 Vault state 中写入认证 Identity envelope、空的默认拒绝 Policy 和独立随机 Audit key。
- 只有成功解锁 Master Password、认证并严格解析 Identity envelope 后，才能创建 Owner `VerifiedCaller`。
- 已存在的 Vault 路径拒绝重复 bootstrap；Owner 身份不隐式授予任何 Secret 或 Vault 级权限。
- Audit event 使用独立 Audit key 逐条认证加密；AAD 绑定 Vault ID、序号和前一事件 authenticator。
- Audit-key envelope 的 AAD 绑定当前事件数量和链头，使局部删尾也会失败。
- Broker 在 Secret 读取前原子提交 Audit event；失败时 fail closed。

实现更新：ADR 0005 将“空 Policy”演进为只绑定随机 Owner Caller 的四条显式 Vault grants。该更新不引入 Human 隐式权限，其余 Identity 与 Audit 决策保持不变。

## 影响

- Audit 与 Vault 共享 64 MiB 容器和原子更新，每次授权都会重写 Vault；这优先保证第一版一致性，不是最终高吞吐设计。
- Identity、Policy、Audit 和 Secret 使用同一 Master Key 根，但具有不同 AAD 域；Audit event 另用独立随机 key。
- 整个旧 Vault 文件连同旧链头一起回滚仍无法检测，需要文件外可信单调状态或锚点。
- Application/AI Agent 凭证验证仍需独立设计；Vault 级管理授权由 ADR 0005 定义。

## 复审条件

- Audit 文件接近容量限制或需要高频并发。
- 引入 Audit 轮换、导出、外部签名/锚点或集中收集。
- 引入 Owner 恢复、多个 Human 或 Master Password 轮换。
- 扩展 Vault 级操作、委派或恢复能力。
