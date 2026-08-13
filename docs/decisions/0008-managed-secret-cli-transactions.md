# ADR 0008: Managed Secret CLI Transactions and Name Resolution

状态：Accepted
日期：2026-08-13

## 背景

第一版用户命令以 Secret Name 操作，但 Policy 使用稳定 SecretId 精确授权。新 Secret 尚无 SecretId，且单独先创建记录、再写 Owner Policy 会产生策略更新失败后的孤儿 Secret。按名称查找也不能先解密全部名称再决定权限，否则 `exists`、`write` 或 `delete` 会退化成隐式 `list`。

## 决策

- `set` 的 Secret Value 只从关闭回显的交互终端读取，不接受 argv、环境变量或普通 stdin。
- 新 Secret 创建必须同时具备精确 Owner 的 `create_secret` 和 `manage_policy` Vault grants。
- Broker 为新随机 SecretId 写入该 Owner 的 `list`、`exists`、`verify`、`write`、`delete` Allow rules；`verify` 由 Phase 7N 增补。
- 上述四条规则不包含 `use`、`read_plaintext`、`export`、`rotate` 或 `manage_policy`。
- 新 Secret 的 metadata/value envelope 与更新后的认证 Policy envelope 在同一次 Vault state commit 中落盘。
- 对已有 Secret 的 `set`、`exists` 和 `remove` 分别使用 `write`、`exists` 和 `delete` 决策；对每个候选 SecretId 先授权，只对 Allow 项在 Broker 内解密名称并精确比较。
- `list` 仍只解密获得 `list` Allow 的 metadata，输出按名称排序且永不包含 Value。
- 删除记录后 V1 暂时保留该随机 SecretId 的失效 Policy rules；SecretId 不复用，这些规则不能授权未来 Secret。

## 影响

- Broker 的原始 `create_secret` 仍不会隐式授予任何数据面权限；只有这个明确要求 `manage_policy` 的管理工作流会写精确规则。
- 只有 `exists` 权限而没有 `list` 权限的 Caller 仍能按其获授权的名称查询，但不能列出名称集合。
- 对无 `write` 权限但名称已存在的 `set` 不会覆盖旧值；创建路径会因名称冲突安全失败。
- 删除是逻辑删除和新 Vault 状态提交，不承诺擦除旧磁盘块、备份或文件系统历史。

## 复审条件

- 引入专用加密名称索引或大规模 Vault 性能优化。
- 引入 Policy garbage collection 或 SecretId 恢复机制。
- 引入独立 `rotate`、`read_plaintext` 或 export CLI。
