# ADR 0011: Private Sensitive Files and Recoverable Credential Delivery

状态：Accepted，2026-08-13。

## 背景

Vault 原子替换会生成新文件，Windows 上不会自动保留旧 DACL。Identity Registry 与明文 credential 文件也无法组成一个文件系统原子事务；进程在两者之间崩溃会留下孤儿 Caller 或未完成目标。

## 决策

- 新增 crate-private `secure_fs`，集中处理敏感文件创建、打开、权限设置和路径检查。
- 每个既有路径组件都拒绝符号链接或 Windows reparse point；叶子打开使用 no-follow 语义并在句柄上复核。
- Unix 敏感文件必须没有 group/other 权限，创建模式为 `0600`。
- Windows 敏感文件使用 protected DACL，只允许文件 Owner、Local System 和 Built-in Administrators 完全访问；创建或打开失败、DACL 不匹配时失败关闭。
- Vault 每次原子替换完成后重新设置并验证权限。Unix 还会在写入临时文件内容前收紧模式；Windows 原子写入库不暴露带 `WRITE_DAC` 的临时句柄，因此临时文件只承载加密 Vault 字节，最终文件提交后立即加固。
- Caller 注册拆成 prepare/commit。commit 前先同步一个受同等权限保护的 credential delivery recovery 文档，再创建空目标、提交 Registry、写入并同步 credential，最后删除 recovery 文档。
- Owner 下一次打开 Vault 时自动恢复：未提交注册只删除操作拥有的空目标；已提交注册则完成缺失/空 credential 文件；非空不匹配目标一律保留 recovery 文档并失败关闭。

## 影响与边界

Recovery 文档在短暂生命周期内包含 Base64 原始 credential，因此它本身是 Secret，并使用与 credential 文件相同的权限和内存清零规则。平台 keystore、磁盘加密、安全删除、目录 ACL 所有权、断电目录项持久性和恶意同权限进程不由本决策解决。既有宽松权限 Vault 不会自动信任或静默迁移。
