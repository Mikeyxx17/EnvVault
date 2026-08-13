# Sensitive Files and Credential Recovery V1

状态：第一版实现与 Windows 本机自动化测试完成；真实低权限账户、跨卷、网络文件系统、恶意并发 race 和断电测试未完成。

## 保护对象

- 加密 Vault 文件；
- Application/AI Agent credential JSON；
- 短生命周期 credential delivery recovery JSON。

Profile 与 `.env.example` 不含 Secret Value 或认证 credential，因此继续使用各自的不覆盖写入规则，不套用敏感文件 DACL。

## 文件权限

Unix 创建模式为 `0600`，打开时拒绝任何 group/other 权限。Windows 使用 protected DACL，唯一允许 ACE 为当前文件 Owner、Local System 和 Built-in Administrators 的 Full Access；继承 ACE、额外主体、deny/callback ACE 或未受保护 DACL都会拒绝。

Windows 句柄显式请求 `READ_CONTROL | WRITE_DAC`，设置后重新读取 DACL 验证。最终 Vault 在每次原子替换后重复加固，避免新 inode/file object 丢失旧权限。

## 路径约束

- 拒绝 `..`；
- 检查每个既有组件；
- Unix 拒绝 symlink，Windows 同时拒绝所有 reparse point；
- 既有叶子使用 no-follow 打开并在句柄 metadata 上复核；
- 新文件使用 `create_new`，所以竞争者先放入叶子会导致创建失败而不会跟随。

这些检查缩小路径替换面，但还不等于对抗拥有同一账户权限的持续 race 攻击已被证明安全。

## Credential 交付恢复

注册和轮换都使用：prepare credential → 同步 recovery 文档 → 创建私有空目标 → commit Registry → 写入并同步 credential → 删除 recovery 文档。

下次 Owner 打开时：

- recovery credential 与当前 Registry verifier 不匹配：只允许删除缺失或操作拥有的私有空目标；
- recovery credential 与当前 Registry verifier 匹配：允许创建缺失目标、续写私有空目标，或确认现有 credential 完全匹配；
- 非空无效/不匹配目标、无效 recovery 文档或不安全权限：失败关闭，不删除证据。

自动化测试分别覆盖注册/轮换的提交前空目标清理和提交后 credential 续写，并覆盖 DACL 创建/复核、Vault 原子替换后权限复核和普通 lock 文件路径。未覆盖突然断电、目录项 flush、真实 junction 创建权限差异和独立渗透测试。
