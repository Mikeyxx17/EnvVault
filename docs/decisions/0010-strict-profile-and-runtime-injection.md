# ADR 0010: Strict Profile References and Runtime Environment Injection

## 背景

Phase 6 需要实现 `envvault run --profile ... -- command`。Profile 只能表达目标程序需要哪些 Secret，不能因为文件中出现一个名称就授予权限。同时，Vault 中的 Secret Name 是加密 metadata；在 `use` 授权前扫描并解密所有名称会破坏 Broker 的逐 Secret 边界。

## 决策

- Profile V1 是严格、value-free、带版本的 JSON 文档。
- 每个 binding 保存一个可移植环境变量名和一个稳定 `SecretId`，不保存 Caller、Policy、credential 或 Secret Value。
- `profile create` 由 Owner 使用已有逐 Secret `list` 权限把名称解析成 ID，并以 `create_new` 写入新文件。
- `policy grant-use` 是独立 Owner 管理动作：它按 Profile 中每个精确 ID 为一个已注册 Caller 写入 `Operation::Use` Allow；Profile 解析本身不修改 Policy。
- `run` 必须同时提供 Profile 和已注册 Application/AI Agent credential 文件，并通过交互式 Master Password 解锁 Vault。credential 建立 `VerifiedCaller`，但不产生授权。
- Broker 对 Profile 中每个 ID 分别执行 `use` PolicyDecision 和 Audit。V1 采用整体失败：任何 Deny、缺失或读取失败都会阻止子进程启动，已经解密的临时值随错误路径释放并清零。
- 进程入口使用精确 argv，不引入 shell；先 `env_clear`，再重建固定平台启动变量白名单，最后注入已授权 bindings。
- 子进程退出码在可表示范围内原样返回；无正常退出码的平台状态返回 1。

## 影响

- 修改 Profile 只能扩大请求集合，不能扩大权限。
- Profile 中的稳定 ID 避免为了名称匹配而在授权前解密无关 metadata。
- Profile 文件不含 Value，但会暴露环境变量名称、SecretId 和应用依赖关系，应按项目 metadata 管理。
- 固定启动变量白名单比继承整个父环境更小，但 `PATH`、用户目录和工具链目录仍会进入目标进程；这是兼容本地开发工具的明确折衷。
- Rust 标准 `Command` 内部的环境副本不能保证逐字节 zeroize；EnvVault 只缩短用户态明文生命周期，不能声称进程环境是安全内存。

## 安全边界

`run` 不能阻止目标程序、插件、构建脚本或后代进程打印、上传或继续传播 Secret，也不能阻止同权限调试器和内存读取。能修改目标代码的 AI Agent 可以让目标程序泄露注入值。更强场景必须使用 Proxy、短期凭证、Capability 或 Human Approval。

## 复审条件

- 引入平台 keystore 后，复审是否仍需每次交互输入 Master Password。
- 引入受限 Capability 或代理后，复审是否允许不向进程提供通用明文值。
- 完成 Windows/Linux/macOS 真实进程、工具链和环境继承测试后，复审固定启动变量白名单。
