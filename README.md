# EnvVault

EnvVault 是一个使用 Rust 开发、面向本地开发者和 AI Coding Agent 的 Secret Manager 与 Secret Authorization Broker。

本项目的核心授权模型是：

```text
Caller × Secret × Operation → Policy Decision
```

每条 Secret 都是独立的存储与权限单元。调用者完成身份验证，不代表它可以访问整个 Vault。

## 当前状态

项目目前已经完成工程骨架、目标架构、初始威胁模型、核心领域类型、Vault V1/Crypto Envelope、精确匹配且默认拒绝的 Policy Engine，以及内部 Broker 第一版。Policy 和 Identity Registry payload 已进入 Vault 的独立 AEAD envelope；Broker 会逐 Secret 授权、先将事件写入认证 Audit 链，再仅解密 Allow 的记录。

Master Password Owner bootstrap、显式 Vault 管理规则、Application/AI Agent Identity Registry、受控 Secret 创建/替换/删除、Policy 更新/读取和 Audit 读取已有内部实现。CLI 已提供交互式 `init`、Secret `set/list/exists/verify/remove`、严格 dotenv `import`、value-free `example`、Identity 注册/列出/轮换/撤销，以及 Profile 创建、显式逐 Secret `use` grant 和 `run -- command` 最小环境注入；Master Password 与 Secret Value 不进入参数。敏感输入默认完全隐藏，可显式使用会泄露长度的 `--masked-input` 星号反馈；新密码和 Secret 会二次确认，`verify` 只返回 match/mismatch。

Windows 敏感文件专用 DACL、路径重解析点拒绝、credential 交付恢复日志、parser fuzz/property/负向泄漏测试、依赖/许可证/来源策略，以及 Audit V2 event/segment、Manifest V2、Descriptor V3 key envelopes、Broker/CLI 活动段、自动轮换/启动恢复、本地镜像 CAS、显式 V1→V2 迁移和 mandatory degraded 原语已完成第一版代码与本机验证。Windows Credential Manager、Linux Secret Service 与 macOS Keychain machine unlock adapter、可恢复代次轮换、显式 `run --machine-unlock`、成功/失败身份认证审计、持久化认证限流、Identity Registry V3 严格 90 天 credential expiry 和 value-free `session whoami` 也已接入；三平台真实凭据库验收、真正远程/硬件单调锚点（当前只有独立目录上的 loopback 参考 CAS，默认可选 rustls）、已实际运行的长期 fuzz campaign、对抗性进程终止/断电注入和独立安全验收仍未完成，因此当前版本仍不能用于保存真实 Secret。导入不会修改或安全删除源 `.env`；`run` 也不是阻止目标程序、同用户恶意进程或 AI Agent 泄漏 Secret 的沙箱。

项目最高级需求见 [EnvVault 项目定义.md](./EnvVault%20项目定义.md)，文档入口见 [docs/README.md](./docs/README.md)。在其他电脑上从源码构建见 [docs/构建说明.md](./docs/构建说明.md)。

## 工程结构

```text
EnvVault/
├── src/
│   ├── cli/          # 命令行接口与命令路由
│   ├── broker/       # Secret 请求编排和发放边界
│   ├── policy/       # Caller × Secret × Operation 决策
│   ├── identity/     # Human、Application、AI Agent 身份模型
│   ├── secret/       # 独立 Secret 领域模型
│   ├── vault/        # 加密存储与原子持久化边界
│   ├── crypto/       # 密码学原语封装
│   ├── process/      # 子进程和运行时注入
│   ├── profile/      # value-free 运行请求集合
│   ├── dotenv/       # .env 导入与示例生成
│   ├── audit/        # 不包含 Secret Value 的审计事件
│   ├── config/       # 非敏感配置
│   ├── keystore/     # 操作系统密钥库适配边界
│   ├── secure_fs.rs  # 敏感文件权限与安全路径边界
│   └── error.rs      # 统一错误模型
├── docs/             # 架构、安全、路线图和决策记录
├── tests/            # 跨模块与安全回归测试
├── fuzz/             # 独立 nightly libFuzzer targets
├── examples/         # 无真实凭证的使用示例
└── scripts/          # 可审查的开发辅助脚本
```
