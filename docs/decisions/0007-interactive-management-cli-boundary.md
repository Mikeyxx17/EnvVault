# ADR 0007: Interactive Management CLI Boundary

补充：Windows DACL、reparse point 拒绝和 credential recovery 已由 ADR 0011 实现；以下“未实现”描述保留为本 ADR 作出时的历史边界。

状态：Accepted
日期：2026-08-13

## 背景

内部 Broker 已能完成 Owner bootstrap 和 Application/AI Agent 身份管理，但没有可信用户入口。将 Master Password 放入参数、环境变量或可管道化标准输入会扩大进程列表、shell history、CI 和日志泄漏面。签发 credential 如果默认打印到终端，也容易进入滚屏、复制记录或重定向文件。

## 决策

- Master Password 只从连接的交互终端读取，关闭回显；`init` 必须二次确认。
- CLI 不提供 password 参数、password 环境变量或非终端 stdin fallback。
- 第一批命令限定为 `init` 和 `identity register/list/revoke`。
- CLI 通过应用服务调用 Broker，不直接调用 Crypto 或 Vault 明文接口。
- 注册必须指定 credential 文件；文件以 `create_new` 预留，禁止覆盖，也不把原始 credential 打印到 stdout/stderr。
- 正常写入失败时删除操作拥有的未完成文件并尝试撤销刚注册的 Caller。
- Unix 文件模式设为 `0600`；Windows ACL 未实现前不把 credential 文件称为平台安全存储。
- CLI 继续依赖 Vault 内认证 Audit 链，当前不额外声明外部 Audit sink。

## 影响

- 自动化脚本不能通过参数、环境变量或管道无交互解锁 Owner，这是有意的 V1 安全限制。
- CI 和 Application 使用需要后续 keystore、受限 IPC 或短期 capability 设计，不能通过增加 `--password` 绕过。
- Registry 与 credential 文件跨文件原子性不成立；正常错误会补偿撤销，进程崩溃窗口需要后续恢复协议。
- Windows 创建的 credential 文件只继承目录 ACL，因此当前能力仍不能用于真实 Secret。

## 复审条件

- 引入系统 keystore、IPC daemon 或无交互机器身份。
- 引入恢复日志以关闭 Registry/credential 文件崩溃窗口。
- 增加 Secret 和 dotenv 管理命令。
- 完成 Windows DACL 与重解析点防护。
