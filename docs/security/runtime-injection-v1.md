# Runtime Injection V1

状态：Phase 6 核心实现和自动化测试已完成；真实平台工具链、ACL、调试器、崩溃与安装环境验收未完成。

## 使用流程

先创建 Application 或 AI Agent 身份并保存一次性 credential：

```text
envvault --vault <PATH> identity register --kind application --name backend --credential-file backend.credential.json
```

Owner 从自己获得 `list` 权限的 Secret 名称创建 value-free Profile：

```text
envvault --vault <PATH> profile create --output backend.profile.json DATABASE_URL JWT_SECRET
```

然后显式为已注册 Caller 授予 Profile 中每个精确 SecretId 的 `use`：

```text
envvault --vault <PATH> policy grant-use --caller-id <CALLER_ID> --profile backend.profile.json
```

最后以该 Caller credential 运行目标程序：

```text
envvault --vault <PATH> run --profile backend.profile.json --credential-file backend.credential.json -- cargo run
```

这些命令默认从关闭回显的交互终端读取 Master Password；Phase 7K～7L 的显式 `--machine-unlock` 可改用平台 credential store。Master Password、credential 和 Secret Value 都不能通过 argv 传入。

## Profile V1

```json
{
  "format": "envvault-profile",
  "version": 1,
  "bindings": [
    {
      "environment": "DATABASE_URL",
      "secret_id": "00000000-0000-0000-0000-000000000000"
    }
  ]
}
```

- Profile 不保存 Caller 或任何 Allow/Deny。
- 环境变量名必须匹配 `[A-Za-z_][A-Za-z0-9_]*`。
- 空 Profile、重复环境名、重复 SecretId、未知字段、未知版本、无效 ID、超过 64 KiB 或超过 1024 bindings 都整体拒绝。
- `profile create` 拒绝覆盖已有文件；Profile 是 value-free metadata，不是 credential 文件。

## 授权与失败语义

1. 严格读取 Profile 和 credential 文件。
2. 交互解锁 Vault，并使用 Registry verifier 认证 Application/AI Agent。
3. 对每个 Profile SecretId 独立执行 `Operation::Use` PolicyDecision 和无 Value Audit。
4. 只有该条 Allow 才从 Vault 读取该条 Value。
5. 任一 binding Deny、缺失、损坏或 Audit 失败时整体停止，不创建子进程。
6. 全部成功后才构造子进程环境。

`policy grant-use` 是独立显式管理命令。仅创建或编辑 Profile 永远不会新增授权。显式 Deny 不会被 grant 命令静默覆盖。

## 子进程环境

进程模块不调用 shell。它使用 `env_clear`，只保留固定平台启动白名单和已授权 bindings。

- Windows：`SystemRoot`、`WINDIR`、`ComSpec`、`PATHEXT`、`PATH`、`TEMP`、`TMP`、`USERPROFILE`、`LOCALAPPDATA`、`APPDATA`、`CARGO_HOME`、`RUSTUP_HOME`。
- 其他平台：`PATH`、`HOME`、`TMPDIR`、`LANG`、`CARGO_HOME`、`RUSTUP_HOME`。

白名单是兼容开发工具的折衷，不是对这些父环境值的真实性或机密性保证。V1 只接受能表示成 UTF-8 的 Secret 环境值。目标程序的 stdin/stdout/stderr 继续继承当前终端；如果目标程序打印 Secret，EnvVault 不会拦截。

## 明确不保证

- 不阻止目标程序、依赖、插件、构建脚本或后代进程读取并传播 Secret。
- 不阻止可修改目标代码的 AI Agent 让程序输出 Secret。
- 不阻止同权限调试器、内存读取、恶意动态库或管理员攻击。
- 不保证标准库 `Command` 内部环境副本被逐字节清零。
- 不代表真实 Windows/Linux/macOS、Cargo/Node/Python 工具链或安装包运行已验收。

因此 V1 只能称为“按精确授权进行最小集合运行时注入并减少长期明文落盘”，不能称为 Secret 隔离或防泄漏沙箱。
