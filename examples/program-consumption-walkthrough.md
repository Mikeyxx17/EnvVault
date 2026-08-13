# Program Consumption Walkthrough

下面使用测试 Vault 和测试值演示程序如何获得 Secret，但不打印 Secret。
命令在项目根目录的 PowerShell 中执行。

## 1. 准备路径

```powershell
$envvault = ".\target\release\envvault.exe"
$vault = ".\demo.vault"
$credential = ".\demo-app.credential.json"
$profile = ".\demo-app.profile.json"
```

如果 `demo.vault` 中已经存在 `TEST_TOKEN`，不需要再次设置。否则执行：

```powershell
& $envvault --masked-input --vault $vault set TEST_TOKEN
```

Master Password 输入一次；Secret Value 输入两次确认。星号只表示收到输入，
数量会暴露长度。

## 2. 注册程序身份

```powershell
& $envvault --masked-input --vault $vault identity register `
  --kind application `
  --name demo-app `
  --credential-file $credential
```

记下输出中的 `caller_id`。credential 文件是明文认证证据，必须当作 Secret
保护，不能提交到版本控制。

## 3. 创建 value-free Profile

```powershell
& $envvault --masked-input --vault $vault profile create `
  --output $profile `
  TEST_TOKEN
```

Profile 只包含环境变量名和 SecretId，不包含 Secret Value。

## 4. 授予精确 use 权限

把 `<CALLER_ID>` 替换为注册时输出的真实 ID：

```powershell
& $envvault --masked-input --vault $vault policy grant-use `
  --caller-id <CALLER_ID> `
  --profile $profile
```

这只授权该 Application 使用 Profile 中列出的 Secret，不授予显示明文、写入、
删除或访问其他 Secret 的权限。

## 5. 通过 EnvVault 启动程序

```powershell
& $envvault --masked-input --vault $vault run `
  --profile $profile `
  --credential-file $credential `
  -- powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\secret-consumer.ps1
```

成功输出：

```text
TEST_TOKEN received: yes
```

示例程序只确认环境变量存在，不显示内容。EnvVault 在启动前验证 credential、
逐 Secret 检查 `use` 权限、写入 Audit，然后解密并注入获准环境变量。

如果已经启用 machine unlock，可增加 `--machine-unlock` 并省略 Master Password
交互；Application credential 和逐 Secret Policy 检查仍然保留。
