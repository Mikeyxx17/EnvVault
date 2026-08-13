# Examples

本目录用于不含真实凭证的最小使用示例。示例不能绕过 Broker 或弱化授权边界。

`secret-consumer.ps1` 是 Phase 7N 的最小运行时示例。它只确认环境变量
`TEST_TOKEN` 是否存在，不输出值：

```powershell
envvault --vault .\demo.vault run `
  --profile .\demo.profile.json `
  --credential-file .\demo.credential.json `
  -- powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\secret-consumer.ps1
```

从注册 Application 到授权和运行的完整过程见
[`program-consumption-walkthrough.md`](./program-consumption-walkthrough.md)。
