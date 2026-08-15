# Examples

本目录用于不含真实凭证的最小使用示例。示例不能绕过 Broker 或弱化授权边界。

`secret-consumer.ps1` / `secret-consumer.sh` / `secret-consumer.py` /
`secret-consumer.js` 是最小运行时示例。它们只确认环境变量 `TEST_TOKEN`
是否存在，不输出值。其他程序也一样：不要打开 Vault，只读已注入的环境变量。

Linux：

```bash
EV=./target/release/envvault
VAULT=./demo.vault
PROFILE=./demo-app.profile.json
CRED=./demo-app.credential.json

$EV --vault "$VAULT" run --profile "$PROFILE" --credential-file "$CRED" \
  -- bash ./examples/secret-consumer.sh

$EV --vault "$VAULT" run --profile "$PROFILE" --credential-file "$CRED" \
  -- python3 ./examples/secret-consumer.py

$EV --vault "$VAULT" run --profile "$PROFILE" --credential-file "$CRED" \
  -- node ./examples/secret-consumer.js
```

Windows：

```powershell
envvault --vault .\demo.vault run `
  --profile .\demo.profile.json `
  --credential-file .\demo.credential.json `
  -- powershell -NoProfile -ExecutionPolicy Bypass -File .\examples\secret-consumer.ps1
```

从注册 Application 到授权和运行的完整过程见
[`program-consumption-walkthrough.md`](./program-consumption-walkthrough.md)。
