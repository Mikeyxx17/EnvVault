# Management CLI V1

状态：Phase 5 管理命令与 Phase 6 Profile、显式 use grant 和 runtime run 入口已实现并通过自动化测试。

## 已实现命令

```text
envvault --vault <PATH> init
envvault --vault <PATH> set <NAME>
envvault --vault <PATH> verify <NAME>
envvault --vault <PATH> list
envvault --vault <PATH> exists <NAME>
envvault --vault <PATH> remove <NAME>
envvault --vault <PATH> import <SOURCE>
envvault --vault <PATH> example [--output <PATH>]
envvault --vault <PATH> identity register --kind <application|ai-agent> --name <NAME> --credential-file <PATH>
envvault --vault <PATH> identity list
envvault --vault <PATH> identity rotate --caller-id <CALLER_ID> --credential-file <NEW_PATH>
envvault --vault <PATH> identity revoke --caller-id <CALLER_ID>
envvault --vault <PATH> profile create --output <PATH> <SECRET>...
envvault --vault <PATH> policy grant-use --caller-id <CALLER_ID> --profile <PATH>
envvault --vault <PATH> audit list
envvault --vault <PATH> audit migrate-v2
envvault audit serve-anchor --data-dir <DIR> --tls-cert <CERT.pem> --tls-key <KEY.pem>
envvault audit serve-anchor --data-dir <DIR> --allow-plaintext
envvault --vault <PATH> audit configure-anchor --endpoint https://127.0.0.1:7432 --token-file <PATH> --tls-ca <CERT.pem>
envvault --vault <PATH> audit configure-anchor --endpoint http://127.0.0.1:7432 --token-file <PATH> --allow-plaintext
envvault --vault <PATH> audit anchor-status
envvault --vault <PATH> run --profile <PATH> --credential-file <PATH> -- <PROGRAM> [ARG]...
```

`--vault` 是全局选项，也可以放在子命令之后。CLI 不接受 `--password`、`--value`、密码/Secret 环境变量或管道输入。

## Master Password 边界

- `init` 从已连接终端读取两次 Master Password 并确认一致。
- 其他命令从已连接终端读取一次。
- 输入期间终端回显关闭；默认完全隐藏，显式 `--masked-input` 时每个字符显示一个 `*`，因此会泄露输入长度。
- 没有终端时直接失败，不回退到参数、环境变量或标准输入。
- 密码进入 `MasterPassword` 后由 zeroizing 类型持有，不出现在成功输出和结构化错误中。
- `set` 在 Vault 成功解锁后，从同一类关闭回显的交互终端读取并确认两次 Secret Value；允许显式空值，但没有 argv、环境变量或 stdin fallback。
- `verify` 从同一终端读取预期值，只输出 `match`/`mismatch`，不显示或持久化预期值、真实值和匹配结果。

这能降低 shell history、进程列表、CI 日志和误重定向暴露风险，但不能阻止同权限调试器、终端劫持、键盘记录器或已被攻陷的进程读取密码。

## Credential 文件交付

`identity register` 和 `identity rotate` 要求显式提供新文件路径。V1 行为：

- 使用 `create_new`，已有文件绝不覆盖。
- 先 prepare Caller 并同步受保护 recovery 文档，再创建空目标、提交 Registry、写入并 `sync_all`。
- Unix 创建模式是 `0600`，读取时拒绝 group/other 权限。
- Windows 使用 protected DACL，只允许 Owner、Local System 和 Built-in Administrators；额外或继承 ACE 失败关闭。
- 下次 Owner 打开时重新校验 recovery credential 是否就是 Registry 当前 verifier 对应的凭据；不匹配时清理未提交的私有空目标，匹配时完成已提交的新 credential 写入。该判断同时适用于注册和保留 CallerId 的轮换。
- 原始 credential 不写入普通 stdout/stderr，但会以 Base64 出现在指定的 JSON credential 文件中。
- credential 的编码缓冲区和临时 Base64 字符串在 drop 时清零。

Credential 文件格式：

```json
{
  "format": "envvault-caller-credential",
  "version": 1,
  "caller_id": "00000000-0000-0000-0000-000000000000",
  "caller_kind": "application",
  "credential": "base64-encoded-32-byte-value"
}
```

该文件是明文认证证据，不是 keystore。任何能读取它的进程都可以冒充对应 Caller。用户必须把它当作 Secret 管理；当前版本仍不能用于真实凭证。

## 审计和授权

- CLI 不直接调用 Vault 明文或 Crypto API，只调用内部 Broker 应用服务。
- Owner 仍通过 Master Password 和认证 Identity Registry 建立身份。
- Identity 注册、列出、轮换和撤销仍执行精确 `manage_identity` 授权。轮换保留 CallerId 和既有 Policy，并在 Registry 提交后立即使旧 credential 失效。
- 新 Secret 的创建同时要求 Owner 的 `create_secret` 与 `manage_policy`，并在一次 Vault commit 中写入记录和该 SecretId 的精确 Owner 管理规则。
- 自动增加的规则只有 `list`、`exists`、`verify`、`write`、`delete`，不会授予 `use`、`read_plaintext` 或 `export`。旧 Vault 首次由 Owner 验证时只升级该 Owner/SecretId 的精确 `verify` grant。
- 已有 Secret 的 `set`、`exists`、`remove` 分别检查 `write`、`exists`、`delete`；名称只在对应 SecretId 获得 Allow 后于 Broker 内解密比较。
- `list` 仅输出获得逐 Secret `list` Allow 的名称，不输出 ID、Value 或密文。
- `import` 严格解析并把每个 key/value 作为独立 Secret 全有或全无地提交；不修改或删除源文件。
- `example` 只生成获得 `list` Allow 的合法 dotenv key，输出 `KEY=` 且拒绝覆盖已有文件。
- 新 Vault 的控制面/Secret 决策写入 Audit V2；`audit list` 需要独立 `read_audit` 权限，历史 Vault 只在显式 `audit migrate-v2` 后切换。默认仍是同盘 local mirror。`audit serve-anchor` 在独立数据目录启动 loopback CAS，默认要求 `--tls-cert`/`--tls-key`；`--allow-plaintext` 只用于测试。Token 绑定首次访问的 Vault，并写 value-free `access.jsonl`。`configure-anchor` 在 Owner 解锁后写入 Vault 旁 sidecar：`https://` 必须带 `--tls-ca`，`http://` 必须带 `--allow-plaintext`。之后轮换按 mandatory 失败关闭。`anchor-status` 只输出 mode、endpoint、token 路径、tls 状态、last-confirmed generation/digest 和是否存在回滚证据，不输出 token 或 Secret。这仍不是远程 WORM 或硬件锚点。
- `profile create` 只生成环境名到 SecretId 的 value-free 请求集合；`policy grant-use` 才执行显式精确授权。
- `run` 严格读取 credential、建立机器 `VerifiedCaller`，对 Profile 每个 SecretId 独立执行 `use` 和 Audit，全部 Allow 后才创建最小环境子进程。

## 恢复边界

Registry 与 credential 文件仍不具备真正的跨文件原子提交，但 recovery 文档关闭了可自动判定的正常进程崩溃窗口。恢复只接管本次操作创建的缺失/私有空目标；非空不匹配目标保留恢复证据并失败关闭。突然断电、目录项持久性和恶意并发替换仍需要故障注入验收。

Secret Name 按项目定义作为位置参数，并且授权后的 `list` 会把名称写入 stdout。名称可能进入 shell history、进程列表或重定向日志，因此 V1 调用方应使用不包含敏感内容的环境变量式名称；只有 Secret Value 受关闭回显输入保护。

## 尚未实现

- 真实低权限 Windows 账户、junction/race、跨卷和安装包 ACL 验收。
- 认证限流/expiry 的真实多进程与时钟操纵验收，以及更强进程证明。
- 真实 Windows 交互终端、ACL、崩溃和安装包验收。
- 删除后的 Policy rule garbage collection；当前失效的随机 SecretId rules 会保留且 SecretId 不复用。
- 物理安全删除；`remove` 不擦除旧磁盘块、备份或文件系统历史。
