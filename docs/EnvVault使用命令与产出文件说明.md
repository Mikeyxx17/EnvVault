# EnvVault 使用命令与产出文件说明

版本：envvault 0.1.0（含 `envvault.json` 项目发现与 `uninstall`）  
配套示例：`examples/`（只检查环境变量是否注入，不打印值）

当前版本尚未完成生产安全验收，不能当作生产 Secret 保险柜。本文按本机可运行的 CLI 行为编写，不构成安全认证。

## 1. 这是什么

EnvVault 主要是命令行程序，不是必须常驻的后台服务。每次执行 `envvault`，进程启动、打开加密 Vault、按「调用者 × Secret × 操作」授权、写审计，然后退出。`run` 在授权通过后拉起子程序；子程序结束后 envvault 也结束。可选的 `audit serve-anchor` 会在独立数据目录启动一个只监听回环地址的 CAS 进程（默认 rustls），供 Audit 轮换确认使用；默认不启动，也不能当成远程保险柜。

可以把它想成 `git` 或 `cargo`：磁盘上有一份程序文件，每条命令调用一次。

| 对比项 | 传统 `.env` / 旧 CLI | 现在 |
|---|---|---|
| 密钥存放 | 项目目录明文 `.env` | 加密 Vault（Master Password 保护） |
| 程序如何拿到 | 自己读 `.env` | 由 `envvault run` 注入环境变量 |
| 谁能用哪条 | 拿到文件就能用全部 | 必须注册身份并精确授予 `use` |
| 每次是否写路径 | 要写 `--vault` / `--profile` / `--credential-file` | 有 `envvault.json` 后可用短命令 |
| 要不要常驻服务 | 不用 | 默认不用；可选 `audit serve-anchor` |

Release 二进制一般在仓库的 `target/release/envvault`，也可放到 `~/.local/bin/envvault`。若提示 `command not found`，检查 `PATH` 是否包含安装目录。

```bash
envvault --version
envvault --help
```

## 2. 像 Cargo 一样：`envvault.json`

项目根目录的 `envvault.json` 类似 `Cargo.toml`。envvault 从当前目录往上查找，读出默认 Vault、Profile、credential 路径和 `caller_id`。文件只含路径和 ID，禁止写入 Secret 值、密码或 credential 原文。

### 2.1 新项目不用手写

在项目根目录执行（不要加 `--vault`）：

```bash
cd /path/to/app
envvault init
envvault set TEST_TOKEN
envvault identity register --kind application --name my-app
envvault profile create TEST_TOKEN
envvault policy grant-use
envvault run -- ./my-app
```

会自动创建 `.envvault/`（Unix 权限 `0700`）、`.envvault/vault`、`envvault.json`，并确保 `.gitignore` 忽略 Vault 与 credential。

| 命令 | 自动写入 `envvault.json` 的字段 |
|---|---|
| `init`（未指定 `--vault`） | `vault`、默认 profile / credential 路径 |
| `identity register` | 顶层 `credential_file`、`caller_id` |
| `identity register --as backend` | `targets.backend` 的 `credential_file`、`caller_id`（不改顶层默认） |
| `profile create` | 顶层 `profile` |
| `profile create --as backend` | `targets.backend` 的 `profile` |

只有「已有旧 Vault」或「想换默认文件名」时才需要手写。相对路径不能含 `..`，也不能写绝对路径。

### 2.2 短命令与长命令

有 `envvault.json` 时：

```bash
envvault list
envvault run -- ./my-app
```

一个项目多个程序时，用 `--as` 写到 `targets`，不要覆盖默认项：

```bash
envvault --as backend identity register --kind application --name backend
envvault --as backend profile create DATABASE_URL JWT_SECRET
envvault --as backend policy grant-use
envvault --as backend run -- ./server

envvault --as agent identity register --kind ai-agent --name coding-agent
envvault --as agent profile create DATABASE_URL
envvault --as agent policy grant-inspect
```

`--as` 只对 `identity register`、`profile create`、`policy grant-use` / `grant-inspect` / `revoke-use`、`run`、`session` 有效。目标名只能是字母、数字、`-`、`_`。

仍可用长参数覆盖默认值或某个 target：

```bash
envvault --vault ./.envvault/vault run \
  --profile ./.envvault/app.profile.json \
  --credential-file ./.envvault/app.credential.json \
  -- ./my-app
```

## 3. 全局选项与输入规则

| 选项 | 作用 |
|---|---|
| `--vault <PATH>` | 指定 Vault；可省略，改用 `envvault.json` |
| `--as <NAME>` | 选用 `targets.NAME`；不改顶层默认 |
| `--format json` | 列表/预览类命令输出 JSON，不含 Value |
| `--masked-input` | 输入时显示 `*`，会暴露长度；默认完全隐藏 |
| `--help` / `-h` | 帮助 |
| `--version` / `-V` | 版本 |

没有 `--password`、`--value`，也不能用环境变量或管道喂密码。

- `init`：终端里输入两次 Master Password。
- 其他需解锁的命令：输入一次。
- `set`：解锁后再输入两次 Secret 值。
- `verify`：再输入一次预期值，只打印 `match` / `mismatch`。
- 没有连接终端（非 TTY）时直接失败。

文档里的 `<CALLER_ID>` 表示换成真实 ID，不要把尖括号打进去，否则 bash 会当成重定向。有 `envvault.json` 后，`grant-use` 通常不必再写 `caller_id`。

## 4. 命令详解

### 4.1 `init`

```bash
envvault init
envvault --vault ./.envvault/vault init
```

创建新的加密 Vault 和 Owner。不加 `--vault` 时在当前目录创建 `.envvault/vault`、写入 `envvault.json`（已存在则不覆盖），并确保 `.gitignore` 含 `.envvault/` 与 `*.credential.json`。已有 `.gitignore` 只追加缺的行，不覆盖你自己的规则。不能对已存在的 Vault 再 `init`。指定 `--vault` 时不写项目文件和 `.gitignore`。

### 4.2 Secret 管理

```bash
envvault set TEST_TOKEN
envvault list
envvault list --verbose
envvault exists TEST_TOKEN
envvault verify TEST_TOKEN
envvault rename OLD_NAME NEW_NAME
envvault remove TEST_TOKEN
envvault change-password
```

名称在命令行，值只从终端读。新 Secret 自动给 Owner `list` / `exists` / `verify` / `write` / `delete`，不会自动给 `use`。程序要用，必须另外 `policy grant-use`。`list --verbose` 额外打印 SecretId 和被授了 `use` 的 caller（管理标签或 ID），不含 Value。`rename` 只改名称，SecretId 和值不变。`change-password` 先输当前 Master Password，再输两次新密码；会重加密整个 Vault，若开了 machine unlock 会尝试轮换包装。`remove` 不擦除磁盘旧块。

### 4.3 `import` / `example`

```bash
envvault import --dry-run ./.env
envvault import ./.env
envvault example --output ./.env.example
envvault example --profile ./.envvault/app.profile.json
```

把严格 dotenv 拆成独立 Secret，或生成不含值的 `.env.example`。默认 example 包含所有你能 `list` 的名字；`--profile` 或 `--as` 只输出该 Profile 里的环境变量键。`--dry-run` 只预览每条是 `create` / `replace` / `conflict`，不写 Vault、不改源文件。`conflict` 表示这个名字已存在但当前身份没有 `write`。真正 `import` 绝不修改、删除源 `.env`，成功时打印 `source_preserved: yes`。导入后明文仍在源文件里，必须自己删掉。`init` / `set` / `import` / `identity register` / `profile create` / `grant-use` 成功后会打一行 `next:`，提示下一步。

### 4.4 Identity

```bash
envvault identity register --kind application --name my-app
envvault identity list
envvault identity rotate --caller-id <ID> --credential-file ./.envvault/my-app.credential.next.json
envvault identity revoke --caller-id <ID>
```

`--kind` 只能是 `application` 或 `ai-agent`。`register` 省略 `--credential-file` 时写到 `.envvault/<name>.credential.json`，并把 `caller_id` 写入 `envvault.json`。credential 是明文认证证据（Unix `0600`），能读就能冒充该程序。新 credential 严格 90 天，到期必须 `rotate`；`rotate` 要换一个还不存在的文件名。

### 4.5 Profile 与授权

```bash
envvault profile create TEST_TOKEN
envvault policy grant-use
envvault policy grant-inspect
envvault policy list
envvault policy revoke-use --secret OPENAI_API_KEY
```

Profile 只是环境变量名到 SecretId 的请求清单，不授予权限。`grant-use` 才把 Profile 里每条 Secret 的 `use` 精确授予该 Caller，之后 `run` 才能注入。`grant-inspect` 只授 `list` 和 `exists`，不授 `use`，适合 AI Agent 查看名字而不拿值。`policy list` 打印当前规则（caller、名字、操作、allow/deny），不含 Secret 值；有 `list` 权限的 Secret 显示名称，否则只显示 SecretId。`revoke-use` 只收回 `use`：给了 `--secret` 就按名称收，否则按 Profile（或 `envvault.json` 默认 Profile）整批收。身份和其它授权都还在。未授权就 `run` 会得到 `the requested Secret is unavailable`。

### 4.6 `run`

```bash
envvault run -- ./my-app
envvault run --dry-run
envvault run --machine-unlock -- ./my-app
envvault completions bash
```

`--` 后面是精确 argv，不经过 shell。会清空父进程环境。Linux 只保留 `PATH`、`HOME`、`TMPDIR`、`LANG`、`CARGO_HOME`、`RUSTUP_HOME`，再加上授权过的变量。子程序只读环境变量，不要读 Vault 或 credential。`run --dry-run` 只打印每个环境变量键会是 `inject` / `deny` / `missing`，不启动程序、不解密 Value。未授权是 `the caller is not authorized...`，Profile 里的 Secret 已删除是 `not present in the Vault`，credential 过期是 `caller credential has expired`。`run` 不是沙箱。`completions` 打印 bash/zsh/powershell 补全脚本，不列举 Secret 名。

### 4.7 Audit / Keystore / Session

```bash
envvault audit list
envvault audit list --secret DATABASE_URL --operation use
envvault audit migrate-v2
envvault audit serve-anchor --data-dir /var/lib/envvault-anchor \
  --tls-cert /var/lib/envvault-anchor/cert.pem \
  --tls-key /var/lib/envvault-anchor/key.pem
envvault audit configure-anchor --endpoint https://127.0.0.1:7432 \
  --token-file /var/lib/envvault-anchor/token.json \
  --tls-ca /var/lib/envvault-anchor/cert.pem
envvault audit anchor-status
envvault keystore enable
envvault keystore status
envvault session whoami
envvault session --machine-unlock whoami
```

`audit list` 输出不含 Secret 值的事件。新 Vault 默认 Audit V2。`keystore` 走操作系统钥匙库，EnvVault 自己不常驻。`serve-anchor` 在独立目录启动只监听回环地址的 CAS，默认要求 TLS 证书和私钥，证书 SAN 必须包含 `DNS:localhost`。可用 openssl 自签仅供本机参考：

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout /var/lib/envvault-anchor/key.pem \
  -out /var/lib/envvault-anchor/cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

`--allow-plaintext` 只用于测试。Token 第一次成功访问后只绑定那个 Vault，服务端写 `access.jsonl`（不含 token）。`configure-anchor` 需要 Owner 密码；`https://` 必须带 `--tls-ca`，`http://` 必须带 `--allow-plaintext`。之后 Audit 轮换按 mandatory 失败关闭。`anchor-status` 不需要密码，只打印 mode、endpoint、token 路径、tls 状态、last-confirmed generation/digest 和 rollback_evidence。这仍不是远程 WORM 或硬件锚点。

### 4.8 `uninstall`

```bash
envvault uninstall
envvault uninstall --purge-project
```

默认只删除 `~/.local/bin/envvault`，保留各项目 Vault。`--purge-project` 还删除当前项目的 `.envvault/` 和 `envvault.json`。需要在终端输入确认词 `uninstall`，purge 还要再输入 `purge`。不删除源码仓库，也不安全擦盘。程序已不在 PATH 时可用 `scripts/uninstall.sh`。

## 5. 密钥会不会一直有效

| 对象 | 是否过期 | 说明 |
|---|---|---|
| 上游服务颁发的密钥 | 由对方决定 | 撤销或轮换后需再 `set` |
| Vault 里的 Secret | 不过期 | 直到 `set` 覆盖或 `remove` |
| Application credential | 严格 90 天 | 到期 `identity rotate`，Policy 可保留 |
| `grant-use` | 不自动消失 | `policy revoke-use` 收回单条；`identity revoke` 废掉整个身份 |
| Master Password | 不过期 | 每次命令或 machine-unlock 时使用 |

## 6. 产出文件

sidecar 文件名 = Vault 路径字符串直接拼接后缀。

### 6.1 项目与你指定的文件

| 文件 | 谁创建 | 里面有什么 | 能否提交 git |
|---|---|---|---|
| `envvault.json` | `init` 或手写 | 相对路径和 `caller_id`，不含密钥 | 可以 |
| `.envvault/vault` | `init` | 加密 Secret、Policy、Identity | 否 |
| `.envvault/*.credential.json` | `identity register` / `rotate` | 明文 credential | 否 |
| `.envvault/*.profile.json` | `profile create` | 环境变量名和 SecretId | 一般不提交 |
| `.env.example` | `example` 或手写 | 只有 `KEY=` | 可以 |
| `.env` | 你自己 | `import` 源。EnvVault 不会删除 | 否 |

### 6.2 Vault 同目录 sidecar

| 文件名模式 | 何时出现 | 作用 |
|---|---|---|
| `*.vault.lock` | 打开 Vault | 防并发写 |
| `*.vault.audit-descriptor-v3.json` | `init` / 迁移 | Audit 目录 |
| `*.vault.audit-active-v2-<段号>.json` | 写审计 | 当前活动段 |
| `envvault-audit-segment-<段号>.json` | 段写满轮换 | 已封存历史段 |
| `*.vault.audit-anchor-v2.json` | 本地锚点确认 | 同盘 CAS，不抗整盘回滚 |
| `*.vault.audit-anchor-client.json` | `audit configure-anchor` | 指向 loopback CAS 的 endpoint 和 token 路径 |
| `*.vault.audit-anchor-confirmed.json` | 远程 CAS 确认后 | last-confirmed generation 与 digest |
| `*.vault.audit-anchor-rollback.json` | 检测到服务端回滚 | 期望 vs 观察到的 generation/digest |
| `*.vault.audit-rotation-recovery.json` | 轮换中途 | 正常完成后应消失 |
| `*.vault.audit-migration-v2.json` | `migrate-v2` 中途 | 完成后应删除 |
| `*.vault.machine-unlock-v1.json` | `keystore enable` | 系统钥匙库绑定，不含 Master Key 明文 |
| `*.vault.credential-delivery.json` | register/rotate 崩溃 | 交付恢复；成功后删除 |

备份：Vault + descriptor + 所有 segment + 若存在的本地/确认锚点 sidecar。独立 CAS 数据目录和 token 文件要单独备份，且不要和 Vault 放在同一回滚域里才有意义。credential 当 Secret 保管。`.lock`、profile、`envvault.json` 可重建。

## 7. 常见报错

| 现象 | 原因 | 怎么办 |
|---|---|---|
| `envvault: command not found` | `PATH` 没有安装目录 | 把二进制放到 `PATH` 里的目录 |
| `no Vault path` | 找不到 `envvault.json`，也没写 `--vault` | `cd` 到项目根，或 `init`，或加 `--vault` |
| `project default path is missing` | 没有默认 profile / credential | 先 `register` / `profile create`，或显式传路径 |
| `No such file or directory`（caller_id 一行） | 写了 `<uuid>` | 去掉尖括号，或用短命令 `grant-use` |
| `the requested Secret is unavailable` | 没 `grant-use` | `envvault policy grant-use` |
| 子程序报环境变量缺失 | 直接启动，未经 `envvault run` | `envvault run -- <程序>` |
| Password input unavailable | 非 TTY | 在真正的终端输入 |
| credential 已存在 | register/rotate 拒绝覆盖 | 换一个新文件名 |
| 90 天后 `run` 失败 | credential 到期 | `identity rotate` 到新文件 |

## 8. 明确做不到的事

- 不能当已验收的生产保险柜。
- `run` 不能阻止子程序把密钥打出去。
- `import` 不会安全删除源 `.env`。
- `remove` / `uninstall --purge-project` 不会擦除磁盘历史块。
- machine unlock 不能防同一操作系统用户下的其它进程。
- 本地镜像 Audit 不能防整盘回滚。loopback 参考 CAS（即使开了 rustls）也不能防同机整体回滚，更不是远程 WORM 或硬件锚点。
- 没有 SDK：其它语言不要自己解密 Vault。
- `envvault.json` 不能代替 credential；丢了 json 只是丢了默认路径。
- `uninstall` 不删除源码仓库，也不扫描整盘上的其它 Vault。
