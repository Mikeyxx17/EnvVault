# EnvVault 使用命令与产出文件说明

版本：envvault 0.1.0（含 `envvault.json` 项目发现与 `uninstall`）  
配套示例：`examples/`（只检查环境变量是否注入，不打印值）

当前版本尚未完成生产安全验收，不能当作生产 Secret 保险柜。本文按本机可运行的 CLI 行为编写，不构成安全认证。

## 1. 这是什么

EnvVault 是命令行程序，不是后台服务。每次执行 `envvault`，进程启动、打开加密 Vault、按「调用者 × Secret × 操作」授权、写审计，然后退出。`run` 在授权通过后拉起子程序；子程序结束后 envvault 也结束。

可以把它想成 `git` 或 `cargo`：磁盘上有一份程序文件，每条命令调用一次。

| 对比项 | 传统 `.env` / 旧 CLI | 现在 |
|---|---|---|
| 密钥存放 | 项目目录明文 `.env` | 加密 Vault（Master Password 保护） |
| 程序如何拿到 | 自己读 `.env` | 由 `envvault run` 注入环境变量 |
| 谁能用哪条 | 拿到文件就能用全部 | 必须注册身份并精确授予 `use` |
| 每次是否写路径 | 要写 `--vault` / `--profile` / `--credential-file` | 有 `envvault.json` 后可用短命令 |
| 要不要常驻服务 | 不用 | 也不用 |

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

会自动创建 `.envvault/`（Unix 权限 `0700`）、`.envvault/vault` 和 `envvault.json`。

| 命令 | 自动写入 `envvault.json` 的字段 |
|---|---|
| `init`（未指定 `--vault`） | `vault`、默认 profile / credential 路径 |
| `identity register` | `credential_file`、`caller_id` |
| `profile create` | `profile` |

只有「已有旧 Vault」或「想换默认文件名」时才需要手写。相对路径不能含 `..`，也不能写绝对路径。

### 2.2 短命令与长命令

有 `envvault.json` 时：

```bash
envvault list
envvault run -- ./my-app
```

仍可用长参数覆盖默认值：

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

创建新的加密 Vault 和 Owner。不加 `--vault` 时在当前目录创建 `.envvault/vault` 并写入 `envvault.json`（已存在则不覆盖）。不能对已存在的 Vault 再 `init`。

### 4.2 Secret 管理

```bash
envvault set TEST_TOKEN
envvault list
envvault exists TEST_TOKEN
envvault verify TEST_TOKEN
envvault remove TEST_TOKEN
```

名称在命令行，值只从终端读。新 Secret 自动给 Owner `list` / `exists` / `verify` / `write` / `delete`，不会自动给 `use`。程序要用，必须另外 `policy grant-use`。`remove` 不擦除磁盘旧块。

### 4.3 `import` / `example`

```bash
envvault import ./.env
envvault example --output ./.env.example
```

把严格 dotenv 拆成独立 Secret，或生成不含值的 `.env.example`。`import` 绝不修改、删除源 `.env`，成功时打印 `source_preserved: yes`。导入后明文仍在源文件里，必须自己删掉。

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
```

Profile 只是环境变量名到 SecretId 的请求清单，不授予权限。`grant-use` 才把 Profile 里每条 Secret 的 `use` 精确授予该 Caller。未授权就 `run` 会得到 `the requested Secret is unavailable`。

### 4.6 `run`

```bash
envvault run -- ./my-app
envvault run --machine-unlock -- ./my-app
```

`--` 后面是精确 argv，不经过 shell。会清空父进程环境。Linux 只保留 `PATH`、`HOME`、`TMPDIR`、`LANG`、`CARGO_HOME`、`RUSTUP_HOME`，再加上授权过的变量。子程序只读环境变量，不要读 Vault 或 credential。`run` 不是沙箱。

### 4.7 Audit / Keystore / Session

```bash
envvault audit list
envvault audit migrate-v2
envvault keystore enable
envvault keystore status
envvault session whoami
envvault session --machine-unlock whoami
```

`audit list` 输出不含 Secret 值的事件。新 Vault 默认 Audit V2。`keystore` 走操作系统钥匙库，EnvVault 自己不常驻。

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
| `grant-use` | 不自动消失 | `revoke` 或改 Policy 才会没 |
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
| `*.vault.audit-rotation-recovery.json` | 轮换中途 | 正常完成后应消失 |
| `*.vault.audit-migration-v2.json` | `migrate-v2` 中途 | 完成后应删除 |
| `*.vault.machine-unlock-v1.json` | `keystore enable` | 系统钥匙库绑定，不含 Master Key 明文 |
| `*.vault.credential-delivery.json` | register/rotate 崩溃 | 交付恢复；成功后删除 |

备份：Vault + descriptor + 所有 segment + 若存在的 anchor。credential 当 Secret 保管。`.lock`、profile、`envvault.json` 可重建。

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
- 本地镜像 Audit 不能防整盘回滚。
- 没有 SDK：其它语言不要自己解密 Vault。
- `envvault.json` 不能代替 credential；丢了 json 只是丢了默认路径。
- `uninstall` 不删除源码仓库，也不扫描整盘上的其它 Vault。
