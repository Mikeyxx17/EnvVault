# EnvVault 项目定义

我要定义这个项目。请以本说明为当前项目的最高级需求，不要再把 EnvVault 理解成简单的 `.env` 加密器。

项目名称暂定：

**EnvVault**

项目定位：

> **EnvVault 是一个使用 Rust 开发的、面向本地开发者和 AI Coding Agent 的 Secret Manager 与 Secret Authorization Broker。**

核心目标不是保护某一种文件，而是：

> **统一保护开发过程中出现的 Secret，并精确控制“谁可以使用哪一条 Secret，以及可以执行什么操作”。**

---

# 1. 什么是 Secret

Secret 是不能公开、但程序运行时可能需要使用的敏感数据。

例如：

```text
OPENAI_API_KEY
DATABASE_URL
DATABASE_PASSWORD
JWT_SECRET
GITHUB_TOKEN
AWS_SECRET_ACCESS_KEY
SSH_PRIVATE_KEY
STRIPE_SECRET_KEY
```

`.env` 只是保存 Secret 的一种传统方式。

因此：

```text
.env != Secret

.env = Secret 的一种输入/存储格式
```

EnvVault 的管理对象应该是：

```text
Secret
```

而不是：

```text
.env 文件
```

---

# 2. 当前要解决的问题

传统项目可能存在：

```text
project/
├── src/
├── Cargo.toml
└── .env
```

其中：

```env
DATABASE_URL=...
JWT_SECRET=...
OPENAI_API_KEY=...
AWS_SECRET_ACCESS_KEY=...
```

这存在几个问题：

1. Secret 以明文长期存在于磁盘。
2. AI Coding Agent 可能读取 `.env`。
3. 一个 `.env` 中经常包含很多互不相关的 Secret。
4. 程序实际上只需要其中一部分，却可能得到整个 `.env`。
5. `.gitignore` 只能防止 Git 提交，不能阻止本地程序或 AI Agent 读取。
6. 不同程序不应该拥有相同的 Secret 权限。
7. AI Agent 不应该天然具有读取 Secret 明文的权限。

EnvVault 要解决这些问题。

---

# 3. 最核心的设计原则

整个项目必须围绕：

> **一个 Secret = 一个独立权限单元**

例如 Vault 中有：

```text
Secret A = DATABASE_URL
Secret B = JWT_SECRET
Secret C = OPENAI_API_KEY
Secret D = AWS_SECRET_ACCESS_KEY
```

某个应用：

```text
rust-backend
```

可能拥有：

```text
DATABASE_URL            ✅
JWT_SECRET              ✅
OPENAI_API_KEY          ❌
AWS_SECRET_ACCESS_KEY   ❌
```

即使 `rust-backend` 已通过身份验证，也不能因此访问整个 Vault。

必须针对每条 Secret 独立授权。

也就是说：

```text
Application authentication
            ↓
        只是确认是谁
            ↓
不能等于：
允许访问全部 Secret
```

真正的检查应该是：

```text
Caller
+
Secret
+
Operation
        ↓
Policy Engine
        ↓
Allow / Deny
```

---

# 4. Vault

Vault 是 Secret 的加密存储层。

例如：

```text
Vault
│
├── secret-001
│   └── DATABASE_URL
│
├── secret-002
│   └── JWT_SECRET
│
├── secret-003
│   └── OPENAI_API_KEY
│
└── secret-004
    └── AWS_SECRET_ACCESS_KEY
```

不要把：

```text
整个 .env
```

作为唯一的权限单位。

`.env` 导入后必须解析：

```text
.env
 ↓
Parser
 ↓
DATABASE_URL
JWT_SECRET
OPENAI_API_KEY
AWS_SECRET_ACCESS_KEY
 ↓
变成独立 Secret Record
 ↓
分别管理
```

Vault 内部应该围绕独立 `SecretRecord` 设计。

---

# 5. SecretRecord

设计类似：

```rust
struct SecretRecord {
    id: SecretId,
    name: String,
    encrypted_value: ...,
    metadata: ...,
}
```

具体结构请在架构设计阶段完善。

Secret ID 应该是内部稳定标识。

权限关系尽量不要完全依赖可修改的 Secret 名称。

---

# 6. Policy Engine

Policy Engine 是权限决策系统。

负责回答：

> 某个 Caller 是否可以对某条 Secret 执行某种 Operation？

模型类似：

```text
Caller
   +
Secret
   +
Operation
   ↓
Policy Engine
   ↓
ALLOW / DENY
```

例如：

```text
rust-backend
+
DATABASE_URL
+
use
=
ALLOW
```

但是：

```text
rust-backend
+
OPENAI_API_KEY
+
use
=
DENY
```

未来 Operation 可以包含：

```text
list
exists
use
read
write
delete
export
rotate
```

其中：

```text
use
```

和：

```text
read plaintext
```

概念上应当区分。

---

# 7. Secret Broker

应用程序不应该直接访问 Vault。

正确结构：

```text
Application
     ↓
Secret Broker
     ↓
Policy Engine
     ↓
Allow?
     ↓
Vault
     ↓
只获取被授权 Secret
     ↓
Application
```

Secret Broker 负责：

1. 接收 Secret 请求。
2. 获取 Caller Identity。
3. 调用 Policy Engine。
4. 如果授权失败，拒绝访问。
5. 如果授权成功，只获取对应 Secret。
6. 不应该因此解锁其他无关 Secret。
7. 记录必要的 Audit 信息。

Broker 可以一次处理多个 Secret 请求，但：

> **每一条 Secret 必须独立进行权限判断。**

例如应用请求：

```text
DATABASE_URL
JWT_SECRET
OPENAI_API_KEY
```

必须得到：

```text
DATABASE_URL   → ALLOW
JWT_SECRET     → ALLOW
OPENAI_API_KEY → DENY
```

最终只能获得前两条。

---

# 8. Identity

系统以后至少存在三类调用者：

```text
Human
Application
AI Agent
```

## Human

例如开发者本人。

可能允许：

```text
set
read
remove
export
policy management
```

---

## Application

例如：

```text
backend.exe
cargo run
node server.js
python app.py
```

应用应该只能获得明确授权的 Secret。

例如：

```text
backend
├── DATABASE_URL ✅
├── JWT_SECRET ✅
└── OPENAI_API_KEY ❌
```

---

## AI Agent

例如：

```text
Codex
Claude Code
Cursor Agent
```

AI Agent 默认应该采用更严格的权限。

例如：

```text
list Secret names     ✅
exists                ✅

read plaintext        ❌
export                ❌
decrypt vault         ❌
modify policy         ❌
```

后续再设计：

```text
Human Approval
Temporary Capability
Restricted Agent Identity
Audit
```

---

# 9. 一个重要安全问题

不要错误地认为：

```text
Agent 不能执行 envvault get
```

就意味着 Agent 无法获得 Secret。

例如如果允许：

```bash
envvault run -- cargo run
```

并把 Secret 注入环境变量：

```text
OPENAI_API_KEY
```

AI Agent 可以修改 Rust 代码：

```rust
println!("{}", std::env::var("OPENAI_API_KEY").unwrap());
```

再运行程序。

Secret 仍然可能泄露。

因此：

> `run -- command` 不是完整的 AI Secret 隔离机制。

第一阶段可以实现 Runtime Environment Injection，但必须在 Threat Model 中明确这个安全边界。

后续应研究更加安全的：

```text
Secret Broker
Capability
Proxy
Credential Brokering
Human Approval
Short-lived Credentials
```

等方案。

不要做“绝对不会泄露 Secret”的错误安全承诺。

---

# 10. .env 的角色

`.env` 只是迁移入口。

例如：

```bash
envvault import .env
```

流程：

```text
.env
 ↓
dotenv parser
 ↓
拆分 KEY=VALUE
 ↓
每个 KEY/VALUE 变成独立 Secret
 ↓
分别存入 Vault
```

导入：

```env
DATABASE_URL=AAA
JWT_SECRET=BBB
OPENAI_API_KEY=CCC
```

应该得到：

```text
Secret #1
DATABASE_URL → encrypted

Secret #2
JWT_SECRET → encrypted

Secret #3
OPENAI_API_KEY → encrypted
```

而不是：

```text
Secret #1
project.env → encrypted entire file
```

---

# 11. 第一阶段 Vault 安全

不要自行发明密码学算法。

考虑成熟 Rust crate，例如：

```text
Argon2id
XChaCha20-Poly1305
zeroize
secrecy
CSPRNG
```

密码学架构需要先设计再实现。

需要考虑：

```text
Master Password
        ↓
Argon2id
        ↓
Master Key
        ↓
Secret Encryption
```

第一版可以使用：

```text
Master Key
    ↓
分别加密 Secret A
分别加密 Secret B
分别加密 Secret C
```

后续可以研究：

```text
KEK
 ↓
Encrypted DEK-A → Secret A
Encrypted DEK-B → Secret B
Encrypted DEK-C → Secret C
```

但第一版不要过度设计。

---

# 12. 第一版 CLI

第一阶段建议：

```bash
envvault init
```

初始化 Vault。

```bash
envvault set OPENAI_API_KEY
```

添加 Secret。

```bash
envvault list
```

只列 Secret 名称，不显示 Value。

```bash
envvault exists OPENAI_API_KEY
```

检查是否存在。

```bash
envvault remove OPENAI_API_KEY
```

删除 Secret。

```bash
envvault import .env
```

把 `.env` 拆分成独立 Secret。

```bash
envvault example
```

生成只有 Key、没有 Secret Value 的 `.env.example`。

后续：

```bash
envvault run --profile backend -- cargo run
```

根据 Profile + Policy，仅将明确授权的 Secret 提供给目标进程。

---

# 13. Profile 与 Policy 不要混淆

例如：

```text
backend profile
```

表示：

```text
这个应用需要：

DATABASE_URL
JWT_SECRET
```

但 Profile 声明“需要”：

```text
!=
```

Policy 授权“允许”。

正确流程：

```text
Profile
 ↓
应用请求 A + B
 ↓
Policy Engine
 ↓
分别检查 A、B
 ↓
Broker
 ↓
只提供真正允许的 Secret
```

不要仅因为 Profile 写了一个 Secret 就自动授权。

---

# 14. Audit

后续需要 Audit 模块。

例如记录：

```text
Caller: rust-backend
Secret: DATABASE_URL
Operation: use
Decision: allow
Time: ...
```

但：

> Audit Log 绝对不能记录 Secret Value。

例如禁止：

```text
DATABASE_URL=postgres://user:password@...
```

日志只保存：

```text
Secret ID / Secret Name
Caller ID
Operation
Decision
Timestamp
```

---

# 15. EnvVault 不是什么

EnvVault 不是：

```text
❌ .env encrypt/decrypt wrapper
❌ password manager
❌ HashiCorp Vault clone
❌ Dotenvx Rust rewrite
❌ cloud secret manager
```

第一阶段也不做：

```text
AWS
Azure
GCP
Kubernetes
团队协作
Web UI
云同步
服务器集群
复杂 PKI
动态数据库凭证
```

项目首先保持：

> Local-first + Developer-first + AI-aware

---

# 16. 核心模块

初步模块：

```text
src/
├── cli/
├── crypto/
├── vault/
├── secret/
├── policy/
├── broker/
├── identity/
├── process/
├── dotenv/
├── audit/
├── config/
├── keystore/
└── error.rs
```

职责：

```text
crypto
→ 密码学

vault
→ Secret 加密存储

secret
→ Secret 数据模型

policy
→ Caller × Secret × Operation 权限决策

broker
→ Secret 请求、授权和发放

identity
→ Caller 身份

process
→ 子进程运行与环境注入

dotenv
→ .env 导入

audit
→ Secret 访问审计

keystore
→ 后续系统密钥库集成
```

---

# 17. 项目的安全原则

优先级：

```text
Security
>
Correctness
>
Maintainability
>
Usability
>
Features
```

核心原则包括：

```text
Least Privilege
Default Deny
Per-Secret Authorization
Explicit Identity
No Plaintext Logging
No Secret in CLI Arguments
Secure Memory Handling
Authenticated Encryption
Atomic Vault Writes
Clear Trust Boundaries
```

---

# 18. 项目最终核心模型

请始终围绕下面的模型进行设计：

```text
                     EnvVault
                        │
          ┌─────────────┴─────────────┐
          │                           │
        Vault                    Policy Engine
          │                           │
   encrypted secrets        Caller × Secret × Action
          │                           │
          └─────────────┬─────────────┘
                        ↓
                  Secret Broker
                        │
             ┌──────────┼──────────┐
             ↓          ↓          ↓
           Human    Application  AI Agent
```

其中最重要的是：

```text
Vault
= 保存 Secret

Policy Engine
= 决定谁能对哪条 Secret 做什么

Secret Broker
= 根据 Policy 处理 Secret 请求

Identity
= 判断请求者是谁
```

---

# 19. 项目的核心差异化

现有 Secret Manager 已经能够：

```text
存储 Secret
加密 Secret
权限管理
运行时注入
```

所以 EnvVault 不应该把这些当成唯一创新。

EnvVault 长期最重要的差异方向是：

> **AI Coding Agent 与本地开发 Secret 的安全共存。**

也就是研究：

```text
Human
→ 高权限

Application
→ 最小 Secret 权限

AI Agent
→ 默认极低权限
```

以及未来：

```text
Agent Identity
Human Approval
Temporary Capability
Secret Broker
Credential Proxy
Short-lived Credential
Audit
```

---

# 20. 当前你要做什么

现在不要直接开始实现完整项目。

先重新审查现有项目。

第一步完成：

1. 阅读当前代码。
2. 对照本需求，判断现有设计哪些可以保留。
3. 判断哪些设计仍然把 `.env` 当作核心对象，需要调整。
4. 判断 Vault 是否支持 Secret 独立记录。
5. 判断 Policy 是否真正支持：
   `Caller × Secret × Operation`。
6. 判断 Broker 是否职责清晰。
7. 判断 Identity 模型是否合理。
8. 分析 `run -- command` 的安全边界。
9. 更新 threat model。
10. 更新 architecture 文档。
11. 给出重构方案。
12. 给出新的完整目录结构。
13. 给出 Phase 0 ～ Phase N 的实施顺序。

现在不要大规模修改代码。

先给我一份：

```text
Current Architecture Assessment
Target Architecture
Gap Analysis
Threat Model Changes
Proposed Module Structure
Migration / Refactor Plan
Implementation Phases
```

等我确认架构之后，再开始修改核心代码。

项目最终目标：

> **EnvVault = 一个面向 AI Coding Agent 的本地 Secret 管理、细粒度授权与 Secret Broker 系统。**

最核心原则：

> **一个 Secret = 一个权限单元。**

以及：

> **程序通过身份验证，不代表它可以读取整个 Vault。**

必须始终遵守：

> **Caller × Secret × Operation → Policy Decision**