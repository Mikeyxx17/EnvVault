# Independent Security Review Checklist V1

状态：Checklist 草案，尚未执行。本文件供独立评审人按域复核 EnvVault 的实现与证据，是 M1.4「独立人员复核」的验收前置件。评审只基于仓库代码、测试证据与运行记录；评审结论不构成自动化验证的替代。全部问题必须 value-free，禁止在评审材料中记录 Secret Value、credential、password 或密钥。

## 使用方式

- 每个检查项判定：`PASS` / `FAIL` / `N/A` / `BLOCKED`（缺少证据）。`BLOCKED` 不得折算为 `PASS`。
- 每个 `FAIL` / `BLOCKED` 必须登记 finding（见结论模板），并给出影响与建议处置。
- 评审完成标准：所有关键域（A/B/C/D）无 `FAIL`，其余域问题全部关闭或有明确跟踪。

## A. 密码学与密钥生命周期

| ID | 检查项 | 证据来源 |
|---|---|---|
| A1 | KDF 为 Argon2id，参数在允许范围内，salt 随机且不重用 | `src/crypto/kdf.rs` |
| A2 | AEAD 为 XChaCha20-Poly1305，envelope 绑定版本/域/关联数据，密文长度有界 | `src/crypto/aead.rs`、`src/vault/format.rs` |
| A3 | nonce 由 CSPRNG 生成；测试验证唯一性；无硬编码密钥/IV | `src/crypto/random.rs`、测试 |
| A4 | 密钥/密码/明文类型实现 zeroize 或等价清空；不实现 Display/普通 Debug/Clone 传播 | `src/crypto/password.rs`、`secret/value.rs` |
| A5 | Audit 使用独立密钥与独立 AAD 域；与 Vault/Policy 密钥域分离 | `src/vault/audit_v2.rs` |
| A6 | 常量时间比较用于 verifier/password 校验 | `src/crypto/digest.rs` |
| A7 | 无自定义密码学原语；全部依赖成熟 crate 且版本被审计 | `Cargo.toml`、`deny.toml` |

## B. 格式、解析与失败关闭

| ID | 检查项 | 证据来源 |
|---|---|---|
| B1 | 全部持久化格式严格解析（deny unknown fields、版本检查、长度上限、canonical 往返一致） | `src/vault/*`、`src/identity/*`、`src/policy/document.rs` |
| B2 | 损坏/篡改输入失败关闭，不部分接受 | 负向测试、fuzz corpus |
| B3 | 四个 fuzz target 的 campaign 记录与 crash 处置 | `fuzz/`、run records |
| B4 | parser 差分/属性测试存在且通过 | `tests/`、proptest |

## C. Broker 顺序与授权

| ID | 检查项 | 证据来源 |
|---|---|---|
| C1 | 每个请求完整携带 CallerId + CallerKind + SecretId + Operation；Profile/命令名/已解锁不替代决策 | `src/broker/service.rs`、`src/policy/engine.rs` |
| C2 | Audit 先落盘成功后才解密；Audit 失败阻止 Secret 发放 | Broker 测试 |
| C3 | 批量请求逐 Secret 决策，一个 Allow 不携带其他记录载荷 | Broker 批量测试 |
| C4 | Deny 时不读取记录载荷；Allow 只向 Vault 请求这一条 | Broker 测试、代码路径 |
| C5 | `Use` 与 `ReadPlaintext` 分离，各自独立授权与审计 | `src/policy/operation.rs` |
| C6 | 默认拒绝；无匹配规则即 Deny；Policy 解析失败关闭 | `src/policy/set.rs`、测试 |

## D. 身份、限流与过期

| ID | 检查项 | 证据来源 |
|---|---|---|
| D1 | 身份不信任自报 ID/路径/进程名；credential 随机、Argon2id verifier、可撤销可轮换 | `src/identity/*` |
| D2 | 90 天 expiry 严格（issued ≤ now < expires），窗口校验拒绝非 90 天 | `src/identity/registry.rs`、对抗性测试 |
| D3 | 限流持久化、时钟回拨不可绕过、全局可用性攻击有界 | 对抗性测试套件 |
| D4 | 认证尝试成功/失败均被审计且 value-free | `src/audit/event.rs` |

## E. 文件权限、路径与持久化

| ID | 检查项 | 证据来源 |
|---|---|---|
| E1 | Windows 敏感文件 protected DACL 设置并复核；Unix 强制 0600 | `src/secure_fs.rs` |
| E2 | 全路径组件检查；symlink/reparse point 拒绝；TOCTOU 竞态处理 | `src/secure_fs.rs`、测试 |
| E3 | 原子写（临时文件 + sync + rename + 目录语义）、锁与 lost-update 防护 | `src/vault/file.rs`、测试 |
| E4 | 恢复 manifest 状态机只能前进；删除仅限 operation-owned 临时文件 | `src/vault/audit_recovery.rs` |
| E5 | 三文件一致性（descriptor/segment/anchor）与 mandatory degraded fail-closed | `src/vault/audit_runtime.rs`、故障注入证据 |

## F. 供应链与工程卫生

| ID | 检查项 | 证据来源 |
|---|---|---|
| F1 | `cargo audit` 无已知漏洞；`cargo deny` license/bans/sources 通过 | CI 记录 |
| F2 | 禁止 unsafe；deny unwrap/expect/panic；clippy pedantic 通过 | `Cargo.toml` lint 配置、CI |
| F3 | 依赖来源可审计、版本锁定 | `Cargo.lock` |
| F4 | 文档安全声明与实现一致；无"绝对不会泄露"类错误承诺 | `docs/security/threat-model.md` |

## 结论模板

### Finding 登记

| 编号 | 域/ID | 严重度（Critical/High/Medium/Low/Info） | 描述（value-free） | 建议处置 | 状态 |
|---|---|---|---|---|---|
| F-01 | ... | ... | ... | ... | 打开/已修复/接受风险 |

### 评审结论

- 评审范围：`<commit 范围 / release 版本>`
- 关键域（A/B/C/D）结果：`<PASS/FAIL 统计>`
- 结论：`通过 / 有条件通过（列出条件）/ 不通过`
- 复审条件（如适用）：`<修复项、证据补交项、重审范围>`

### 签署

- 评审人：`<name / affiliation>`
- 复核人：`<name>`
- 评审时间（UTC）：`<ISO-8601>`
- 关闭时间（UTC）：`<ISO-8601>`

> 独立评审关闭是 M1.4 的硬条件；缺少本文件签署的评审记录，不得宣布生产安全验收完成。
