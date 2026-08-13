# Vault Format V1

## 状态

状态：Initial implementation format。

V1 是本地单文件、逐 Secret 加密格式。格式一旦被真实用户数据使用，任何不兼容修改都必须增加 `version`，不能静默改变现有字段语义。

## 密码学套件

```text
KDF:      Argon2id v=19
AEAD:     XChaCha20-Poly1305
Key:      32 bytes
Salt:     16 random bytes per Vault
Nonce:    24 random bytes per encrypted envelope
Random:   operating-system CSPRNG
Encoding: JSON container + RFC 4648 padded Base64
```

新建 Vault 的 Argon2id 参数：

```text
memory_kib  = 65536
iterations  = 3
parallelism = 1
```

参数保存在文件头中，以便未来迁移。读取器必须限制参数上下界，避免恶意文件请求无限内存或计算时间。

## JSON 容器

逻辑结构如下：

```json
{
  "format": "envvault",
  "version": 1,
  "generation": 1,
  "vault_id": "base64(16 bytes)",
  "kdf": {
    "algorithm": "argon2id",
    "version": 19,
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt": "base64(16 bytes)"
  },
  "aead": {
    "algorithm": "xchacha20poly1305"
  },
  "key_check": {
    "nonce": "base64(24 bytes)",
    "ciphertext": "base64(ciphertext + 16-byte tag)"
  },
  "identity": {
    "generation": 1,
    "envelope": {
      "nonce": "base64(24 bytes)",
      "ciphertext": "base64(ciphertext + 16-byte tag)"
    }
  },
  "policy": {
    "generation": 1,
    "envelope": {
      "nonce": "base64(24 bytes)",
      "ciphertext": "base64(ciphertext + 16-byte tag)"
    }
  },
  "audit": {
    "key_envelope": {
      "nonce": "base64(24 bytes)",
      "ciphertext": "base64(32-byte Audit key + 16-byte tag)"
    },
    "head_authenticator": "base64(16 bytes)",
    "events": [
      {
        "nonce": "base64(24 bytes)",
        "ciphertext": "base64(encrypted Audit event + 16-byte tag)"
      }
    ]
  },
  "records": [
    {
      "secret_id": "00112233-4455-6677-8899-aabbccddeeff",
      "revision": 1,
      "metadata_envelope": {
        "nonce": "base64(24 bytes)",
        "ciphertext": "base64(ciphertext + 16-byte tag)"
      },
      "value_envelope": {
        "nonce": "base64(24 bytes)",
        "ciphertext": "base64(ciphertext + 16-byte tag)"
      }
    }
  ]
}
```

JSON 中没有 Secret Name、Secret Value、Owner ID、明文 Policy 或明文 Audit event。名称和 Value 位于每条记录的两个独立加密载荷中，因此 `list` 只需解密已获授权记录的 metadata envelope，不需要把 Secret Value 带入内存。Identity、Policy 和 Audit 分别使用独立的认证域。

## Key Check Envelope

空 Vault 没有 Secret Record，不能通过尝试解密第一条记录验证密码。因此 V1 包含独立 `key_check` envelope。

它加密固定的格式标记，但使用独立随机 nonce。AAD 绑定：

```text
domain separator
+ format version
+ vault_id
+ KDF algorithm/version/parameters
+ KDF salt
```

密码错误、KDF 字段被修改、Vault ID 被修改或认证标签损坏时，都必须返回统一的 unlock/integrity failure，不能继续读取记录。

## Secret Record Envelope

每条 Secret 的 metadata 和 value 分别使用独立随机 nonce 和独立 AEAD 调用。AAD 绑定：

```text
domain separator
+ format version
+ vault_id
+ secret_id
+ record revision
+ envelope kind
```

这可以检测不同 Vault、不同 Secret ID 或不同 revision 之间的密文替换，但不能独立阻止攻击者把整个旧记录连同旧 revision 一起回滚。

## Policy Envelope

Policy payload 使用独立随机 nonce 和 AEAD 调用。AAD 绑定：

```text
domain separator
+ format version
+ vault_id
+ policy generation
```

Policy Document 内部 generation 必须与 envelope generation 完全相同。密文认证失败、文档解析失败或 generation 不一致都会使 Policy Engine 进入 `Invalid` 状态并默认拒绝全部请求。Policy 与 Secret 记录由同一个 Vault state 原子提交，但 V1 仍不能抵抗整个 Vault 文件的离线回滚。

## Identity Registry Envelope

新 Vault bootstrap 生成随机 Owner CallerId，并将严格版本化的 Identity Registry 放入独立 envelope。AAD 绑定格式版本、Vault ID 和 Identity generation。成功解锁 Master Password 后仍必须认证并严格解析该 envelope，才能产生 `VerifiedCaller(MasterPassword)`。

Registry 后续保存 Application/AI Agent 的 Argon2id credential verifier，但不保存原始 credential。同一路径已存在时初始化失败，因此不能通过重复 bootstrap 替换 Owner。Owner 身份本身不自动产生 Secret 或 Vault 级授权。

## Audit Chain

Vault 创建时生成独立 32-byte Audit key，并用 Master Key 认证加密。每个 Audit event 使用 Audit key、独立 nonce 和以下 AAD：

```text
domain separator
+ format version
+ vault_id
+ event sequence
+ previous event authenticator
```

Audit-key envelope 的 AAD 还绑定当前 event count 与 chain head，因此局部修改、重排、中间删除和只删除尾部会在打开 Vault 时失败。事件 payload 使用严格版本化格式，不包含 Secret Value。

限制：攻击者如果能恢复整个旧 Vault 文件（包含旧 key envelope、旧链头和旧事件），V1 内嵌 Audit 链仍无法检测这种完整文件回滚。Phase 7J 已让新 Vault 默认使用可归档、轮换并本地 CAS 锚定的 Audit V2 sidecar，历史 V1 可显式迁移；真正外部可信锚点仍未部署，因此完整文件回滚保护仍未成立。

## 加密载荷

解密后的 metadata 载荷为：

```text
4 bytes   magic = "EVSM"
1 byte    payload version = 1
2 bytes   name length, big endian
N bytes   UTF-8 Secret Name
```

解密后的 value 载荷为：

```text
4 bytes   magic = "EVSV"
1 byte    payload version = 1
4 bytes   value length, big endian
M bytes   Secret Value
```

限制：

- Secret Name 最大 255 UTF-8 bytes，并继续执行领域验证。
- Secret Value 最大 1 MiB。
- 载荷不得包含尾随字节。
- 所有长度计算必须使用 checked arithmetic。

## 文件更新

写入流程：

1. 获取同路径 `.lock` 协作锁。
2. 比较磁盘 `generation` 与内存基线，拒绝覆盖并发修改。
3. 在目标文件同目录写入临时文件。
4. `sync_all` 临时文件。
5. 原子提交，使读者只能看到旧文件或完整新文件。
6. 更新内存 generation。

V1 的 `generation` 只能检测协作进程的并发覆盖，不能防止离线攻击者回滚整个 Vault。可靠 rollback protection 需要文件外的可信单调状态。

## 解析规则

- 文件大小上限 64 MiB。
- 记录数上限 10,000。
- 拒绝未知格式、未知版本、未知算法和未知字段。
- 拒绝重复 Secret ID、revision 0、错误 Base64、错误固定长度和超长密文。
- 任何记录认证失败都将该记录视为损坏，不返回该记录明文。
- Policy envelope 认证失败或 payload 无效时 Broker 可打开 Vault 以报告 `Invalid` 状态，但所有授权决策必须 fail closed。
- Identity payload 最大 1 MiB；Audit event payload 最大 4 KiB，最多 100,000 条，并继续受 64 MiB Vault 文件上限约束。
- Audit key、事件链或链头认证失败时 Vault 打开失败。

## 当前平台限制

- 原子替换不能自动证明目录、ACL、备份和同步软件的安全性。
- `atomic-write-file` 在非 Unix 平台不保留原文件权限、ACL 或其他元数据；当前 `secure_fs` 会在每次最终替换后重新设置并复核 Windows protected DACL，但断电窗口和独立平台验收仍未完成。
- 叶子符号链接会被拒绝；父目录规范化不能抵抗拥有更高权限的并发文件系统攻击者。
- V1 直接使用 Master Key 加密各记录，尚未采用每记录 DEK/KEK。

## 参考实现来源

- RustCrypto Argon2: <https://docs.rs/argon2>
- RustCrypto ChaCha20Poly1305: <https://docs.rs/chacha20poly1305>
- zeroize: <https://docs.rs/zeroize>
- getrandom: <https://docs.rs/getrandom>
- atomic-write-file: <https://docs.rs/atomic-write-file>
