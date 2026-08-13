# Policy Engine V1

## 核心决策

Policy V1 只支持精确规则：

```text
(CallerId + CallerKind) × SecretId × Operation × Effect
```

其中 `Effect` 是 `allow` 或 `deny`。没有 wildcard、前缀匹配、CallerKind 全局授权、Profile 自动授权或 Human 隐式绕过。

CallerKind 与 CallerId 一同进入匹配，避免同一个 ID 被错误解释为 Human、Application 或 AI Agent 时继承其他身份类别的授权。

Vault 控制面使用独立的精确模型：

```text
(CallerId + CallerKind) × VaultOperation × Effect
```

它不伪造 SecretId，也不改变所有 Secret 数据面请求必须逐条授权的原则。

## 决策优先级

对一个完整请求：

1. 查找 Caller、Secret 和 Operation 都完全相同的规则。
2. 如果存在任何匹配 `deny`，返回 `ExplicitDeny`。
3. 否则如果存在匹配 `allow`，返回 `Allow`。
4. 否则返回 `NoMatchingGrant`。

Policy source 缺失、损坏或无法解码时，`PolicyEngine` 不加载部分规则，而是对所有请求返回 `DefaultDeny`，并保留 `Missing` 或 `Invalid` 状态供后续 Audit 使用。

## Operation

V1 包含：

```text
list
exists
verify
use
read_plaintext
write
delete
export
rotate
manage_policy
```

这些 Operation 互不蕴含。例如：

- `use` 不允许 `read_plaintext`。
- `list` 不允许 `exists`。
- `exists` 不允许 `verify`；`verify` 也不允许读取明文。
- `write` 不允许 `delete` 或 `rotate`。
- Human 身份不自动允许 `manage_policy`。

Secret `manage_policy` 只表达针对某条 Secret 的管理。Vault 控制面另有：

```text
create_secret
manage_policy
manage_identity
read_audit
```

这些 VaultOperation 同样互不蕴含，且 Human/Owner 身份本身不产生授权。

## 批量请求

`evaluate_batch` 对每个 `AuthorizationRequest` 单独调用相同的精确决策，并返回绑定原请求的 `PolicyEvaluation`：

```text
Secret A → Allow
Secret B → NoMatchingGrant
Secret C → ExplicitDeny
```

绑定请求与决策是为了阻止上层把 Secret A 的 Allow 错用到 Secret B。

## Policy Document V1

Policy 文档是确定性、有版本的 JSON payload：

```json
{
  "format": "envvault-policy",
  "version": 1,
  "generation": 1,
  "rules": [
    {
      "effect": "allow",
      "caller_id": "11111111-1111-1111-1111-111111111111",
      "caller_kind": "application",
      "secret_id": "22222222-2222-2222-2222-222222222222",
      "operation": "use"
    }
  ],
  "vault_rules": [
    {
      "effect": "allow",
      "caller_id": "33333333-3333-3333-3333-333333333333",
      "caller_kind": "human",
      "operation": "manage_policy"
    }
  ]
}
```

解析器：

- 拒绝未知字段、未知格式和未知 Operation/Effect/CallerKind。
- 拒绝未知版本、generation 0 和完全重复规则。
- Secret rules 与 Vault rules 合计最多接受 10,000 条规则和 8 MiB payload。
- 以规范顺序编码，便于稳定测试和后续认证。

## 重要的持久化边界

Policy Document 编解码本身只验证结构，不验证来源真实性。Broker 集成层现已把 Policy payload 放入 Vault V1 的独立 AEAD envelope，并校验 envelope generation 与文档 generation 一致。

禁止直接把普通 JSON 文件当成可信 Policy，因为能修改文件的攻击者可以加入合法格式的 `allow`。当前 Broker 只激活从已解锁 Vault 的认证 envelope 解密并严格解码成功的 Policy。

认证持久化与 Windows protected DACL 第一版已完成自动化测试，但整个 Vault 文件的离线回滚保护、对抗性路径/断电测试和独立真实平台验收仍未完成。认证 Policy 不能被描述为完整生产授权保证。

## Bootstrap 边界

第一条 Vault `manage_policy` 权限如何建立是安全敏感的 bootstrap 问题。V1 不通过“所有 Human 默认管理员”绕过它。

当前 bootstrap：

- 随机生成唯一 Human Owner CallerId。
- 只允许在全新 Vault 路径执行。
- 为这个完整 Caller 精确写入 `create_secret`、`manage_policy`、`manage_identity` 和 `read_audit` Allow。
- Identity、规则、Audit key 与 Vault 一起原子、认证地提交。
- 已存在路径拒绝重复 bootstrap。

这些是显式 Policy rule，不是 Owner/Human 的代码级绕过。Policy 更新可以删除 Owner 自己的 grant；系统不会偷偷恢复权限。
