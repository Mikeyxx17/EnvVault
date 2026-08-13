# Module Dependency Rules

## 允许的主要依赖

箭头表示左侧模块可以使用右侧模块公开的类型或接口：

```text
cli      → broker, process, dotenv, keystore(unlock only), config, secure_fs, error
process  → broker, identity, secret, error
dotenv   → secret, error

broker   → identity, policy, secret, vault, keystore(management), audit, error
policy   → identity, secret
vault    → secret, crypto, secure_fs, error
audit    → identity, secret, policy, error

crypto   → error
keystore → crypto, secure_fs, platform credential-store API, error
secure_fs → operating-system filesystem permission APIs
config   → error
```

目前 `error` 是面向 CLI 的统一错误边界。随着实现增长，各安全模块应优先保留自己的结构化错误，再在外层转换，避免一个全局错误枚举反向耦合全部模块。

## 禁止的依赖和调用

以下路径即使“更方便”也不能出现：

```text
cli/application → crypto decrypt
cli/application → vault plaintext read
cli/commands    → platform credential-store API
policy          → vault or crypto
audit           → plaintext or encrypted payload
dotenv          → vault internal storage format
config          → Secret Value
identity        → implicit policy grant
profile         → automatic authorization
```

任何面向调用者的 Secret 获取都必须经过 Broker。Vault 不负责判断业务权限；Policy 不负责读取 Secret；Crypto 不知道 Caller、Policy 或 Secret 名称。

SHA-256 等具体密码学/摘要实现必须封装在 `crypto`；`vault` 只能调用窄的 digest 接口，不能让持久化模块散落具体算法 crate 的直接使用。

Audit V2 的 segment/anchor/descriptor 线格式和本地恢复协调属于 `vault`，因为 segment 承载加密 envelope，且三文件提交需要 Vault 协作锁；`audit` 仍只拥有 value-free `AuditEvent`，不得因此新增 `audit → crypto` 或 `audit → vault` 依赖。

## 避免循环依赖

- 模块接口由最接近该职责的模块拥有。例如 `PolicyEvaluator` 属于 `policy`，Vault 访问接口属于 `vault`。
- Broker 只依赖接口，不依赖平台细节。
- Windows 凭据管理器等实现放在 `keystore` 内部，不能让领域层依赖 Windows API。
- `cli` 的 machine-unlock 路径只能取得不透明 `MasterKey` 后交给 Broker 打开；Keystore 管理必须经过 Broker 的 `manage_keystore` Policy/Audit，不能在命令处理器中直接启用、轮换或禁用。
- Windows DACL 和 reparse point API 只允许出现在 `secure_fs`；`vault` 与 `cli` 只能调用其窄文件接口。
- 如果 `process` 与 `broker` 出现双向调用需求，应增加窄的请求/消费接口，而不是形成模块循环。

## Secret Value 传播规则

当后续引入明文类型时，传播范围必须满足：

1. Policy、Identity、Audit、Config 和 Dotenv 元数据接口永远不接收明文类型。
2. Vault 解密得到的明文只能交给已经授权的 Broker 消费路径。
3. 明文类型不得实现 `Display`、普通 `Debug`、`Clone` 或通用序列化。
4. 错误类型不得持有明文。
5. 批量结果不得因为一个 Allow 而携带其他记录的载荷。

## 代码评审检查

每次新增跨模块引用时必须回答：

- 该依赖是否绕过 Broker 或 Policy？
- 接口是否传递了完成职责所不需要的数据？
- 是否让 Secret Value 进入日志、错误或可复制类型？
- 失败时是否默认拒绝？
- 是否为每条 Secret 分别作出决策？
