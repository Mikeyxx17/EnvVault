# Dotenv Migration V1

状态：严格解析、批量原子导入、value-free `.env.example` 生成和自动化测试已完成；真实平台文件权限与重解析点验收尚未完成。

## 命令

```text
envvault --vault <PATH> import [--dry-run] <SOURCE>
envvault --vault <PATH> example [--output <PATH>]
```

`example` 的默认输出是当前目录下 `.env.example`。输入源和输出路径可以进入 argv；Secret Value 不进入 argv、环境变量或 stdout/stderr。

## 严格解析子集

V1 支持：

- UTF-8，可选 UTF-8 BOM。
- 空行和以可选前导空白开始的 `#` 整行注释。
- `KEY=value` 与 `export KEY=value`。
- 未引号值；只有前面是空白的 `#` 才开始行尾注释，`value#suffix` 保留 `#suffix`。
- 单引号字面值。
- 双引号，以及 `\n`、`\r`、`\t`、`\\`、`\"` 五种显式转义。
- 空值，例如 `EMPTY=`。

V1 不执行：

- `$NAME`、`${NAME}` 环境变量展开。
- 命令替换或 shell 求值。
- 多行 quoted value 或 continuation。
- 非 UTF-8 字节值。
- shell `source` 的其他语法。

Key 必须匹配 `[A-Za-z_][A-Za-z0-9_]*`。重复 key、非法 key、NUL、无效 UTF-8、错误引号、未知转义和 quoted value 后的非注释数据都会让整份导入失败。错误只报告安全的行号，不包含 Value。

资源限制：单文件最大 1 MiB，最多 1,024 个 entry；Vault 和 Policy 的更低剩余容量仍会继续限制实际导入数量。

## 导入事务

每个 entry 都转换成独立 `(SecretName, SecretValue)`，`.env` 本身不会成为 Vault 对象或授权单元。

- 已存在且获得 `write` Allow 的名称：保留 SecretId，增加 revision 并替换 Value。
- 新名称：要求精确 Owner 的 `create_secret` 和 `manage_policy`，生成随机 SecretId，并增加 `list/exists/verify/write/delete` Allow rules。
- 已存在但没有 `write` Allow 的名称不会被覆盖；后续新建路径会因名称冲突而整批失败。
- 所有 metadata/value envelopes、revision、新 SecretId、新 Policy rules 和 Policy generation 在一次 Vault state commit 中落盘。
- 任一解析、授权、容量、加密、名称冲突、generation 或文件提交失败都不会留下部分 Secret 更新。

授权 Audit 发生在最终批量提交之前，因此一次最终失败的导入可能保留对应的 Allow/Deny 尝试事件。这是安全审计证据，不代表 Secret 已提交。

`import --dry-run` 使用同一套分类：对已有记录检查 `write`（可写则为 `replace`），否则在具有 `exists` 时把同名记为 `conflict`，其余为 `create`。若将创建新 Secret，仍要求 `create_secret` 与 `manage_policy`。预览只输出名称和动作，不含 Value；`committed: no`，源文件不变。有 `conflict` 的真正导入仍整批失败且不提交。

## 明文生命周期

- CLI 使用有界读取，源文件缓冲区在 drop 时清零。
- 解析中的 quoted/unquoted Value 中间字符串使用 zeroizing 缓冲区。
- 每个 Value 随后进入不实现 `Debug`、`Display`、`Clone` 或序列化的 `SecretValue`。
- 这些措施不能清除操作系统文件缓存、源文件磁盘块、备份、编辑器历史、交换文件或先前复制。

成功导入绝不修改或删除源 `.env`，并明确输出 `source_preserved: yes`，但不回显可能包含控制字符的源路径。用户必须自行治理源文件；EnvVault 不宣称能够安全删除它。

## `.env.example` 生成

- 只使用逐 Secret `list` Allow 后返回的名称。
- 名称按字典序排序，每行输出 `KEY=`。
- 不读取 Secret Value，也不输出 SecretId 或密文。
- 如果任一可见 Secret Name 不是合法 dotenv key，则整次生成失败，避免静默遗漏。
- 输出使用 `create_new`；已有文件绝不覆盖，写入失败会删除本操作拥有的未完成文件。

## 尚未完成

- Windows ACL、Unix 权限、符号链接/重解析点和父目录信任验证。
- 崩溃注入、磁盘写满和断电恢复验收。
- 大规模导入性能与并发压力测试。
- 长时 parser fuzz campaign、覆盖率趋势和更完整的 dotenv 语义属性测试。
- 安全源文件删除；该能力当前明确不提供。
