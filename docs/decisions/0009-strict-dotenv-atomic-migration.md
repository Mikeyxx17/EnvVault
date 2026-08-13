# ADR 0009: Strict Dotenv Parsing and Atomic Migration

补充：parser fuzzing 第一版已由 ADR 0012 实现；长期 campaign 与真实磁盘故障测试仍未完成。

状态：Accepted
日期：2026-08-13

## 背景

`.env` 只是迁移输入，但其中每个 key 必须成为独立 Secret。调用 shell 或实现宽松、环境相关的解析会引入变量展开、命令执行、重复 key 覆盖和不可重复结果。逐条写入又会在中途失败时形成部分导入和不完整 Policy。

## 决策

- 使用项目内严格、无求值的 UTF-8 dotenv 子集，不调用 shell，不执行变量或命令展开。
- 重复 key 和任何格式错误都整份拒绝；错误不携带 Value。
- 输入限制为 1 MiB 和 1,024 entries；CLI 使用有界读取和 zeroizing 源缓冲。
- 已存在名称必须先通过该 SecretId 的 `write` 授权；新名称要求 `create_secret + manage_policy`。
- 新 Secret 获得同一精确 Owner 的 `list/exists/verify/write/delete`，不获得 `use/read_plaintext/export`；`verify` 由 Phase 7N 增补。
- 整批 Secret upsert 与可选 Policy 更新只进行一次 Vault state commit。
- 授权 Audit 可以先于最终 commit 持久化；最终失败不回滚安全审计证据。
- 导入不修改、不删除源文件，也不宣称安全擦除。
- `.env.example` 只从 `list` 授权后的合法 dotenv names 生成 `KEY=`，使用 `create_new` 拒绝覆盖。

## 影响

- 与依赖复杂 shell/dotenv 扩展的文件可能不兼容，需要用户先转换成受支持子集。
- V1 不支持任意二进制或非 UTF-8 Value。
- 无权写入的同名 Secret 导致整个导入失败，不会以新 ID 绕过授权。
- 导入失败后 Audit 中可能存在尝试记录，但 Vault 不存在部分 Secret commit。
- 源 `.env` 在成功后仍保持明文，用户必须另行治理。

## 复审条件

- 需要兼容新的 dotenv 语法或二进制 Value。
- 引入导入预览、显式 partial-success 模式或恢复日志。
- 完成 parser fuzzing、平台路径加固和真实磁盘故障测试。
