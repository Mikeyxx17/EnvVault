# Real-runtime Matrix Evidence Template V1

本模板用于 [三平台真实运行矩阵 Runbook](./real-runtime-matrix-v1.md) 的逐项证据留档。所有字段 value-free：禁止出现 Secret Value、credential、password、密钥或密文。每条记录一个检查项、一个平台。

## 1. 环境

- 平台：`<windows | linux | macos>`
- OS 版本/补丁：`<uname -a / winver / sw_vers 输出摘要>`
- 文件系统（Vault 所在卷）：`<NTFS | ext4 | btrfs | APFS | ...>`
- 账户权限：`<admin | standard>`
- EnvVault 构建：`<release commit 前缀>`
- 执行时间（UTC）：`<ISO-8601>`

## 2. 检查项

- ID：`<A1..A8 / B1..B9 / C1..C6 / D1..D3>`
- 描述：`<检查项名称>`
- 前置状态：`<Vault 是否已建、keystore 状态、工作目录>`

## 3. 执行

- 命令序列：`<逐条命令，不含敏感参数>`
- 关键输出摘要：`<退出码、关键提示行（value-free）>`
- 完整日志路径：`<log 文件>`

## 4. 判定

- 判定：`pass | fail | blocked`
- 观察到行为：`<与判定标准的对比>`
- blocked 原因（如适用）：`<环境限制>`
- fail 影响（如适用）：`<安全影响>`

## 5. 处置

- [ ] pass：归档并更新矩阵进度表
- [ ] fail：转 issue（编号 `#<n>`），阻塞 M1.3 关闭直至复测通过
- [ ] blocked：记录原因，不折算为 pass

## 6. 签名

- 执行人：`<name>`
- 复核人：`<name>`
- 关闭时间（UTC）：`<ISO-8601>`

> 任何自动化通过都不能代替本矩阵的真实会话执行；本模板本身就是验收证据的一部分。
