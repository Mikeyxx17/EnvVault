# Test Fixtures

本目录只能保存明确标记的假凭证和非敏感测试数据，禁止放入任何真实 Secret。

`audit_v2/` 保存 canonical JSON、AAD 与 recovery manifest 固定向量。重复字节只是公开格式样本，不是有效生产密钥；V2 格式不得在不升级版本的情况下静默改写这些向量。
