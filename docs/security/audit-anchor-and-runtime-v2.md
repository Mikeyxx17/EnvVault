# Audit V2 Anchor and Runtime Integration

状态：Phase 7I/7J 的本地实现和自动化验证已完成。Broker/CLI 使用 Audit V2 sidecar、活动段阈值轮换、启动恢复、本地镜像 CAS、显式 V1→V2 迁移和 mandatory degraded fail-closed 已有代码证据。远程/硬件 anchor、目录级断电 durability 和独立安全评审未完成。

## AnchorSink 与 CAS

`AnchorSink` 只接受 canonical Anchor V2 bytes，并提供读取与 exact expected-generation compare-and-set。实现必须验证：

- proposed generation 等于 expected + 1；
- vault id 不变，segment id 和 sequence 单调增加；
- generation 1 predecessor 为零；后续 predecessor 等于当前 canonical anchor bytes 的 SHA-256；
- 相同 canonical bytes 的响应丢失重试视为 `AlreadyApplied`；同 generation 的不同状态视为 conflict。

当前 `LocalMirrorAnchorSink` 写 `<vault>.audit-anchor-v2.json`，使用私有文件、sidecar lock 和原子替换。它能验证协议、发现误损坏和本地不一致，但与 Vault 位于同一回滚域，不能声称抵抗同盘整体回滚。

mandatory sink 的读/CAS 失败会保留 recovery manifest。后续打开或 Audit 写入识别该 manifest，返回 degraded 错误，不通过本地镜像静默降级。当前 CLI 默认使用 `local_mirror`，尚无用户可配置的远程 mandatory sink。

## Broker 与活动段

新 Vault 创建 Descriptor V3 和随机 active key envelope。Broker 的 Policy decision 形成 value-free `AuditEvent` 后：

1. 在 Vault lock 下验证 descriptor 和活动 key；
2. 认证读取现有活动段，或构造第一条事件；
3. 原子提交活动段 bytes，再推进 descriptor head；
4. descriptor 落后而活动文件领先时，重启校验整段后只允许向前对账；
5. Audit 成功后才调用可选外部 sink，并继续 Secret 操作。

达到 1024 个事件、8 MiB，或 V2 硬上限前触发轮换。轮换复用 Manifest V2 的 `prepared → sealed-file-synced → vault-committed → anchor-confirmed`，启动时最多执行有界幂等步骤。sealed segment 和 active segment 都通过 Descriptor V3 key envelope 解密读取。

## 显式迁移

历史 Vault 只有 V1 Audit 时，普通打开继续使用 V1；不会自动创建 V2。Owner 显式执行：

```text
envvault --vault <PATH> audit migrate-v2
```

迁移先记录一次 `read_audit` 授权、完成 V1 链认证和事件解码，再写私有迁移标记；标记绑定 vault id、事件数和 length-prefixed canonical event bytes 的 SHA-256。复制中断后，普通命令停止，V1 仍是权威；显式迁移重试只复核权限而不再改变源链，并必须匹配源摘要、验证已经复制的 V2 前缀，然后继续。全部事件逐项相同后才删除标记并切换。V1 链保留为冻结历史副本，迁移后不再双写，禁止 V2→V1 降级。

CLI `audit list` 经过独立 `read_audit` 授权，输出时间、Caller、认证方式、目标和 Decision，不输出 Secret Value、credential、password、key 或密文。

## 未完成边界

- 远程 append-only/WORM、平台单调计数器或硬件 AnchorSink；
- remote sink timeout/replay/service rollback 的端到端测试；
- 父目录 handle flush、强制终止和真实断电证明；
- retention/export/备份验证和显式清理命令；
- 多进程压力、恶意同账户竞态和独立安全审计。
