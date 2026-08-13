# ADR 0013: Audit Segments, Rotation Recovery, and External Anchors

状态：Accepted，2026-08-13。Audit V2 格式、轮换、恢复、本地镜像 CAS 和 mandatory degraded 原语已实现；真正外部单调 sink 的部署与真实断电验收仍属于生产安全门禁。

## 背景

V1 把全部 Audit Event 放在 Vault JSON 内，最多 100,000 条。链头绑定事件数量和最后 authenticator，可检测当前文件内的修改、重排与局部删尾，但每个事件都会重写整个 Vault，整个旧文件连同旧链头回滚时无法检测。

## 决策

### 分段模型

- Audit sequence 在同一 Vault 中永不重置；segment 只是物理边界。
- 每个 segment header 绑定 `vault_id`、`segment_id`、起止 sequence、前一 segment terminal authenticator、创建时间和格式版本。
- segment 内事件继续使用独立 Audit key、sequence 和前一 authenticator 作为 AAD。
- active segment 达到事件数或字节阈值后，由精确 `rotate_audit` Vault permission 触发轮换。
- 旧 segment 先写入私有、不可覆盖的独立文件；文件完成同步后，Vault 再原子提交新的 active segment key envelope 和 sealed-segment descriptor。

### 崩溃恢复

轮换使用受 `secure_fs` 保护的 recovery manifest：prepared → sealed-file-synced → vault-committed → anchor-confirmed。恢复只能删除本次操作拥有且尚未被 Vault descriptor 引用的临时文件；已提交 descriptor 的 segment 必须保留并验证。非空不匹配文件、sequence 倒退或 authenticator 不一致一律失败关闭。

### 外部锚点

Anchor 是不包含 Secret Value 的 canonical record：`vault_id`、最后 sequence、segment id、terminal authenticator、前一 anchor digest 和格式版本。Anchor sink 必须提供单调 compare-and-set；普通同盘文件或仅用 DPAPI 加密的文件不能作为回滚防护。V1 可选后端顺序为远程 append-only service、硬件/平台单调存储，最后才是明确标注为“仅防误损坏”的本地镜像。

允许操作必须在本地 Audit commit 成功后才继续。若配置了 mandatory anchor，anchor CAS 失败则 Vault 进入 `audit_anchor_degraded`，拒绝 Secret 发放和控制面写入，只允许 Owner 执行诊断/恢复。不得通过丢弃本地事件来追平外部 anchor。

### 保留与删除

Retention 以完整 sealed segment 为单位。只有远端 anchor 已确认包含该 segment terminal state、导出副本已验证且明确授权 retention 操作后才能删除；删除事件本身写入后续 segment。物理安全删除不作保证。

## 不变量

- sequence、segment id 和 anchor generation 单调增加；
- 新 segment 的 predecessor 必须等于旧 segment terminal authenticator；
- Vault descriptor、sealed file 和 anchor 三方的 terminal state 必须一致；
- 任何缺失、重复、倒退或未知格式都失败关闭；
- Audit payload 继续无法承载 Secret Value、credential、password 或密钥。

## 实施门槛

Phase 7D～7H 已建立 V2 schema、恢复状态机、SegmentStore、Manifest V2/Descriptor V3 和认证密钥生命周期。Phase 7I/7J 已接入本地 `AnchorSink` CAS、degraded 原语、Broker/CLI 活动段、自动轮换/启动恢复和显式 V1→V2 迁移；新 Vault 默认使用 V2，历史 Vault 不静默迁移。ADR 仍为 Proposed：真正远程/硬件单调 sink、目录 durability、真实断电测试与独立安全评审完成前，不能声明完整回滚保护或生产安全完成。
