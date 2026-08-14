# ADR 0015: External Monotonic Anchor Wire Protocol

状态：Proposed（草稿，2026-08-13）。本 ADR 冻结远程 AnchorSink 的 wire protocol 与故障语义，供参考实现、test double 与未来真实部署共用。真实部署验收完成前，不声明完整回滚保护。

## 背景

ADR 0013 确立了外部锚点的必要性：`vault_id`、最后 sequence、segment id、terminal authenticator、前一 anchor digest 与格式版本组成的 canonical record，必须写入与 Vault 不在同一回滚域的单调 compare-and-set sink。当前代码已具备：

- `AnchorSink` trait：`load()` 与 `compare_and_set(expected_generation, canonical_anchor)`；
- `LocalMirrorAnchorSink`：本地私有文件 + sidecar lock + 原子替换的完整 CAS 语义验证；
- mandatory sink 失败进入 `audit_anchor_degraded`、失败关闭的原语。

缺的是：真正外部 sink 的传输协议、认证、幂等、重试与服务端回滚检测语义。没有冻结协议，任何远程/硬件 sink 都无法实现或验收。

## 候选方案

| 方案 | 说明 | 评估 |
|---|---|---|
| A. HTTPS CAS 服务 | 自托管或对象锁存储托底的 append-only 服务，暴露本文协议 | 首选首部署目标；可复现、可审计、跨平台 |
| B. 硬件/平台单调计数器 | TPM monotonic counter、平台密钥库单调项 | 根信任最强，但 API 异构；通过本地 loopback shim 暴露同一 HTTP 协议再接入 |
| C. 云对象存储 object lock 直连 | S3 Object Lock / Azure immutability 作为 CAS 后端 | 实现上是 A 的存储后端变体，不作为独立协议 |
| D. 仅本地镜像 | 现有 LocalMirrorAnchorSink | 只能发现误损坏，不能抵抗同盘整体回滚，明确不作为回滚防护 |

选择 A 为协议形态基准；B 通过 loopback shim 复用同一协议，不在本 ADR 内定义厂商 API。

## 决策

### 传输与编码

- HTTPS/1.1 或更高；TLS ≥ 1.2，优先 1.3；拒绝明文回退。
- JSON body，UTF-8，版本化路径前缀 `/v1/`。
- Canonical anchor bytes 维持 `AuditAnchorV2` 现状不变（format `envvault-audit-anchor`，version 2，JSON，≤ 4 KiB）。服务端必须重新解析并重序列化，逐字节相等才视为 canonical；否则 `422`。
- 协议不携带 Secret Value、credential、password 或密钥；anchor 内容本身即 value-free。

### 端点

```text
GET /v1/vaults/{vault_id_b64}/anchor
  200 {"anchor": "<base64 canonical bytes>"}
  404 {"error": "not_found"}          # 该 vault 尚无 anchor

POST /v1/vaults/{vault_id_b64}/anchor/compare-and-set
  body:
    {
      "request_id": "<base64 16B CSPRNG>",
      "expected_generation": <u64>,
      "anchor": "<base64 canonical bytes>"
    }
  200 {"status": "applied",           "anchor": "<base64 stored canonical bytes>"}
  200 {"status": "already_applied",   "anchor": "<base64 stored canonical bytes>"}
  409 {"status": "conflict",          "generation": <u64>, "anchor": "<base64 current canonical bytes|null>"}
  404 {"error": "vault_not_found"}
  422 {"error": "invalid_anchor"}     # 非 canonical、generation 语义错误等
  429 {"error": "rate_limited"}
  503 {"error": "unavailable"}        # 可重试
```

路径中的 `vault_id_b64` 必须等于 anchor 内 `vault_id`，否则服务端返回 `422`。

### 认证与授权

- Bearer token：每 vault 一个、只授权该 `vault_id` 的读写；服务端拒绝跨 vault 访问。
- Token 由服务端线下签发/吊销；轮换与吊销流程属于部署运营，不在本协议内。
- 服务端必须记录访问审计（调用者、vault、操作、结果、时间），不记录 token 本身。

### CAS 语义（与本地镜像一致）

服务端在持久化互斥下原子执行：

1. proposed generation 必须等于当前 generation + 1；
2. generation 1 的 `previous_anchor_digest` 为零；否则必须等于当前 canonical bytes 的 SHA-256；
3. `vault_id` 不变；`segment_id`、`sequence` 单调不减；
4. 相同 canonical bytes 的重试返回 `already_applied`；同 generation 不同 bytes 返回 `conflict`；
5. 返回 `applied`/`already_applied` 前必须完成持久化（fsync/对象锁提交），禁止先应答后落盘。

### 幂等与重试

- 客户端为每次逻辑 CAS 生成 CSPRNG `request_id`（16B）；重试复用同一 `request_id`。
- 服务端维护有界去重账本（按 vault + request_id 记录首次结果），保留窗口 ≥ 客户端最大重试周期。
- 客户端重试策略：每 attempt 超时 10s，指数退避 + 抖动，最多 5 次，总预算 ≤ 60s；预算耗尽或 409/422 → 失败关闭，不无限循环。

### 服务端回滚检测

- 客户端在 recovery manifest 中持久化 last-confirmed 的 `(generation, canonical bytes)`。
- 任何响应满足其一即判为服务端回滚：`generation < last_confirmed_generation`；或 generation 相等但 canonical bytes 不同。
- 回滚判定 → mandatory degraded 失败关闭、记录 value-free 证据（期望 vs 观察到的 generation/digest），只允许 Owner 诊断/恢复；禁止自动追平或重新 apply。

### 冲突与不可用

- `409 conflict`：客户端验证返回的 current anchor 的语法与链关系，但不自动对账；本地继续持有证据并进入 degraded，由 Owner 诊断决定后续。
- `503`/网络失败：按重试策略重试；mandatory anchor 场景下最终失败沿用现有 degraded 语义，绝不静默降级到本地镜像。

## 影响

- `AnchorSink` trait 无需修改；远程实现作为新 struct 落入 `vault` 模块（trait 暂不公开，避免过早承诺公共 API）。
- 新增客户端状态：last-confirmed `(generation, digest)`、重试状态与 request_id 生成，全部 value-free。
- Vault 文件格式、Descriptor V3、segment 格式零改动。
- 本地镜像仍是默认 sink；远程 mandatory sink 的 CLI/config 接入不属本 ADR 范围。

## 安全边界

- 协议不能阻止被攻破或恶意的 anchor 服务说谎：信任模型是"anchor 服务是更高保证的 append-only 系统"，客户端只验证语法与链一致性，不验证服务诚实性。硬件锚点通过平台根信任缩小该假设，但不能消除。
- 端点暴露本身可能泄露 vault 存在性；部署方需自行控制网络暴露面。
- 本文不改变既有边界：`run` 不是沙箱、同用户进程不可隔离、自动化通过不等于生产安全验收。

## 复审条件

- 至少一种真实后端部署并通过故障矩阵：响应丢失、重复请求、冲突、服务不可用、服务端回滚、恢复；
- 参考实现 + test double 的协议测试通过（对应后续工作项）；
- 独立安全评审关闭，方可宣布 M1.1 的外部锚点部分完成。
