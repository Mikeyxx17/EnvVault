# Audit V2 Rotation Fault-injection Matrix

状态：Manifest V2 状态机、active/sealed key envelope 认证、segment staging 故障点、Descriptor V3 generation 提交、三文件本地恢复和 local-mirror / loopback CAS deterministic tests 已实现。远程锚点文件不变量有本机 Linux 与本机 Windows harness 冒烟（`remote-anchor` 场景）。本机 Windows 进程击杀记录见 [m1.2-windows-process-kill-record-v1.md](./m1.2-windows-process-kill-record-v1.md)。目录断电、Windows VM 和远程 WORM 验收尚未通过。

## 恢复状态

Recovery manifest 只能按以下顺序前进：`prepared → sealed-file-synced → vault-committed → anchor-confirmed`。每次更新必须写私有临时文件、`sync_all`、原子替换并复核权限。Manifest 绑定 vault id、operation id、旧/新 generation、segment id、sequence 区间、临时/最终文件名及其 digest；路径只保存父目录内的文件名，禁止任意绝对路径。

恢复删除仅限 manifest 中本次 operation-owned 的临时文件。非空最终 segment、Vault descriptor 已引用的文件、来源不明文件和 digest 不一致文件一律不能删除。

## 轮换矩阵

| 注入点 | 重启时可观察状态 | 必须执行 | 禁止行为 |
|---|---|---|---|
| 建 manifest 前 | 只有旧 Vault/active segment | 继续使用旧状态 | 猜测或删除临时文件 |
| `prepared` manifest 落盘后、segment 临时文件前 | manifest + 旧 Vault | 删除空/不存在的 operation-owned staging，或安全重试 | 修改旧 Vault |
| segment 写一半 | 临时文件 digest/长度不符 | 删除该 operation-owned 临时文件并重建 | 将部分文件 rename 为最终文件 |
| segment 已写但 file sync 前 | durability 未证明 | 重写、sync 后再前进 | 标记 `sealed-file-synced` |
| file sync 后、manifest 更新前 | 完整临时文件，状态仍 prepared | 重新验证 bytes/digest、sync，幂等前进 | 仅凭文件存在跳过验证 |
| rename 最终名后、目录 sync 前 | 最终文件可能在断电后消失 | 重启时验证；缺失则从安全 staging 重建，否则停止 | 提交引用不存在 segment 的 Vault |
| `sealed-file-synced` 后、Vault commit 前 | 新 segment 不被 descriptor 引用 | 验证旧 generation 后提交；并发变化则停止并人工诊断 | 覆盖并发 Vault generation |
| Vault 临时写一半或 commit 前 | 旧 Vault 应仍可打开 | 丢弃 Vault 原子写临时物，保留 sealed segment | 删除已同步 segment |
| Vault commit 后、manifest 更新前 | descriptor 已引用 segment | 通过 descriptor/digest 识别已提交，幂等前进 | 按旧 manifest 状态删除 segment |
| `vault-committed` 后、anchor CAS 前 | 本地链有效、外部 anchor 落后 | mandatory 模式进入 degraded；重试 exact expected-generation CAS | 发放 Secret、控制面写入或跳过 generation |
| anchor CAS 成功、响应丢失 | sink 可能已拥有新 generation | 读取并逐字节比较 canonical anchor；相同视为成功，不同则失败关闭 | 盲目创建下一 anchor |
| anchor 返回冲突/领先 | 外部状态与本地不一致 | 失败关闭并保全全部证据 | 回退 sequence、丢事件“追平” |
| `anchor-confirmed` manifest 删除前 | 三方状态一致 | 复核后删除 recovery manifest | 删除 sealed segment |
| manifest 删除或目录 sync 中断 | 可能残留已完成 manifest | 识别三方一致并幂等清理 | 重复轮换或重复 anchor generation |

## 必测不变量

- 对每个注入点，重启不得出现 Secret 发放发生但对应本地 Audit event 丢失。
- sequence、segment id、Vault generation、anchor generation 不倒退、不重复。
- descriptor 引用的 segment 必须存在、为普通私有文件且 canonical digest 一致。
- 后段 predecessor、前段 terminal、descriptor 和 anchor terminal 必须一致。
- mandatory anchor 落后或未知时，`use`、明文读取和所有控制面写入失败关闭。
- optional/local-mirror 模式必须显式标注无回滚保护，不能复用 mandatory 的安全声明。
- 注入测试不能通过 mock “成功写入”替代真实文件 `sync_all`、rename、目录 durability 和进程终止测试。

## 验收层级

1. 纯状态机 exhaustive tests：合法/非法跃迁和关键 evidence/action 组合已覆盖；仍需扩展组合生成测试。
2. 文件层 deterministic failpoint tests：manifest create/update/tamper、pending key ciphertext 篡改、segment 空/半写/封存/篡改、segment/descriptor predecessor 断裂、descriptor 篡改/并发 generation、commit 后 manifest 未推进、sealed-key 保留和三文件幂等恢复已覆盖；anchor 和父目录 durability 的其余注入点仍需 Windows/Linux 实现。
3. 多进程 generation/lock 压力测试。
4. VM/真实磁盘强制终止与断电恢复。
5. 外部 CAS sink 的超时、重复请求、冲突和服务端回滚：协议层与 loopback HTTP/HTTPS 自动化已覆盖；远程 WORM 部署级记录仍缺。
6. 远程锚点 durable 文件（store / last-confirmed / rollback）的本机击杀场景已有合成 harness。
7. 真实 Vault 轮换进程击杀（`envvault-fault-target`）已覆盖 prepared/sealed/commit/anchor 四个窗口：本机 Linux `kill -9`，以及本机 Windows `taskkill /T /F`（见 [m1.2-windows-process-kill-record-v1.md](./m1.2-windows-process-kill-record-v1.md)）。Windows VM 与断电仍缺；只完成了进程击杀，断电未做。当前击杀场景不发放 Secret。

只有第 1～2 层自动化通过不能声明真实断电安全；只有本地镜像通过也不能声明完整文件回滚防护。
