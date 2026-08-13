# Dependency and Supply-chain Policy V1

状态：本机策略与 CI workflow 已建立；当前 RustSec 数据库扫描无已知漏洞。CI 尚未在远端实际运行。

## 固定边界

- 主工程锁定 Rust 1.97 和已提交 `Cargo.lock`；
- CI 安装固定版本 `cargo-audit 0.22.2`、`cargo-deny 0.20.2` 和 `cargo-fuzz 0.13.2`；
- fuzz CI 使用 `nightly-2026-07-31`，避免每日 nightly 漂移；
- GitHub Actions 使用完整 commit SHA；
- Cargo 来源只允许 crates.io registry，不允许未知 registry 或 Git dependency；
- wildcard dependency 被拒绝；项目为 `publish = false`，private workspace license 不参与第三方 license 判定。

允许的第三方许可证为 Apache-2.0、BSD-3-Clause、MIT 和 Unicode-3.0。新增许可证必须显式评审并修改 `deny.toml`。

## 当前结果

- `cargo audit` 更新 RustSec 数据库后扫描 108 个锁定依赖：未报告 vulnerability；
- advisories、licenses 和 sources：0 error；
- bans：0 error、6 个 duplicate-version warning；
- 重复版本来自密码学版本代际（包括 Argon2 的 `digest 0.10` 与 SHA-256 的 `digest 0.11`）、Windows permissions 的旧 `bitflags`，以及 dev-only `proptest` 依赖链。当前只警告，不使用无依据 `skip` 隐藏；升级上游依赖时继续收敛。

## 执行

```powershell
.\scripts\security-check.ps1
.\scripts\security-check.ps1 -IncludeFuzz -SecondsPerFuzzTarget 30
```

`cargo audit` 和 `cargo deny advisories` 需要可更新且可加锁的 advisory 数据库。在受限环境出现只读 lock 错误时必须在获准环境重跑，不能记录为通过。

## 未证明事项

无已知 advisory 不代表依赖没有漏洞。当前尚未实施 SBOM 签名、构建 provenance、制品签名、依赖 vendoring、恶意 crate 行为审查和独立供应链评审。
