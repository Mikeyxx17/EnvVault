# EnvVault Fuzz Run Record

- Run: `20260813-173217`
- Started (UTC): `2026-08-13T17:32:17.2899080Z`
- Duration: `14449s`
- Toolchain: `rustc 1.99.0-nightly (ad3d0bc14 2026-07-31)`
- cargo-fuzz: `cargo-fuzz 0.13.2`
- Parameters: `3600`s/target, max_len `32768`
- Overall: `clean`

## Results

| Target | Status | Corpus before | Corpus after | New artifacts | Coverage total |
|---|---|---:|---:|---:|---|
| vault | clean | 1 | 2334 | 0 | TOTAL                                12357             12228     1.04%         800               792     1.00%        7959              7858     1.27%           0                 0         - |
| identity_audit | clean | 10 | 5729 | 0 | unavailable |
| policy_profile | clean | 2 | 2044 | 0 | TOTAL                                12357             12143     1.73%         800               781     2.38%        7959              7801     1.99%           0                 0         - |
| dotenv | clean | 1 | 436 | 0 | TOTAL                                12357             12099     2.09%         800               781     2.38%        7959              7810     1.87%           0                 0         - |

## Notes

- "artifacts_found" means libFuzzer produced crash/timeout/OOM artifacts; review them before reuse.
- Minimized corpus is written in place under `fuzz/corpus/<target>`; review and commit intentionally.
- Coverage percentages cover the `envvault` crate sources only; third-party code is filtered out.

