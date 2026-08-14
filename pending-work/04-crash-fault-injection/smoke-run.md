# Fault-injection Run Record

- Run: `20260813-215939`
- Started (UTC): `2026-08-13T21:59:39.8974861Z`
- Scenario: `scenario.ps1`
- Recovery: `recovery.ps1`

| Checkpoint | Marker seen | Scenario exit | Recovery exit | Verdict | Detail |
|---|---|---|---|---|---|
| before-manifest | True | -1 | 2 | fail_closed | no committed descriptor; nothing can be lost |
| manifest-written | True | -1 | 2 | fail_closed | no committed descriptor; nothing can be lost |
| segment-half | True | -1 | 2 | fail_closed | no committed descriptor; nothing can be lost |
| segment-written | True | -1 | 2 | fail_closed | no committed descriptor; nothing can be lost |
| vault-committed | True | -1 | 0 | recovered | consistent state with 50 committed events |
| anchor-confirmed | True | -1 | 0 | recovered | consistent state with 50 committed events |

