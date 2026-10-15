# X-01 / X-02 acceptance evaluator

Guardian #17 needs one pinned multi-repository run (DAV + ACS + sealed ACS
bootstrap + signed OTA over WireGuard) and one common 18-case negative matrix.
Orchestration lives in Admiral `deploy/secured/` and ArlanPhone QEMU; this
repository owns the **verdict**: `internal/acceptance` and `cmd/guardian-acceptance`.

Report JSON: `manifestId`, `manifest.repos` (exact 40-hex SHA for Guardian,
Admiral, SunkarCWMP, SunkarDAV, ArlanPhone), `results[]` with `id` 1–18,
`status` (`PASS|FAIL|BLOCKED|NOT_RUN|WAIVED`), `manifestId`, `evidence`,
`leakScanClean`.

Rules: complete only when all 18 are `PASS` on one manifest with evidence and a
clean secret-leak scan. `WAIVED` is never `PASS`; only #9 (IPv6 part) may be
waived, with a reason. Missing cases are `NOT_RUN`; results from another
manifest, duplicates and unknown IDs invalidate the report.

```sh
go run ./cmd/guardian-acceptance report.json   # exit 0 only for 18/18 PASS
```

Scenario 13 must exercise Guardian #21 (store outage → 503 + Retry-After, no
false revoke); existing component coverage is
`internal/httpapi/device_auth_outage_test.go`. This tool does not run the lab:
until an orchestrator emits a report, X-01/X-02 remain PARTIAL.
