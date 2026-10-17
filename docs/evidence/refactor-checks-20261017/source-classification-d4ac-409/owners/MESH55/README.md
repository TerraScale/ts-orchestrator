# MESH55 candidate source classification

Read `classification.json` for the exact 55 original roots, raw declaration evidence, core/local assertions and connected helper/production citations. `summary.json` supplies immutable source/allocation pins and category totals.

Candidate counts: **35 integration / 8 unit / 11 mixed / 1 unresolved = 55**. No accepted ledger count changes.

The unresolved root is `internal/globalcontrol/fencing_test.go::TestConcurrentWritersNeverInterleaveTerms`. Numeric suffixes make both IDs longer than the canonical 26-character ULID format. Production `PutDirectory` reads the roster, then validation returns before concurrent append/CAS; the test discards all errors. Log assertions observe setup state and do not establish the intended concurrent-writer obligation. No original is retired or replaced.

Globalview Build roots use the shared `observedRollup` helper: production Build -> publishOnce -> actual NATS -> separate remote Follow -> listening HTTP server/client -> asserted rollup. Pure synthetic inputs limit acquisition claims; they do not make this demonstrated transport incidental. Separate local input-preservation assertions are classified mixed. HTTP recorder-only assertions remain unit.

Runtime: **UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION**. Source review does not prove compilation, passing tests, production availability, R3 quorum, cloud effects or deployed multi-region behavior. No 7330 qualification transfers. Retirement authorization and credit: **false / 0**.

Integrity: all allocated baseline/source declaration hashes and test-file pins were recomputed from immutable Git blobs; every cited source file and function span is pinned. Raw declaration/span SHA256 excludes the following LF. `generate.py` is the static artifact builder; it invokes Git object reads and performs no Go/runtime execution. `integrity.json` records the independent static packet checks. `SHA256SUMS` covers every other artifact.

Next: independent peer review of these candidates. Accepted-ledger promotion requires a separate authorization.
