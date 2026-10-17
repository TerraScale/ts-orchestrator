# NET48 candidate source classification

Review `classification.json` for all 48 literal original roots at `d4ac68882716e7cfb14afca2f88ad596a38041af` (tree `3b73a410a025bd8050ad1d42e54acc7d5eda4b82`).

1. Candidates: 26 integration, 11 unit, 9 mixed, 2 unresolved; total 48.
2. Unresolved: `TestHelperNetBird` has no independent assertion. `TestPodmanManagerSyncAndPrune` keeps GRU while assigning a 10.252/16 subnet, so first Prune validation blocks the intended assertions.
3. All 96 baseline/current declaration hashes and copied immutable Git blobs verified. Exact root declarations, assertion/failure indexes, helper/production spans and file pins are retained in JSON and `source/`.
4. Runtime: `UNKNOWN_NO_RECEIPTS_REVIEWED_NO_EXECUTION`. No Go/build/format/test/lint/runtime/cloud or process/listener/lock action. Retirement false; delta 0; no ledger promotion or 7330 qualification transfer. Global accepted counts remain 171 classified / 4129 unadjudicated / 19 retired.
5. Next: independently peer-review the candidates and both unresolved findings. A separate accepted promotion is required for any ledger count change.

Allocation: `/tmp/ts-d4ac-next300-allocation-proposal-raxuc07l/allocation.json` SHA256 `032cb201e692326da7274b12d7dfd15512b1befd325cce375188ae0447ca2523`.
Baseline: `bfca60368f60d2da67f9016d1d489317ae8749c8`. QA acceptance: `/tmp/ts-qa-next300-allocation-independent-2ivixd0j/review.json` SHA256 `4a1acb09fb4e6ee22f2d9eeb6ea610ed627c7de40851937676dfdc5bc96436a3`.

`SHA256SUMS` covers every report file except itself; files are sealed 0444 and directories 0555. The builder is retained as static report-generation provenance; its execution only reads pinned Git objects and writes this exclusive report directory. No source, Git, allocation or ledger file was changed.
