# DATA75 candidate source review

75 original roots retained exactly: **2 integration, 16 unit, 0 mixed, 57 unresolved**. Runtime: UNKNOWN for every root. Retirement delta and ledger promotion: 0.

The 57 unresolved roots depend on incomplete `natscell.Start` fixtures using `Config{Lab: true}`. Canonical `natscell.Config` has no Lab field; validation also requires TLS/JWT material absent from these fixtures. Source-only review cannot repair or substitute fixtures. Each root records its intended assertion target without granting it classification credit.

The 18 resolved categories describe independently connected assertion paths. Whole delivery-package compilation is visibly blocked by shared unsupported fields and has not been run. The two integration paths use direct `server.NewServer` fixtures: root08 checks real NATS dispatch/cancellation to a silent synthetic API subscriber; root34 checks actual one-server JetStream Put/Delete, restricted direct-read permissions and production leader reads. Neither earns execution, replication or current7330 credit.

`classification.json` contains literal allocated IDs, exact baseline/current declarations, independent per-root rationales, assertion text/conditions, helper/production spans with Git blobs and SHA256, file pins, limitations and findings. `declarations/01.txt` through `75.txt` contain exact source declaration bytes without following LF. `source-blobs/` contains canonical full-file bytes for every citation. `build_packet.py` is the reproducible static generator, not a source change or test execution.

Source: d4ac68882716e7cfb14afca2f88ad596a38041af; tree: 3b73a410a025bd8050ad1d42e54acc7d5eda4b82. Baseline: bfca60368f60d2da67f9016d1d489317ae8749c8. The input manifest/contract/independent-allocation-review hashes are embedded in JSON. Every baseline/source declaration pin was independently rechecked.

Candidate only. Independent peer review and separate accepted-ledger promotion are required before accounting changes. No source/Git/ledger changes, Go commands, process/listener/lock actions, cloud work or runtime execution occurred. Files sealed0444 and directories0555 with SHA256SUMS. All original safety obligations remain open.
