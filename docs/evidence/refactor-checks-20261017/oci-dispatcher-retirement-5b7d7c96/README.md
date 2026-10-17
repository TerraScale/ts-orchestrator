# OCI dispatcher boundary and isolated retirement

The replacement exercises the real Factory.Compute client and HTTP dispatcher with three signed SDK requests: success, throttling and a dropped connection. Every original telemetry assertion remains byte for byte: calls3/errors2/throttled1, deterministic durations, four exact metric series and OCID nonleak. Signature presence is checked; request-signature cryptographic verification is outside this fixture.

Exact source `d45d64d2` passed one root with no skips or extra identities in actual session59523 (root0.830s/package0.842s, total5.034s). The separately reviewed retirement `5b7d7c96` removes only the original declaration, its separator and unused errors import:1776bytes/45lines. All five other free declarations remain exact. True `go test -c` with default vet passed in session64733 (5.430s); the16349624-byte ELF remains outside this repository, mode0600 and never executed.

The adopted file matches qualified retirement source byte for byte. `adoption-review.json` maps copied files and the excluded binary; nested original checksum files retain exact bytes and may therefore name that excluded binary. Root `SHA256SUMS` covers the direct copies. Copied Go files use `.go.txt` names; no archive was created.

The native compile terminal explicitly reports truncation (237662originaltokens). The complete on-disk receipt, source snapshots and raw logs are retained; no complete terminal capture is claimed. This qualifies the exact local boundary and isolated retirement, without repeated runtime, race, full shared-tree or production qualification. Frozen first-party inventory remains4319 originals:6 qualified retirements and4313 globally unadjudicated.
