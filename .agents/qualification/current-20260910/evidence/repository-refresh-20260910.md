# Repository and gate refresh — 2026-09-10

Evidence-only refresh captured after the current worker activity. No product
source was changed by this refresh. HEADs and dirty counts below are the final
read-only snapshot; qualification runtime artifacts account for most of the
TerraBase dirty tree.

| Repository | HEAD | Dirty entries |
| --- | --- | ---: |
| terrabase | `ff3da34f83fb86b93cf7db51395085f628f5433e` | 871 |
| ts-cli | `94500effb7268011c9a112702ffd06cc7a89d3fb` | 8 |
| ts-dashboard | `34ef28f5973faeb00e16aa01407141a391c71f2f` | 0 |
| ts-deploy | `f67339046130832491b164b2fdfab53f8e10c723` | 1 |
| ts-docs | `178b00f982e238a23b005d9ee3cfd26ef5ecc699` | 0 |
| ts-dotnet | `808df27407c34983bbf91130986a6d8d855507d9` | 0 |
| ts-go | `a0824d48660c6524fcccfbf3e0e50d5e1624e08d` | 7 |
| ts-landing | `746ae3e7954a45f1dbc2a09ae6e79eae8fe34c36` | 9 |
| ts-orchestrator | `97476cc3225126555f17cfaf448b3a446f912be5` | 4 |
| ts-proxy | `93c5c79fc0aa843531f57a1aa5c11595ef5de776` | 0 |
| ts-rust | `9ca84825639d6ece4aec8cebc663f4ca029fc65f` | 1 |
| ts-typescript | `a17729ee0852fcc1a4b8bbdc2063c4e2a08fd0a2` | 0 |

The TerraBase producer archive is internally consistent:

* `terrabase/contract-archives/v1.tar` SHA-256:
  `e7a8bcbe752d814006c52fd40df055d54ac9adb7e3c1e5050630951d8f3498af`
* `v1.tar.sha256` and all five consumer `CONTRACT_ARCHIVE_SHA256` pins match
  that digest exactly.

## Gate results

Commands were run as `timeout 120s make check` in each consumer checkout;
results are the command's actual exit status.

| Repository | Result | Relevant result |
| --- | --- | --- |
| ts-cli | FAIL (2) | Contract verification passed; tests failed because stored credential belongs to a different API origin, including `internal/cli` doctor/import/SQL tests. |
| ts-dashboard | FAIL (2) | Missing required `TS_SDK_SOURCE`. |
| ts-deploy | PASS (0) | vet, build, and race tests passed. |
| ts-docs | FAIL (2) | Build and local tests passed; cloud snippet gate failed because the real sandbox inputs are unavailable. |
| ts-dotnet | FAIL (2) | Immutable contract source is not configured (`CONTRACT_URL`/archive or explicit `CONTRACT_SOURCE`). |
| ts-go | FAIL (2) | Contract/vet passed; `TestSubscribeUsesCanonicalOffsetCapabilityAndCopiesSnapshotBody` expected `checkpoint = "opaque-0"`. |
| ts-landing | PASS (0) | Build, validation, 47 Node tests, Svelte check, and lint passed. |
| ts-proxy | PASS (0) | Typecheck, 190+4+100+8 tests, dry-run deploy, and Go checks passed; workerd emitted network-disconnect diagnostics during tests. |
| ts-rust | FAIL (2) | Immutable/local contract source is not configured. |
| ts-typescript | FAIL (2) | Pinned v1 contract is unpublished; requires explicit local source or immutable URL/archive. |

`make check` in `ts-orchestrator` was started at the current checkout and
interrupted after roughly 103 seconds when `cmd/orchestrator` remained blocked;
the emitted failure was `database admission remains unresolved
error="host disconnected"`. Other packages that completed before the
interrupt were successful.

The wrapper exit-code regression suite was independently run with:

```text
python3 -m unittest test_local_composition.py
......
Ran 6 tests in 0.419s
OK
```

Those tests cover preserving the first phase failure, attempting all cleanup
children, propagating child status 17/33, timeout status 124, and wrapper
failure status 1 while bounding/redacting logs.

Coverage gaps remain: TerraBase's full Cargo gate was not rerun because its
checkout contains active qualification runtime artifacts; cloud sandbox gates
for docs/dashboard remain unavailable; and the orchestrator race suite needs a
clean rerun after resolving the host-disconnected admission condition.
