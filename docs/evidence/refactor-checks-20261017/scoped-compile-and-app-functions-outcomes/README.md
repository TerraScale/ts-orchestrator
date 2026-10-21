# Second accepted evidence publication packet

This is a packaging-only copy of seven already accepted scoped reports. Accepted QA reports control scope and limits. Copying evidence makes no new test, compilation, semantic-equivalence, production or global-closure claim. APPd0b is excluded entirely; this packet makes no claim about its outcome.

## Compile-only results: default vet requested, no output-binary execution

| Scope | Exact source / tree | Accepted result | Boundary |
| --- | --- | --- | --- |
| auth97d | `97d30105e6d4c0258d6caf119721045a9851db67` / `3a4938e8d0c9427b1d4a9e9cecca812530b2ac84` | PASS8: eight test binaries across nine selected packages | natstest has no tests. tests/firecracker contains only ignored Go source and was excluded, with no compile credit. The 105 test names are declaration metadata only. |
| rootbackup38645 | `38645f8f339d7c51b1dc39db749edecefd4d2a4f` / `892c89a1e2bdc4cc058ff7b4ec945a10c7f1cd63` | PASS5: rootbackup, oci, placement, managedmaterial, storage/backup | Nine OCI/placement source paths differ from auth97d. No duplicate-compilation equivalence. Old duks packet unused. |
| OCI620 aggregate | `620dab4633c50988c800b68ec5d4b7dd1dcbb881` / `16588948874f281cde2ba4efc582646be5c8ed1d` | NOT_QUALIFIED; native terminal exit 1; seven partial binaries | Sole error: internal/region/netbird_network_integration_test.go:14:2: "io" imported and not used. region.test is missing; rootfoundation has no tests. |
| OCI64 region only | `64a55bb2fc0034279732cfb8a99c06b75cf90d6a` / `430c89f4408d37377f6492f7d827c58f2578cb89` | PASS1: ./internal/region, go test -c -tags=fixturetest | No nine-package rerun and no aggregate620 success. |

Compile-only results do not execute emitted test binaries, target init, TestMain or test bodies. Default vet was requested as retained; this packet runs no Go command or analyzer. All 21 ELF output binaries (902,436,219 original bytes) are excluded with exact SHA256, size, original mode and reason in MANIFEST.json.

## Selected runtime results: explicit vet off, non-race

| Scope | Exact source / tree | Accepted result | Boundary |
| --- | --- | --- | --- |
| APP6aab focused | `6aab710808fddcc45fb15e770369449dfd2d6861` / `bb2a066c76922e400db62fe5b180ecedcd417d6b` | PASS1: TestServiceIntentGeneration, internal/swarmruntime; package 0.057s | Pure-memory duration fingerprint only. No manager, native or cloud credit. |
| APP6aab manager | Same 6aab source/tree | FAIL: TestGenericRuntimeSignedManagerIntegration, root 169.02s / package 169.296s, final assertion line 580 | Overall NOT_QUALIFIED. Ordered phase evidence is partial evidence, not independently named passing tests. |
| FUNCTIONS afad | `afad42a30b651cd7210a094942eaf0f4c5696f1f` / `62de48b7834190163e2306e7847faa617b241c89` | PASS10 run/pass identities across four selected roots | Local authenticated broker/authority admission ordering only; no managers, native/containerd, cloud or distributed-transaction claim. |

The APP manager run uses actual local authenticated brokers/managers with a simulated executor and external recipient adapter. Election follows zero-replica drain and the old probeClient persists; no live-workload failover claim. Its accepted report explicitly leaves final retained native evidence preservation unverified. Copies and packaging hashes do not remove that historical qualification limit.

FUNCTIONS selected TestFunctionPublicationFencesRootsAcrossArtifactWait (current, rotated, expired, released_leader), TestFunctionPublicationOrdersRootWritersBeforeIntentCAS (apply, repair), TestRootRegistryAdoptsOnlyExtendingChains, and TestRootRepairNeverRollsBackAValidRecord. The 306 raw events comprise 1 start, 10 run, 284 output, 10 test PASS and 1 package PASS. Accepted QA independently validated complete event identities, order, finite timing and frames. Inherited three-manager wording in its original static-review.json is preserved unchanged and grants no manager credit. A prior 552 compile-failure receipt is retained solely as history with zero-test credit.

## Provenance and historical seals

Every request, runner, source/tool manifest, pre/post snapshot, raw output, retained native object, receipt and seal under the ten selected evidence roots is copied unless it is ELF. Seven exact pinned QA reports, seven manifest-pinned source snapshots, and the pinned prior 552 receipt are included. Historical request states and source-only seals stay as originally recorded; later terminal evidence is separate. In particular OCI620 and OCI64 final-seal files, and the FUNCTIONS seal, remain source-only records. OCI64 preservation-proof.json is retained unchanged.

OCI620 retains eight actual surfaced native result objects, including its resource check, plus the candid manual empty-poll transcription poll-2-manual.json. That transcription is not an actual captured return. Its other retained objects contain results without tool-call inputs. Native objects in other result-only scopes likewise do not manufacture missing call arguments. FUNCTIONS uniquely retains six machine-captured tool arguments and unchanged result objects plus its manifest. These are retained surfaced objects, not an independent harness-backend or OS execution audit.

## File layout and verification

All copied files are flat. MANIFEST.json maps every selected original absolute path and directory to its copied filename, includes exact original modes and byte identities, and records every deduplicated alias. Equal SHA256 and size are insufficient alone: duplicate bytes were also compared directly. Copied files use mode 0644; executable source runners are retained as evidence, never run. Every .go snapshot is renamed .go.txt with repository path, source commit/tree and source-manifest pin. Any .patch bytes would be copied unchanged.

SHA256SUMS directly lists each payload and generated README.md and MANIFEST.json. It excludes itself to avoid a recursive checksum. Run `sha256sum -c SHA256SUMS` from this directory to verify retained bytes; use MANIFEST.json to resolve original absolute-path references inside copied artifacts. Historical absolute paths in originals are not rewritten.

The packager rehashed every copied mapping against its original after copying, including all aliases, and checked excluded ELF identities again. No archives, ELF files, symlinks, subdirectories or direct .go files are present. Packaging did not rerun accepted checks, execute runners/binaries, acquire grants/leases/locks, edit source/Git/shared worktrees, retry or publish. No cloud or remote operation occurred.
