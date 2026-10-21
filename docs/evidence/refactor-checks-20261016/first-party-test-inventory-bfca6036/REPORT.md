# First-party Go test source inventory

Frozen HEAD: `bfca60368f60d2da67f9016d1d489317ae8749c8`
Frozen tree: `7b0b97136b7225c4897917bf600f76d5c069560f`
Generated UTC: 2026-10-16T23:23:29.529724+00:00

## Verified artifact scope

The inventory contains **1,036 tracked first-party `_test.go` blobs**, read from immutable Git objects at the exact HEAD above. Every `third_party`, `vendor`, and `.git` path component is excluded. Both root-module and nested-module files are included. Working-tree status was empty before and after generation. Nothing in the source worktree was changed.

| Declaration kind | Lexical count |
| --- | ---: |
| Test candidates | 4,319 |
| TestMain candidates | 4 |
| Benchmark / Fuzz / Example candidates | 0 / 0 / 0 |
| Named non-method helper functions | 1,663 |
| Total recorded declarations | 5,986 |

996 files contain a Test or TestMain candidate; 40 have neither. Helpers, constants, methods, fixtures and build variants can still make those 40 files necessary. This report makes no deletion recommendation. All 4,323 entry candidates have lexically compatible signatures; none were typechecked. No lexical extraction errors were recorded.

## Explicit unknown closure

| Question | Status |
| --- | --- |
| Unit / integration contract classification | **Unclassified** for all 1,036 files and 5,986 declaration records |
| Manual source / assertion review | **Unknown** for every record; no exhaustive manual review |
| Test execution, race results, reliability | **Unknown** for every record; no runners executed |
| Exact package/build selection under any runner | **Unknown**, not evaluated |
| Integration quality or end-to-end completeness | **Unknown**; no inference from names, directories, or direct tier calls |

The artifact is a source declaration inventory, not a claim that 4,319 tests were discovered, executed or passed. No classification from the old draft was promoted. No original artifact was deleted or modified.

## Old draft provenance

`/tmp/ts-refactor-qa-test-inventory.tsv` has SHA-256 `a95c65d54d7292d3b42d26d9d0f1a828a84639cd981332f724842dbd948d60a1` and 1,012 data rows. Its recorded 8,418 test and 323 benchmark declarations remain **unverified draft counts**. It has no producing command, commit/tree binding, per-file hashes, or classification/closure evidence. The existing inventory owner reported no verified producing command or source snapshot; that owner's authoritative inventory concerned vendored NATS only.

`docs/evidence/refactor-recovery-20261016.md:69` mentions the TSV. A mention and filesystem mtime do not establish the producing source snapshot. The evidence document's own snapshot commits cannot be assigned to the TSV without evidence.

The draft includes 131 `third_party` rows, outside this audit's scope; it has 881 first-party rows. First-party path comparison: **862 shared, 19 draft-only, 174 frozen-only**. `draft-comparison.tsv` excludes third-party paths and preserves old counts beside refreshed counts, including a separate Test-plus-TestMain alternate. Shared paths or matching counts do not prove identical old bytes or scanner semantics. Draft-only does not establish a deletion or a defect.

## Runner policy observed in frozen source

1. **T0 PR:** `.github/workflows/ci.yml` sets `TS_TEST_TIER=pr`; `Makefile` routes to `scripts/ci/racetest/race-test.sh`, whose PR mode adds `-short`. `tier.Integration` skips only when `testing.Short()`. T0 is therefore not a verified unit-only selection.
2. **T1 pushes:** `TS_TEST_TIER=full` omits `-short`; `ci-verify` also runs `fixturetest-check` (`go vet -tags fixturetest ./...` and fixturegen `go test -tags fixturetest`). Plain `make test` uses `go test ./...`; `test-fast` uses `go test -short ./...`.
3. **Race scheduler:** root-module package discovery uses `go list ./...`. It shards `internal/app`, `internal/bootstrapstart`, `internal/natscell`, and `tests/deploy`; other discovered packages run together. Sharded listing uses `go test -race -vet=off -list '.*'`, then ASCII `^(Test|Example|Fuzz)[A-Za-z0-9_]*$`. Its packed-count check covers only those selected listed names. Scheduling classes and duration estimates do not establish test contracts.
4. **T2 image:** the seven explicit selectors below share 600 seconds. `TS_TEST_TIER=qualification` makes missing fixtures fatal through the tier helper. The shell runner rejects any selected SKIP or absence of a top-level PASS. `image.yml` supplies all seven before image build when its gate proceeds. Presence of these rules is source evidence, not a successful qualification receipt.
5. **Nested module:** `e2e/go.mod` owns 3 test files / 9 Test candidates. Root `./...` does not automatically cover it. `.github/workflows/e2e.yml` separately runs `go test -race ./...`, vet and build from `e2e`, then the E2E driver. Workflow triggers and actual executions were not audited beyond source inspection.

`tier.Qualification` skips for missing fixtures in ordinary runs, fails for missing fixtures in qualification, and can run outside qualification when fixtures exist. It requires at least one fixture name. `tier.Unavailable` similarly skips ordinarily and fails in qualification. Ordinary CI can pass with skips. Indirect helper calls and tests missing a tier gate cannot be ruled out by this inventory.

| Qualification suite | Package | Selector |
| --- | --- | --- |
| terrabase-walkthrough | ./internal/app | `^TestTerraBaseWalkthroughAgainstRealMembers$` |
| terrabase-successor | ./internal/managedmaterial | `^TestProduceSuccessorRustInterop$` |
| native-validator | ./internal/managedmaterial | `^TestPrepareInitialUsesAdmittedPackagedNativeValidator$` |
| rendered-sfo-enrollment | ./internal/app | `^TestManagedPlacementEnrollmentFromRenderedSFOBundle$` |
| terrabase-binary | ./internal/terrabase | `^TestTerraBaseBinaryPeerMesh$` |
| terrabase-release | ./internal/app | `^TestTerraBaseReleaseDeployUpgradeRollback$` |
| ts-auth-terrabase | ./internal/tsauth | `^TestBootstrapAgainstTerraBaseRelease$` |

The seven selectors each resolve to one lexically observed declaration in this snapshot; file and declaration hashes are in `qualification-selectors.tsv`. This confirms source presence only. `CONTRIBUTING.md:116` says “eight” suites, while the actual script and workflow enumerate seven; this report follows executable source.

## Explicit coverage exceptions and limits

1. **Race exceptions:** `race-durations.txt` assigns `internal/bootstrapstart` patterns `TestFounderRuntime*`, `TestFounderReplacement*`, `TestReplacement*`, `TestFencedReplacementStopsBeforeEveryMutation`, and `TestFounderFloorArtifactsMatchInitializedPeerFloor` to `norace`. Static matches are 30, 3, 2, 1 and 1 declarations (37 distinct), preserved in `norace-static-matches.tsv`. Runtime selection remains unknown.
2. **Qualification exceptions:** the runner comments exempt `TestBackupGoRust*ProcessBridge` D10 children because a Rust parent supplies packets/results. Firecracker qualification uses `ts-orch qualification firecracker ...` on KVM outside this script. These comments explain intent, not proof those paths ran elsewhere. Seven selectors do not exhaust all qualification-gated source declarations.
3. **Scope exceptions:** the separate vendored NATS module and its `nats-identity-check` regression are excluded. 50 first-party test files carry leading build constraints; the three nested-module files have separate discovery. GOOS/GOARCH filename rules, build tags, toolchain, cgo, testdata and dot/underscore directory rules were not evaluated into runner inclusion. A textual declaration can be excluded from a given build.
4. **Execution limits:** no benchmark run (`-bench`) or fuzz campaign (`-fuzz`) is present in these tier runners; fuzz seed cases can run under ordinary Go tests. TestMain executes per package binary rather than as an individually listed test. Subtests, generated tests, registrations and runtime case counts are not enumerated.
5. **Scanner limits:** a Python lexical tokenizer skips comments, interpreted/raw strings and runes, scans package-level named non-method functions, and applies Go-style entry-name casing plus syntactic testing-parameter checks. It is not a Go parser/typechecker and does not validate all grammar, aliases, shadowing, example output rules or compiler discovery. Direct tier observations (17 Integration, 14 Qualification, 3 Unavailable call expressions across 30 Test and 4 helper declarations) are syntactic only; alias shadowing, indirect helpers, reachability and fixture contracts remain unknown.

## Artifact use

`files.tsv` binds every file to Git blob OID and SHA-256, build preamble observations, counts and unknown statuses. `declarations.tsv` adds source lines, declaration hashes, candidate signature status and direct tier observations. Both use the exact HEAD/tree recorded in `metadata.json`; filenames alone carry no classification.

`generate.py` reproduces the source scan, comparison and metadata. `finish.py` renders this report and runner selector artifacts. They write only beside themselves under `/tmp`; no Go, build, test, lint or race command is invoked. Synthetic scanner assertions passed; those checks are not repository test evidence. Automated scanning covered every scoped blob; manual inspection stayed bounded to runner sources and selected snippets, not more than 1,000 files.

`SHA256SUMS` seals every artifact here except itself. The original draft SHA is rechecked. Required next evidence for classification or closure is a bounded contract review plus applicable runner receipts bound to this exact source; neither exists in this inventory.
