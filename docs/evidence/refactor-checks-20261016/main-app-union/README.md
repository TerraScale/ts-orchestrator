# Main and application source union — 2026-10-16

This is retained source and local qualification evidence for the feature branch
`refactor/qa-main-union-20261016`. It does not authorize advancing main.

## Source

Frozen source `99fa294562aeb87929d85e7ece8395379481d03b` composes main
`72e903719c7b53dee94305f50b3bdb8b147f0eda` with application source
`3d9a933e0f59f3e69888d2cb17ed60d8ddea0457` and the owned deltas recorded
in `ts-main-union-source-resolution-20261016.json`. Thirteen conflicts were
resolved while preserving independent final-image proof and stronger release
checks. Instruction files were unchanged. Five original third-party assets
retain their exact upstream bytes, including upstream whitespace.

Later, test-only capacity commits `1cd6b189` and `19558037` were imported as
`86cf0969` and `1a75a41e`. No passing capacity cases were rerun. Their individual
receipts apply to the exact revisions recorded in the capacity ledger, rather
than one combined current-union suite.

## Local checks

| Check | Result | Scope |
| --- | --- | --- |
| Whole application test-package compile | PASS | Frozen 99fa2945; no tests executed |
| Static linux/amd64 command build | PASS | Frozen 99fa2945; development build |
| Static linux/arm64 command build | PASS | Frozen 99fa2945; development build, no native execution |
| Final-image production admission boundary | COMPILE FAILURE | Missing serviceMigrationFixture; no tests ran |
| Capacity owned leaves | 25 individual PASS receipts | Exact original/repair sources in retained ledger |
| Application membership current-grant read | PASS | ddc22a6e; signed observer, positive leader reads, zero DIRECT reads |
| Registry post-Vault current-admission guard | Four leaves PASS | e8c70091; no whole-union claim |

`build-receipts.json` records artifact hashes and local paths. Empty build logs
are retained; binaries are not committed. Local checks used Go 1.27.1,
GOMAXPROCS=2, GOFLAGS=-p=2 and nice -n 19. Static binaries are not stamped
production artifacts and establish no runtime admission.

## Actual published-main workflows

These apply to main 72e90371, separately from this union:

1. [CI 38976624335](https://github.com/TerraScale/ts-orchestrator/actions/runs/38976624335)
   passed, including both static builds and downstream dispatch.
2. [Image 38978307685](https://github.com/TerraScale/ts-orchestrator/actions/runs/38978307685)
   failed real-infrastructure qualification: the seven requested suites lacked
   required TerraBase, D11, native validator or rendered SFO fixtures. The raw
   log also contains an earlier Nix guestfs build error.
3. [Deployment 38978309858](https://github.com/TerraScale/ts-orchestrator/actions/runs/38978309858)
   failed before credentials because no serving region had exact retained
   production qualification.

Raw workflow and capacity logs are retained as deterministic gzip archives.
Gates remain intact; no workflow retry, credential change, cloud provisioning
or deployment was performed for this evidence. Connected full application
startup/recovery, protected-writer IAM and child creation, native/final image
qualification, live regional/stateful acceptance, integration migration
closure and measured operational benefits remain open.

## Later bounded startup fixture

[Startup fixture receipts](startup-fixture/README.md) retain exact APP `582a3992`
PASS, the earlier rejected marker-mode fixture, and union `4e5fcb5c` whole APP
fixturetest compile PASS. READY is manually emitted and observed; production
startup and positive material delivery remain unqualified. No passing runtime
case was repeated on the union.

## Later release admission check

The original signed migration fixture helper from `452f19de` was restored by
REL `de07c2d9` and imported as `9b7ba79d`. The exact union then passed
`TestFinalImageProductionAdmissionBoundary`: 14 subtests, no skips, 0.710s package.
[Receipt](release-admission-receipt.json) and the raw `9b7` log supersede the
historical `99fa` compile failure for this one selected check. This is local
source admission regression evidence; native/live and whole-union runtime
qualification remain open.
