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
| Final-image production admission boundary | PASS at 9b7ba79d | 14 subtests, no skips; earlier 99fa compile failure retained |
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

## Later issued-credential enrollment fixture

[Enrollment evidence](enrollment-fixture/README.md) retains exact APP `92eacab2`
PASS in 2.38s with no skips. Actual enrollment producers complete the grant, an
Agent connects with the issued credentials, current recipient checks pass, and
disabling the grant causes refusal. The original invalid-name fixture failure
is retained. Test-only commits `d34fcb90` and `92eacab2` were imported as
`71203f70` and `9012b9c3`; whole APP fixturetest compilation passed on the exact
union `9012b9c3`. No passing runtime case was repeated. Production startup,
installed credentials and the native/live boundaries remain unqualified.

[Scoped vendor outcomes](../vendor-scoped-67ec90a3/README.md) retain separate
exact-source passes and failures without importing that vendor source or
claiming migration closure. The [first-party source inventory](../first-party-test-inventory-bfca6036/REPORT.md)
records 1,036 files and 4,319 lexical Test candidates; classification and
execution remain unknown.

## Later read-only status correction

[Attempt status evidence](../attempt-status-61aa29d6/README.md) retains exact
`61aa29d6` PASS for all four signed OCI SDK HTTP cases, with no skips
(package 0.273s). Status now includes current SFO node names alongside retained
legacy names. GRU naming, terminated-instance exclusion, both compartment
pagination chains and wrapped later-page errors are covered. The original
`18b3ac46` compilation failure executed no cases and remains in the packet.
The feature branch fast-forwarded to the exact qualified source; no passing
case was repeated and main remains unchanged. Live OCI and migration closure
remain unqualified.

[Corrected vendor receipts](../vendor-scoped-dd038410/README.md) retain the
separate `dd038410` service-latency and authentication-diagnostics passes,
alongside links to their historical failures. This source stays on its own
feature branch. The [three-contract source review](../first-party-oci-contract-review-bfca6036/REVIEW.md)
is bound to frozen `bfca6036`; its F1 status finding is corrected by the
separate evidence above. Its isolated-negative and live-witness gaps remain
open.

## First bounded vendor FIFO result

[Remote latency evidence](../vendor-fifo1-dd038410/README.md) retains FIFO
position 1 on exact separate vendor `dd038410`: one never-run TCP/cluster-route
root passed in 0.177s package time, with no skips. All 55 frozen bindings
matched before and after. At that result, ten serial batches, twelve never-run
roots and 106 TCP-eligible cases remained. The original private interleaving and race-detector
contract remain unqualified; no source removal or central closure is implied.


## Signed SDK/socket observer scenario

[Observer evidence](../observer-sdk-socket-ba75b29a/README.md) retains exact
`ba75b29a`: the root and all ten subcases passed without skips (package 7.699s).
The original three-slot packet checks remain, with one positive create-key
observation and nine independent rejection cases. All 59 service responses
crossed localhost HTTP and passed exact byte/hash and request-sequence checks.
The original default compile failure, one-line stale fixture correction and
corrected compile PASS are retained. Go's standard pinned-PATH prefix caused
a wrapper metadata flag; its unchanged original receipt and separate QA
adjudication are both included. No passing case was repeated. This uses the
existing fixture observer constructor; normal construction, DNS/TLS, live OCI,
full admission, native execution and F3 remain unqualified. Original isolated
cases remain as of this exact source, pending separate retirement review.

## Later vendor FIFO outcomes

These apply only to separate vendor source `dd038410`; no vendor source was
imported into the application feature. Each packet retains exact commands,
individual outcomes, source bindings, raw logs and historical evidence.

| FIFO | Retained outcome | Scope |
| --- | --- | --- |
| [2](../vendor-fifo2-dd038410/README.md) | PASS, 2 roots / 3.247s | Configured imports and activation expiry |
| [3](../vendor-fifo3-dd038410/README.md) | PASS, 22 selected TCP leaves / 0.134s | Parent separate; full 49-leaf root unqualified; 27 startup rows receive zero TCP credit |
| [4](../vendor-fifo4-dd038410/README.md) | PASS, 1 root / 2.374s | Standard permission admission; original private interleaving/race unqualified |
| [5](../vendor-fifo5-dd038410/README.md) | PASS, 50 leaves plus parent / 0.549s | Original private locked-reader stress/race unqualified |
| [6](../vendor-fifo6-dd038410/README.md) | FAIL, 1 root / 2.597s | Received `svc.0`, expected `svc.1`; no retry |

The queue stopped before FIFO7. Five never-run batches (six roots / 30 cases)
remain, alongside the retained FIFO6 failure and all private/equivalence gaps.
[Separate FIFO1 reconciliation](../vendor-fifo1-dd038410/inventory-reconciliation/README.md)
preserves original/derived receipt provenance without overwriting the original
runtime summary. [FIFO4 inventory reconciliation](../vendor-fifo4-dd038410/inventory-reconciliation/README.md)
is historical as of that position; later outcomes do not rewrite its checkpoint.
All original-removal, race, global migration and central-closure claims remain
open. Main remains `72e90371`.
