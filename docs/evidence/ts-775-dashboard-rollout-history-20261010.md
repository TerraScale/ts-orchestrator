# TS-775: retain regional rollout phases and exact detail

## Defect and change

Terminal rollout commits retain their validated v1 `Record` in `TS_ROLLOUTS`
and clear the cell's active slot. The dashboard used `Store.Rollouts`, which
reads only that slot, for both `/rollouts` and `/rollouts/{id}`. A completed,
aborted or rolled-back rollout therefore lost its phase, timestamp and diagram
while its record and terminal journal decisions remained readable.

The dashboard now reads recorded controller/host stages for the newest 64
release generations plus the active rollout. Discovery uses derived stage IDs,
bounded reads and existing record validation, without scanning all KV keys.
Exact-ID detail reads the retained record independently, including records
outside that recent list. The insight engine still reads only the active slot.
Both reads use the existing five-second dashboard cache; failed refreshes show
unavailable data rather than cached terminal success or a successful empty list.
Cache lifetime starts at result insertion, so a five-second provider timeout
still receives five seconds of shared failure reuse after the read completes.

No persisted shape, v1 schema, KV key or release-state-machine behavior changes.
No migration, backfill, reset, new API, dependency or feature switch is needed.
The source retains terminal record keys without a TTL; the 64-generation list
is a discovery window, not a promise of seven days of history. Managed-update
detail remains separate from exact release-record lookup.

The existing fake dashboard world is now confined to `_test.go` fixtures.
The tagged standalone preview command and its Make target are deleted, retaining
page/stream fixture coverage without executable fake providers or an opt-in tag.

## Before and after locally

The actual embedded-NATS/store/controller/dashboard lifecycle regression fails
against the original implementation: terminal records clear the slot and remain
loadable, but both pages omit their terminal status pill, stored phase-start
time and diagram. Exact detail also fails after 64 further release generations.
The negative-control overlay and authenticated original sources are under
`/tmp/ts775-rollout-implementation/negative-control/`; `before.log` and
`before-overlay.log` record the expected failures.

The corrected production wiring passes complete, aborted, rolled-back and
frozen lifecycle cases, reconnect/new-store persistence, real cache expiry,
older exact-ID detail, authenticated journal/chain identity and unauthorized
request rejection. Other regressions cover sparse stages, 0/1/64/65/max-uint64
generation arithmetic, at most 131 KV reads, deduplication/order, active records
outside the window, abandoned/missing versus malformed/wrong-scope records,
cancellation/disconnection, read-only revisions and sanitized error display.
Retained nonterminal orphan records do not become active deadline insights.

PR review also found that a release-record read failure hid independently
available managed TerraBase update data. The detail view now renders the exact
managed operation from placement before considering release-provider failure.
The existing page warning still names the unavailable release source; it does
not make that unrelated failure an unknown managed phase. The regression checks
artifact, seat progress, phase counts and progress bar for missing, unattached
and failed release providers. With placement absent, the release failure still
shows unavailable rather than a successful empty or invented update.

That corrected regression fails against the prior template (missing all five
managed evidence fields), then the entire dashboard race suite passes after
moving the branch and regenerating the template. Logs are
`/tmp/ts775-managed-update-outage-before.log` and
`/tmp/ts775-managed-update-outage-after.log`. The unchanged full recheck passed
in `/tmp/ts775-managed-update-full-recheck.log`; independent review approved
the source and clean committed release checks passed for `f137ea9f` in
`/tmp/ts775-managed-update-release-check.log`.

CI run [2106](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/2106)
failed the aborted lifecycle case at that exact revision. The regional decision
API returned both expected admission/aborted records with `partial=true` while
the asynchronously attached stream was replaying. `Journal.Query` deliberately
reports that state as partial; the test incorrectly demanded completeness on
its first request. This is distinct from the earlier local bootstrap timeout.
The exact run ID is `16646`, job ID `38002`; its retained log is
`/tmp/ts775-ci2106-job-38002.log`.

The lifecycle test now waits only while that API reports partial, within its
existing 45-second context. HTTP errors, malformed JSON and truncated results
still fail immediately; permanent replay still fails at the original deadline.
Terminal phase, regional identity, journal chain, authentication, persisted
records and list/detail assertions remain required. No production behavior,
test tier, timeout or completeness guarantee changes.

An uncached 12-run race check using CI's Go concurrency settings reproduced
the same failure before this correction, then passed all 12 runs after it:
`/tmp/ts775-ci2106-before.log` and `/tmp/ts775-ci2106-after.log`. Full verification
for this correction is recorded separately in `/tmp/ts775-ci2106-full-check.log`.
Fresh independent review and exact-commit release checks gate its publication.

Focused rollout/insights/dashboard/fixture race suites, app integration,
vet, generation and native build passed. The parent full local command also
passed with `umask 022` and `nice -n 19`:

```sh
nice -n 19 mise exec shellcheck@0.11.0 -- \
  make --keep-going verify build shellcheck fixturetest-check
```

The full log is `/tmp/ts775-rollout-full-check.log`; implementation commands,
tests and source identities are in `/tmp/ts775-rollout-implementation/REPORT.md`.
The full command also passed after the fixture-only move, with exit 0 confirmed
by the parent (`/tmp/ts775-rollout-test-only-full-check.log`).

Independent review round 1 found that the shared cache stamped entries before
the provider read, so deadline-length failures were expired immediately upon
insertion. The one-line correction stamps the completed result instead. A
permanent synthetic-time regression exercises both real list and exact-detail
handlers with five-second child-context deadlines. It fails before the fix
with three provider calls instead of one, then passes shared reuse until the
full TTL and a fresh read at expiry. The whole dashboard race suite passed
after correction (`/tmp/ts775-rollout-cache-deadline-after.log`); the failing
control is `/tmp/ts775-rollout-cache-deadline-before.log`.

The full command is rerun for the cache correction, logged at
`/tmp/ts775-rollout-cache-fix-full-check.log`. Fresh independent approval and
clean exact-revision release checks remain required before publication.

## Live baseline and acceptance boundary

Fresh reads on 2026-10-10 first verified all six connected controller names/IPs
with the existing local `netbird-wt0` daemon and bound direct requests to its
`nb-wt0` interface. Existing regional token files were used without printing
their values, proxies or redirects. Captures are under
`/tmp/ts775-rollout-history-live-before/`.

All six controllers returned 200 for `/rollouts`, `/releases`, `/metrics`,
`/readyz` and `/storage`; `/v1/snapshot` still returned 404. GRU's list displays
its older frozen rollout. Each SFO list says "No release rollout is known in
this region", despite the earlier signed-release completion evidence. Serving
version observations remain GRU `1e57e6c17362`/`93c6b7e3df4f` and SFO
`107e060af74f`. These are older serving builds, not acceptance of this patch.

The broader access check finished with exit 1: all six SFO IP/native-DNS home
page reads exceeded five seconds, and each SFO members page showed only one
observed controller rather than the expected three. GRU checks passed.
A successful targeted read does not make that broader check green. Its output
is `/tmp/ts775-rollout-live-before-check.txt`; retain these timing and inventory
failures in the page audit and recheck after the qualified rollout.
GRU/SFO link repair remains TS-774 and global page fan-out remains TS-794.

After a qualified signed deploy, verify the main run, all serving revisions,
readiness and regional quorum first. Read the real regional terminal decision
for that signed generation and its `attrs.rollout`; compare list and exact detail
on all six controllers. Require the terminal **status pill**, stored timestamp
and phase diagram, not merely the always-rendered word "complete" in a diagram.
Repeat after the five-second cache lifetime and the next already-authorized
restart/leader handoff. Use a known retained older record to verify exact lookup
outside the list window. No synthetic live rollout is needed for a UI check.

Live-after acceptance is pending. No deployment, serving-cell rebuild, rollout,
backup creation, credential provisioning or storage reset occurred in this slice.
Older serving rollout-key formats remain the existing signed-deployment boundary
recorded in [TS-783's evidence](ts783-rollout-storage-20261010.md); this change
adds no old-key decoder or reset procedure.

## Dependencies and remaining page audit

COS merged #364 as `5f56292c1004a2b1e88985732ee736da05b2069a` on main.
This branch is rebased onto that revision; Git dropped the equivalent `fe8df08e`
fixture prerequisite. Full checks still use real harness-derived rollback IDs;
no test budget is changed. Rebased validation is recorded separately in
`/tmp/ts775-rollout-main-rebase-full-check.log`, and clean exact-commit release
checks and fresh independent review gate the force-with-lease publication.
#366 remains the dependency for the separately approved backup-completion slice,
whose local commit `00763eb8` is preserved. This rollout slice only reads existing
records and does not add an OCI cancellation boundary.

TS-796 overlap is limited to the existing controller store-to-observation wiring
in `controller.go`, `observability.go` and `decision_journal.go`. No config,
cadence or switch path is added or replaced. The removed fake preview is also
reported as overlap with TS-796. TS-794 owns global rollout views.

The earlier [fourteen-page audit](ts-775-dashboard-metrics-storage-20261009.md)
and [route RTT/deployment evidence](ts-775-dashboard-route-rtt-20261009.md) remain
the acceptance ledger. This slice fixes retained local release phases/detail.
The remaining TS-775 implementation slices are authoritative host-agent/TerraBase
running versions and actual running/failed/passed CI-run inventory. Desired
digests and successful admitted-release manifests cannot establish those views.
The empty OCI inventory stays with TS-782; names with TS-776; link repair with
TS-774; cross-region fan-out with TS-794; switch removal with TS-796.

Risk: these checks prove durable read/display behavior locally. They do not
prove that today's fleet runs a recorded completed release or that the new
signed revision is serving in either region.
