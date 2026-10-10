# TS-775: local NATS route RTT and deployment verification

## Serving state after #358 merged

PR #358 merged as `3473c03dd1ff81f280b7836b61211076acecf096`.
Its exact main CI run [#1949](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/1949)
failed `TestReleaseChannelRollsCIReleasesOutRegionByRegion` before fleet
deployment. The lab expected `rolled-back`, but control-plane rollback
exhausted its 20-second fixture deadline and froze. A local watchdog's
successful binary restore does not establish completed control-plane
rollback: the controller still needs durable state, safety gates, an accepted
step and a fresh proof after acknowledgment. The production rollback path
and fixture were unchanged by #358.

This slice raises only the six-broker fixture's rollback budget from 20 to
60 seconds. A deterministic executor regression holds gate recovery for
25 seconds: the short budget freezes without sending rollback, while the
longer budget still requires an accepted acknowledgment and a fresh newer
proof. Unaccepted retries, cached/stale proofs, unchanged deadline, known-bad
recording and stopping later units remain enforced. No production rollback
deadline or safety gate changes. Focused low-priority race checks at
`GOMAXPROCS=2` passed the executor package (11.05 seconds), previously failing
release-channel E2E (50.62 seconds) and running-cell E2E (50.73 seconds).
The CI runner's exact contention has not been reproduced; qualified main CI
remains the deployment requirement.

At 2026-10-09 23:42–23:43 UTC, authenticated reads over delta's verified
NetBird interface `nb-wt0` found these serving revisions:

| Region | Controller A | Controller B | Controller C |
| --- | --- | --- | --- |
| GRU | `1e57e6c17362` | `93c6b7e3df4f` | `93c6b7e3df4f` |
| SFO | `107e060af74f` | `107e060af74f` | `107e060af74f` |

All six system scrapes still had `ts_orch_collect_ok{section="system"} 1`,
one CPU, about 4.09 GB RAM and 50,884,108,288 filesystem bytes. Real
`/members` chart payloads showed GRU CPU 29.26%, memory 36.92%, disk 27.30%;
SFO CPU 36.75%, memory 30.87%, disk 10.96%. The earlier systemd `/proc`
repair remains effective. The merged physical-node/storage model has not
been verified live; the old `/v1/snapshot` still returned 404.

Read-only Object Storage inventory found four objects in each verified head
bucket, `gru-1-head` and `sfo-1-head`, namespace `grxnmoqvrcdv`: host enrollment,
rollouts, service set and trust roots. Their explicit prefixes are
`kv-snapshot/v1/gru/` and `kv-snapshot/v1/sfo/`. Snapshot contents and secrets
were not exported. The new snapshot-health UI remains pending deployment.
This blocked-verification evidence was posted as Ku comment
`aadb1804-b042-4656-8ef8-5d3944cfec9a` on TS-775.

No unsigned binary was substituted, no cell was rebuilt and no live archive
was reset while old writers remained. The targeted v1 host-history reset and
all-controller acceptance procedure remain in the
[metrics/storage evidence](ts-775-dashboard-metrics-storage-20261009.md#deployment-evidence-boundary).

## Route RTT before and after

Authenticated `/nats` reads on GRU A (`10.200.87.215`) and SFO A
(`10.200.112.213`) at 2026-10-09 23:56 UTC returned HTTP 200 and the permanent
message: “Route round-trip times are not sampled yet”. Both peers were
connected in the selected NetBird inventory before the requests. Captures
are in `/tmp/ts775-route-live-before/{gru,sfo}/nats.html`.

The new path reads the embedded broker's existing PING/PONG measurements
through `Routez`, groups pooled/dedicated connections by observed peer,
and carries maximum positive RTT plus measured/total coverage through the
v1 snapshot, Prometheus, existing history sampler/persistence/API and NATS
page. Unset or invalid RTT never becomes measured zero. Disconnect removes
the current peer's metrics and stops new samples. Current snapshots display
unavailable/stale evidence and inventory bounds explicitly. The chart keeps
sub-millisecond precision and formats microseconds, milliseconds and seconds.

Local checks use three real embedded brokers to verify observed identities,
pooled connections, positive RTT, metric/history delivery and disconnect
removal. Rendered HTML tests retain both directions and preserve a
13.37-microsecond point exactly. Coverage tests exercise unknown, partial,
stale and truncated observations and existing history export/import and v1
API. These are local after-change checks, not live deployment evidence.
The generic history storage format is unchanged; this slice adds metric
names, without migration or backfill. No monitor listener, dependency,
configuration switch or cross-region view is added.

## Local validation

Passed with `umask 022`, at low CPU priority:

```sh
nice -n 19 mise exec shellcheck@0.11.0 -- make format-check generate-check vet build shellcheck fixturetest-check
nice -n 19 mise exec shellcheck@0.11.0 -- make verify
nice -n 19 go test -race ./internal/dashboard ./internal/natscell ./internal/observability -run 'Test(NATSRouteRTT|ObserveRoutes|EmbeddedRouteRTT|RouteRTT)' -count=1
nice -n 19 go test -race ./internal/dashboard -run '^TestNATSRouteRTT' -count=1
```

The latest complete parallel race run includes the previously failing release-channel
E2E, which passed in 50.038 seconds. Independent T3 pre-push review approved
all changed files with no actionable findings. JavaScript formatter
checks confirmed microsecond/millisecond/second labels; serving RTT and merged
storage acceptance still require the signed deployment.

An additional full local run failed before run-1 admission: both cells kept
reporting run 0 and no release channel until the two-minute region wait
expired. This differs from the rollback-budget failure. Four uncached focused
race executions passed in 47.47, 48.19, 50.39 and 47.91 seconds. The failed run
also logged slow JetStream snapshots, but contention is not proven to be its
cause. No further rollout deadline change was made; the failed log is retained
at `/tmp/ts775-route-peak-coverage-verify.log`.

The #362 completeness review added regressions that failed before correction:
unidentified, omitted or failed collection cannot claim an empty route
inventory, and a recovered current snapshot cannot hide earlier omissions
within the chart's selected range. The chart reads the sampler's retained
inventory-truncation metric with the same bounds as RTT and keeps positive
bucket maxima visible through rollups. Out-of-range gaps and complete history
do not trigger the warning. Empty/unavailable table rows also show their
snapshot observation time. This changes only presentation, not stored data.

The next #362 review identified averaged RTT peaks and incomplete measurement
coverage. The chart now selects each RTT bucket's maximum, validating that
selected value for NaN/Inf, while other gauges retain their averages. It also
compares retained total/measured connection averages by member, server, peer,
tier and timestamp. The sampler emits both counts together, so any deficit
survives recovery and rollups without treating complete count changes as gaps.
Missing counterparts, unmatched RTT coverage and any query/replay bounds keep
the existing partial warning visible, including peers with no measured RTT.
Regressions reproduced both findings before correction and cover raw/1m/5m/1h
history, invalid peaks, complete changing counts, out-of-range gaps, missing
coverage, 65 coverage series and existing history export/import. Additional
review checks require RTT evidence when retained counts claim measurements
and align restored/fresh series to their common bucket tier before comparison;
an old restored gap outside the selected range does not taint fresh coverage.
History compares existing coarse bucket counts against aligned finer bucket
counts so same-minute recovery cannot hide persisted rollups, even when a
bounded snapshot retains only hourly buckets and the dashboard selects 15m.
This evidence survives repeated export/import and recovery, without adding
serialized state. Complete fine coverage remains selected when missing older
samples lie before the query. The chart also compares bucket sample counts,
so a fresh RTT cannot hide an earlier lost RTT in the same hourly bucket after
a bounded export. Recovery, repeated-restart and live hour-boundary resolution
counterexamples failed before correction and now pass. Sample counts are
in-process query metadata excluded from JSON;
they already exist in the stored buckets. These remain local checks; the
generic history format, v1 APIs and broker producer are unchanged.

## #362 merge validation (2026-10-10)

#362 merged as `6b2474212684874b000edfccf400917391ac00d1`. Its exact
main CI [#2032](https://git.terrascale.tech/TerraScale/ts-orchestrator/actions/runs/2032)
failed both `TestExecutorRollbackDeadlineIncludesGateRecovery` cases;
`deploy.yml` did not start. The executor had correctly moved the canary,
but the test loaded a different rollout ID and saw an empty record. TS-783
had changed the shared harness to use the canonical release-generation ID;
the new regression still derived controller and host IDs from `rel1`.

The failure reproduced locally with the race detector. The correction reads
both IDs directly from the harness's generated program. It preserves the
20/60-second budgets, gate-recovery delay, acknowledged rollback, cached/stale
proof rejection, fixed deadline, known-bad assertion and later-unit checks.

Authenticated reads from delta at 04:53–04:57 UTC verified every target as
one Connected NetBird peer with the expected FQDN/IP and route through
`nb-wt0`. Curl bound to that interface, bypassed proxies and redirects, and
received credentials through stdin. All fourteen sidebar pages returned
HTTP 200 on all six controllers; this proves availability, not correct data.
`/metrics` and `/readyz` also returned 200, while `/v1/snapshot` and
`/v1/regions` returned 404 everywhere. Both regional `/nats` pages still
said route round-trip times are not sampled.

Read-only Object Storage metadata also confirmed four configuration snapshot
objects in each verified regional head bucket, `gru-1-head` and `sfo-1-head`,
under `kv-snapshot/v1/gru/` and `kv-snapshot/v1/sfo/`. Object contents were
not read. Their presence does not establish the new snapshot-health checks;
those still require the merged binary.

The following percentages are the final CPU, memory and disk points in each
serving controller's real `/members` chart payload. They prove the earlier
systemd collection repair remains effective; they do not prove deployment of
the merged host/filesystem/storage/RTT model.

| Controller | Serving revision | CPU | Memory used | Disk used |
| --- | --- | --- | --- | --- |
| GRU 1 | `1e57e6c17362` | 36.53% | 37.22% | 28.01% |
| GRU 2 | `93c6b7e3df4f` | 23.14% | 26.55% | 25.54% |
| GRU 3 | `93c6b7e3df4f` | 26.54% | 24.97% | 24.17% |
| SFO 1 | `107e060af74f` | 39.41% | 30.41% | 11.56% |
| SFO 2 | `107e060af74f` | 23.63% | 24.81% | 9.835% |
| SFO 3 | `107e060af74f` | 21.95% | 21.93% | 9.881% |

All six system collectors reported success. Host-history replay readiness
was zero on GRU 3 and one elsewhere; archive-incomplete was zero everywhere.
Transient captures remain in `/tmp/ts775-post362-pages-before` on delta and
contain no captured request headers. No archive reset ran with old writers.

Read-only `ts-orch release fleet-status --namespace grxnmoqvrcdv` additionally
found GRU still targeting `d7a257ec`/run 1835 with reason "the cell's rollouts
are paused", without environment/architecture scope. SFO reported the older
`107e060af74f`/run 1849 complete with `canary`/`arm64` scope. These deployment
conditions predate #362. The deployment-lag guard's 19 lag/proof failures are
not attributed solely to this new merge. TS-774 retains the root-signed
identity/telemetry handoff and TS-746 the existing GRU recovery; no manual
deployment bypass was attempted.

Post-merge evidence was posted on TS-775 as Ku comment
`7363514c-a644-41e2-8511-20fd34dc63ce`. The follow-up audit retained four
defects: unobserved volume-backup completion, unattached CI run inventory,
missing host/TerraBase version inventory, and completed rollout phase details
lost after active-slot release. The next storage slice is on
`cos/ts-775-volume-backup-completion`; its switch-adjacent overlap was reported
to TS-796. Global fan-out remains TS-794 work.

## Remaining acceptance work

The [fourteen-page audit](ts-775-dashboard-metrics-storage-20261009.md#dashboard-and-api-audit)
also retains full qualification/version inventories and observed volume-backup
completion as later TS-775 slices. TS-794 owns global fan-out, TS-796 owns
switch/cadence/session removal, and TS-782 owns the empty OCI dashboard.
TS-775 is not DONE until a qualified signed deployment reaches every
GRU/SFO controller, the required v1 telemetry reset completes and fresh
CPU/memory/filesystem/snapshot evidence is checked on the serving dashboard.
