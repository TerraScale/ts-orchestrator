# Decision journal, history, insights and region view

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

The decision journal answers "what did the orchestrator decide, and why".
Four read-only slices feed the dashboard from it:

| Slice | Package | What it provides |
| --- | --- | --- |
| Decision journal | `internal/decisionlog` | `Record`, the regional `TS_DECISIONS` stream, queries, chains, cross-region federation |
| Metric history | `internal/observability` (`History`) | raw/1m/5m time series for about 24h, range queries, KV snapshots |
| Insights | `internal/insights` | ranked "needs attention" problems with evidence and actions, 1h/24h summaries |
| Region view | `internal/regionview` | one summary card per region: health score, quorum, leaders, versions, capacity, rollouts, decisions, insights |
| Region links | `internal/regionlink` | read-only request/reply to other regions' `ts.orch.v1.<region>.obs.<leaf>` subjects |

None of these slices is admission evidence, and nothing in the control plane
reads them back to decide anything.

## Recording a decision

Call `decisionlog.Record` at the point where your slice has *committed* a
decision: after the durable write, compare-and-swap or API call that makes
it real, not before. Record exactly once per decision, on the path that
performed it, so retries and redeliveries do not duplicate records.

```go
id := decisionlog.Record(ctx, decisionlog.Decision{
	Region:  cell,                                   // lowercase cell token; the Journal fills it when empty
	Actor:   decisionlog.Actor{Slice: "autoscale"},  // the Journal fills Actor.Member
	Kind:    decisionlog.KindScaleUp,
	Subject: decisionlog.Subject{Kind: "database", ID: databaseID, Name: "orders/p0"},
	Summary: "Scaled orders/p0 from 3 to 5 seats",   // one plain sentence: what
	Reason:  "Write latency p95 stayed above its target for 10 minutes.", // why
	Rule:    "autoscale.latency_p95",
	Signals: []decisionlog.Signal{{
		Name: "write_latency_p95", Value: 41, Unit: "ms",
		Comparison: "<=", Threshold: decisionlog.Threshold(25), Passed: decisionlog.Passed(false),
	}},
	Alternatives: []decisionlog.Alternative{{Option: "scale to 4", Reason: "projected p95 still above target"}},
	Status:   decisionlog.StatusInProgress,
	Epoch:    snapshot.Epoch,                         // the authority epoch you held
	ParentID: parentID,                               // optional: chain under an earlier decision
})
```

Rules for callers:

- `Record` never blocks on the network and never returns an error. It
  indexes the decision in memory, queues it for the background writer and
  returns the ID. A full queue drops the durable copy and counts it in
  `ts_orch_decisions_dropped_total{reason="queue_full"}`; a stream that
  rejects it after retries counts `reason="publish_failed"`.
- Never let recording change the decision path: do not branch on the
  returned ID, do not wait for it, and keep building the record cheap.
- `Summary`, `Reason` and `Outcome` are short fixed phrases. Never put raw
  upstream error text, secrets, tokens or signed payloads in a record.
- A record is immutable. A later status (succeeded, failed, rolled back) is
  a **new** decision whose `ParentID` names the first one.
- Use the `Kind*` constants in `decision.go`. A new kind is any short
  `lower_snake` token; add it to `kindNouns` in
  `internal/insights/summary.go` so summaries read well.
- Before a controller installs its journal (and in processes that never do,
  such as one-shot CLI commands and hosts) records go to the structured log
  as `component=decision` events, so nothing is lost silently.

### Chaining across slices

When one slice starts a chain and another continues it, use the process-wide
correlation table instead of sharing state:

```go
// release admission (rollout slice)
id := decisionlog.Record(ctx, decisionlog.Decision{Kind: decisionlog.KindReleaseAdmitted, ...})
decisionlog.Correlate("release:"+digest, id)

// canary promotion (later, maybe another slice)
decisionlog.Record(ctx, decisionlog.Decision{
	Kind: decisionlog.KindCanaryPromoted, ParentID: decisionlog.Correlated("release:"+digest), ...})
```

The managed TerraBase update already does this with
`placement.ManagedUpdateCorrelation(operationID)`: the admission is the root,
and the reconciler's `upgrade_started`, `canary_promoted` or `held`
decisions are its children. `GET /v1/decisions/{id}` returns the whole chain
(`Root`, every decision oldest first, and `Latest`, whose status is the
chain's status).

## Where decisions are recorded today

| Decision point | Kind(s) | Where |
| --- | --- | --- |
| Placement seat stage transitions | `stage_changed`, `host_launched`, `host_reclaimed` | `placement.JournaledStore` (wraps the reconciler's store) |
| Placement holds | `held` (once per reason per 15 minutes) | `app.holdJournal`, from the reconciler's `OnHold` |
| Managed TerraBase update admission | `release_admitted` (chain root) | `app.recordManagedUpdateAdmission` |
| Managed update canary phases | `upgrade_started`, `canary_promoted`, `held` (failed) | `placement.JournaledStore` |
| Delivery intents | `delivery_applied`, `delivery_held`, `delivery_rejected` | `delivery` consumer, on the path that wrote the receipt |
| Founder peer launches | `founder_launched` (succeeded or failed) | `bootstrapstart.recordFounderLaunch` |
| Authority leader changes | `leader_changed` (recorded by the new leader) | `app.watchControlPlane` |
| Cluster health | `quorum_degraded`, `quorum_restored` (by the leader, or anyone while leaderless) | `app.watchControlPlane` |
| NetBird enrollment | `peer_enrolled` (succeeded or failed) | `netbird.Enroll` |
| Staged rollouts | `release_admitted` (chain root, correlated on `release:<digest>`), `upgrade_started`, `canary_promoted`, `batch_promoted`, `rollout_completed`, `rollback`, `frozen`, `held` (aborted) | `rollout.Store.Begin` / `rollout.Store.Commit`, after the KV write |
| Self-update activations | `upgrade_started` (activated, then succeeded when confirmed), `rollback` | `selfupdate.Activate`, `selfupdate.Watch` |
| Workload autoscaling | `scale_up`, `scale_down` with every policy signal and its target | `workload.Reconciler`, after the desired-state writes succeeded |
| Volume backups | `backup_taken` | `backup.Runner.RunOnce`, after OCI accepted the create |
| Volume reattach on host loss | `volume_reattached` | `failover.Reattacher.Step`, after the replacement attach |
| Volume auto-grow | `volume_resized` | `placement.Controller.growVolume`, after the journaled resize |
| Controller slot replacement | `controller_replaced` | `membership.Reconciler`, after the founder (or the seed, when routed) accepted the replacement; `membership.SeedServer` on the seed when a routed replacement finishes or fails (rule `membership.seed_routed`) |
| Region proposals | `region_proposed` | `regionplanner.Submit`, after the lifecycle record was stored |
| Region admissions | `region_admitted` (admitted or readmitted, with the estimate and committed spend), `held` (refused by the region maximum, the ceiling or the approval; once per cell and reason) | `regionops.Loop`, after the lifecycle record was stored |
| Region lifecycle steps | `region_step` (in progress, succeeded, or failed when held), `held` (waiting for an approval, a fresh admission, an effector or an OCI effect in progress; once per cell and reason) | `regionops.Loop`, after `Driver.Advance` or an observed resume |
| OCI declarative reconcile | `oci_desired_published`, `oci_drift_corrected`, `oci_resource_deleted`, `oci_resource_released` | `app.desiredPass` after the KV writes; `ociresource.Controller` after the cloud write or the purge |

### Providers of the other slices

| Provider | Implementation | Wired |
| --- | --- | --- |
| `insights.AutoscalerProvider` | `app.workloadAutoscalers` over `workload.Reconciler.Last` | when `controller.autoscale.enabled` |
| Metric history (autoscale and TerraBase load charts) | `app.withAutoscaleSamples` over `workload.Reconciler.Last` and `hostload.Aggregator.Nodes` | on the authority leader; signals need `controller.autoscale.host_telemetry` (see [autoscale-telemetry.md](autoscale-telemetry.md)) |
| `insights.VolumeProvider` (also the dashboard storage page) | `app.placementVolumes` over the placement member states | on managed controllers |
| `insights.RolloutProvider` | `rollout.Store.Rollouts` | available; no controller opens the rollout store yet |
| `insights.BudgetProvider` | `regionplanner.Budgets` | when `controller.region_planner.enabled` (global home only) |
| `insights.OCIResourceProvider` (rule `oci_drift`) | `app.ociResourceStatuses` over `TS_OCI_OBSERVED` | when `controller.oci_reconcile.enabled` |

### Original contract for the parallel slices

| Slice | Expected kinds | Notes |
| --- | --- | --- |
| rollout | `release_admitted`, `upgrade_started`, `canary_promoted`, `batch_promoted`, `rollout_completed`, `rollback`, `held`, `frozen` | Correlate on `release:<digest>`; record the health gates as `Signals` with thresholds and `Passed`. Implement `insights.RolloutProvider` for the deadline rule. |
| selfupdate | `upgrade_started`, `controller_replaced`, `rollback` | Subject `member/<name>`; the new version in `Attrs["version"]`. |
| autoscale | `scale_up`, `scale_down`, `held` | Record the metric that crossed its target. Implement `insights.AutoscalerProvider`. |
| storage | `volume_resized`, `volume_reattached`, `backup_taken` | Subject `volume/<ocid>`. Implement `insights.VolumeProvider`. |
| membership | `member_replaced`, `controller_replaced`, `host_reclaimed` | Subject `member/<name>` or `host/<ocid>`. |
| regionplanner | `region_proposed` | Region in `Region`; implement `insights.BudgetProvider` for budgets. |
| regionops | `region_admitted`, `region_step`, `held` | Region in `Region`, subject `region/<cell>`; proposal, phases, step and create key in `Attrs`. |

Every provider is optional: the insights engine and the region view take
nil for anything not built yet, and the rules that need it stay silent
rather than invent data.

## Storage and retention

Each controller publishes its decisions to the cell's `TS_DECISIONS` stream
on `ts.orch.v1.<cell>.obs.journal`, replicated at the cell's quorum size,
with limits retention: 30 days, 256 MiB and 500k messages, oldest discarded
first. Publishes use the decision ID as the message ID, so retries are
deduplicated. Every controller tails the stream into an 8192-decision
in-memory index, so any member answers for the whole region; older ranges
are read from the stream on demand.

Decisions are queried locally with `Journal.Query`/`Journal.Chain`, over
HTTP on the private listener (`GET /v1/decisions?region=&kind=&actor=&subject=&since=1h&limit=`,
`GET /v1/decisions/{id}`), and from other regions over NATS request/reply
on `ts.orch.v1.<region>.obs.decisions` (one answer per region through a
queue group). `decisionlog.Federation` merges every region newest first and
reports each region's state: `ok`, `not_linked` (no cross-region link yet),
`unreachable` or `error`. Interregion leafnode peers are linked through the
cell connection: the interregion contract carries exactly the
`obs.region` and `obs.decisions` services, and both responders decode
requests strictly and bound every filter.

Every controller registers these responders and the snapshot responder.
They need the controller's `obs.>` subscription grant; rejected subscriptions
are logged without stopping the controller.

## Metric history

`observability.History` keeps every series at three resolutions: raw
samples for one hour, one-minute rollups for six hours and five-minute
rollups for 24 hours (average, min and max per step). The sampler reads the
cell-wide snapshot every 10 seconds (`SnapshotSampler` lists the series
names: members, CPU, memory, filesystems, NATS, JetStream streams and
consumers, OCI calls/errors/429s, TerraBase seats and rollout progress) and
saves the rollups to the `TS_METRIC_HISTORY` KV bucket every five minutes,
so charts survive a restart. Query with `History.Range` or
`GET /v1/history?metric=&label.member=&range=6h&rate=1`.

## Insights and summaries

`insights.Engine` evaluates its rules every 15 seconds. Each insight has a
severity, a title, a plain-language `Why`, `Evidence` (value, threshold,
the history series to chart), an `Entity` with a dashboard link, and
`Actions` (a CLI command or a page). The engine streams `opened`,
`escalated` and `resolved` changes for toasts (`Subscribe`) and keeps them
for summaries. `insights.Summarize` writes a deterministic paragraph for a
window from decisions, changes and open insights; `GET /v1/summary?window=1h`
serves it and `GET /v1/insights` the ranked list.

## Region view

`regionview.Provider` builds this region's `Summary` and gathers the other
regions' over `ts.orch.v1.<region>.obs.region`. The health score starts at
100 and subtracts for lost or degraded quorum, members not ready, a missing
leader, open insights by severity (capped) and mixed versions; 85 and above
is healthy, 50 and above degraded, below that critical, and a region that
cannot be observed is unknown. `GET /v1/regions` lists every region, local
first.

## Dashboard providers

The UI reads only interfaces:

- `decisionlog.Source` (query and chain) and `decisionlog.LiveSource` (new
  decisions for SSE),
- `observability.HistorySource`,
- `insights.Source` (ranked list, changes, live changes) and
  `insights.Summarizer`,
- `regionview.Source`.

`app.runtimeObservability.providers` holds them once a controller attaches
its journal.
