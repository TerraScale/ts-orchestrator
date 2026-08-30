# Public Alpha release boundary

> Historical implementation record. The current release boundary must qualify
> Dashboard, the C# Database API, TerraBase RF=2 placement, QUIC TBEP, native
> CRDT replication, reactive sync, and direct legacy-service cutover. References
> below to the old MCP client, R3 database topology, or previous service set are
> not current requirements.

The repository now has a local decision seam for the three-region Public Alpha
release. It is deliberately narrower than a production launch system.

The implemented code can:

- route global and strict-regional requests only to selected, healthy GRU, SFO,
  or FRA regions;
- prepare one immutable candidate in all three regions and cross one global
  blue-green activation barrier;
- converge partial activation toward the committed global digest;
- reject activation when regional, cross-client, readiness, or final-approval
  evidence is missing, stale, failed, duplicated, or candidate-mismatched;
- verify external DNS, HTTP, TLS, certificate, regional identity, and targeted
  read/write/query/replication/isolation/failover evidence for the global and
  strict regional API endpoints;
- emit exact-target rollback intents with the retained configuration and
  migration set, without rebuild authority;
- verify the `terrascale.public-alpha-handoff/v1` digest and its canonical
  status, security, legal, support, registration, and redirect probes
  independently;
- require digest-bound manual QA before the named final approval; and
- append digest-bound release events and evidence references to a durable
  compare-and-swap journal record keyed by release ID.

These are deterministic local contracts. They do not prove the adapters that
collect evidence, execute intents, change traffic, retain registry bytes, or
store the journal in the production R3 topology.

## Qualification blockers

Public Alpha remains blocked until the owning production process records all of
the following against the exact integration tree and candidate:

- a production-shaped GRU/SFO/FRA rehearsal, including partial activation and
  exact-byte rollback;
- DNS, TLS, global endpoint, and strict-regional endpoint probes;
- real OCI A1, provider, systemd, containerd, network, storage, and R3 journal
  restart/member-loss drills;
- the same live customer journey through raw API, .NET, TypeScript, and MCP;
- tenant isolation, metering/billing, replication, monitoring, registration,
  payment, manual QA, and named final-launch approval;
- published public status, security disclosure, legal policies, support terms,
  and launch documentation;
- the complete production-readiness audit and required seven-day soak; and
- proof that receipts survive the deployed R3 journal and that current and
  rollback artifacts remain available in every region.

No local test result or draft procedure below satisfies those gates.

The read-only endpoint preflight on 2026-08-19 did not qualify the launch:
`status.terrascale.tech` and `dashboard.terrascale.tech` did not resolve, the
required docs paths returned 404, and `dash.terrascale.tech/register` timed out.
Deploy and Orchestrator reject those observations; neither repository treats
them as launch evidence.

## Draft incident procedures

These procedures describe the decision boundary for a future authorized
operator surface. The current repository does not expose commands that mutate
production traffic or infrastructure.

### Degraded region

1. Mark the region unhealthy in fresh routing evidence; do not route the global
   endpoint to unknown or unhealthy regions.
2. Keep strict-regional requests fail-closed for that region. Do not silently
   move a strict request elsewhere.
3. Hold activation unless every required gate still covers GRU, SFO, and FRA.
4. Restore the region, rerun regional and customer gates, and attach new
   digest-bound evidence before admitting it to routing.

### Failed placement

1. Hold the affected candidate and preserve the last accepted placement and
   release generations.
2. Inspect the typed placement failure and its journal evidence; do not infer
   success from provider inventory alone.
3. Retry only through the fenced reconciler after authority and evidence are
   current. Never create an overlapping writer or adopt an unknown resource.
4. If recovery cannot satisfy all regions, keep activation closed and escalate
   through the placement/provider runbook qualification path.

### Failed activation

1. Determine whether the global activation barrier committed from its durable
   release state, not from endpoint observations alone.
2. Before commit, converge any prematurely changed region to the previous
   qualified digest and keep traffic on that digest.
3. After commit, converge partial regions toward the committed candidate only
   while post-activation gates remain valid.
4. If any customer gate fails, select rollback; append the decision and evidence
   to the release receipt before acknowledging completion.

### Rollback

1. Resolve the previous qualified digest, configuration, migration set, and
   retained artifact bytes from the verified handoff.
2. Reject rollback if retained bytes are missing, changed, or schema
   incompatible. Building replacement bytes is forbidden.
3. Reconcile each region independently to the same rollback digest while
   retaining partial progress in durable state.
4. Rerun health, isolation, replication, billing, and customer-journey gates;
   record the rollback event and evidence links in the receipt.

### Stuck reconciliation

1. Read the durable operation/release state, current authority epoch, desired
   digest, and per-region observed digest.
2. Fence stale or duplicate writers. Do not delete journal state or advance a
   generation by hand.
3. Resume the existing idempotent step when its evidence is current; otherwise
   hold and recollect evidence.
4. If bounded compare-and-swap retries continue to contend, leave the operation
   unacknowledged and escalate with the release ID, revisions, digests, regions,
   and redacted evidence references.
