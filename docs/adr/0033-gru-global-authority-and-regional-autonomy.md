# GRU global authority and autonomous regional control

- Status: Accepted
- Updated: 2026-08-30
- Decision owner: TerraScale workspace owner
- Scope: global and regional authority, NATS, disconnected operation,
  bootstrap, release cutover, and control-state ownership

## Context

TerraScale needs one global policy authority and regional control that can
repair local failures during a GRU or WAN outage. The control plane must remain
outside the customer request and database replication paths.

## Decision

### One global group and one group per region

GRU runs the permanent three-replica global control group. It owns global
policy, admitted release sets, region catalog state, signed regional policy,
global limits, Cloudflare intent, and regional journal aggregation.

GRU, SFO, and FRA each run a separate three-replica regional control group.
The regional group owns hosts, workloads, volumes, routing backends, identity
operations, repair, and OCI mutations inside its region. GRU's regional group
uses the same contract as SFO and FRA.

Global controllers do not hold ordinary regional OCI mutation credentials.
They admit regional policy. A regional leader executes that policy with a
region-scoped identity.

### JetStream R3 is the control store

Every group uses a three-server, file-backed JetStream domain. JetStream Raft
commits authority claims, KV state, streams, and operation journals.
Orchestrator does not run another consensus log.

NATS gateways form a control supercluster. Gateways carry approved subjects
between domains, but no Raft group spans a WAN link. Regional clients connect
to local servers.

The control subject root is `ts.orch.v2`. V1 streams, consumers, credentials,
and leases cannot acquire v2 authority.

NATS stores Orchestrator control state only. It never stores customer
documents, WAL records, CRDT deltas, replication frames, query results,
reactive frames, payment data, or authoritative usage facts.

### Fenced authority

The active controller holds a monotonic term and compare-and-swap lease in its
local JetStream KV store. Mutation requires:

- the newest live term and matching session;
- the expected build and protocol generation;
- a healthy local quorum;
- a current lease; and
- no newer observed term.

Clock uncertainty, quorum uncertainty, a future term, an ambiguous KV result,
or a protocol mismatch makes the controller read-only. Leadership permits a
control transition. It does not grant a TerraBase membership change, provider
operation, secret, or destructive action. Each domain still applies its own
persisted authorization.

### Regional autonomy

An isolated regional quorum may use its last accepted regional policy and
admitted digests to restart workloads, replace failed hosts, scale within
limits, expand storage, repair allocations, renew existing identity classes,
roll back, maintain routing backends, and coordinate TerraBase recovery.

It cannot admit a new release, change global policy, publish a region, widen
permissions, rotate a global trust root, delete quarantined data, perform
ordinary cost scale-in, weaken durability, or exceed hard limits.

Serving and safety work has no short wall-clock cutoff. Global and
customer-facing policy changes remain frozen for the outage. Existing database
reads, eligible writes, replication, repair, and client catch-up do not depend
on NATS or Orchestrator availability.

### Reconnect preserves regional facts

A region commits isolated work locally and appends it to an ordered outbox.
After reconnect, GRU validates the complete regional journal before issuing
destructive or rollout work for that region.

GRU policy wins desired-state conflicts. It does not erase provider resources,
committed operations, accepted allocations, or TerraBase observations. The
control plane builds a new plan from the uploaded journal and fresh external
observations.

### Regional blue-green rollout

GRU admits the immutable release set and wave order. Each connected regional
leader creates full green capacity beside unchanged blue and keeps green out
of production routing while startup, dependency, authorization, isolation,
routing, customer-journey, and rollback tests run.

The region switches traffic through one term- and generation-fenced routing
update. A failure before cutover changes only green. Blue stays available
through the rollback window. Rollback restores the retained digest and never
rebuilds the image.

TerraBase uses surge Members, catch-up, Merkle verification, and accepted
overlapping membership. Controller and NATS releases replace one replica at a
time and restore quorum before the next replacement.

### OCI bootstrap and ownership

The target `bootstrap` command creates a new OCI estate, establishes GRU and
regional control, records deterministic resource identities, hands control to
the new JetStream domains, and retires bootstrap credentials. Every provider
operation follows ADR 0020.

Until ORCH-6 lands, operators create the one-time network, IAM, and Vault
estate through the ORCH-5 runbook. Orchestrator validates it read-only and owns
normal compute and storage churn. No external reconciler becomes another state
owner.

## Authority matrix

| State | Writer | Durable home | Partition behavior |
| --- | --- | --- | --- |
| Global policy and region catalog | Global leader | GRU global JetStream | Frozen without GRU quorum |
| Admitted release set | Global leader | GRU global JetStream | Regions use retained digests |
| Regional policy | Global leader | GRU and target regional JetStream | Last accepted generation remains executable |
| Regional authority and operations | Regional leader | Regional JetStream | Continues with local quorum |
| Provider observations | Regional actuator | Regional journal, then GRU | Uploaded after reconnect |
| TerraBase membership and recovery | TerraBase | TerraBase | Independent of NATS |
| Control backups | Backup controller | OCI Object Storage | Restore requires a higher fenced generation |

## Failure rules

- One controller failure elects a replacement inside the same group.
- One NATS server failure preserves quorum and acknowledged control state.
- GRU loss freezes global work and leaves regional safety work active.
- Regional quorum loss freezes new regional mutations while admitted workloads
  continue from persisted configuration.
- A provider timeout becomes `OutcomeUnknown` and resumes as the same
  operation.
- Control-store restoration creates a higher recovery generation and fences
  every old term.

## Security

- Servers and gateways use TLS 1.3 mutual authentication.
- Clients use distinct scoped NKey or credential identities.
- Global, regional, infrastructure, agent, CI, monitoring, and recovery
  accounts have disjoint permissions.
- A compromised region cannot use its identity in another region.
- NATS carries references to secrets, never secret bytes or private keys.
- Break-glass and disaster bootstrap require explicit owner authority.

## Migration

The checked-in adapter still contains v1 subjects and consumers. ORCH-1 moves
`run`, `check`, journals, discovery, and delivery to `ts.orch.v2`, then deletes
the v1 taxonomy, codecs, and tests. V1 and v2 never share authority.

## Verification

The design requires tests for authority, quorum, lease expiry, reconnect,
restore, one-controller and one-server loss, gateway and WAN failure, provider
lost responses, blue-green rollback, control-plane outage during customer
traffic, and GRU/SFO/FRA operation. Launch uses the workspace's seven-day soak.

## Consequences

GRU always decides global policy. A regional quorum decides execution inside
that policy. The cost is a three-controller and three-NATS-server floor per
region, dedicated GRU global capacity, journal reconciliation after outages,
and temporary green capacity during rollout. The benefit is regional repair
without putting the control plane on the customer data path.
