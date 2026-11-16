# Service replica autoscaling

`ts-orch node` starts the existing replica autoscaler with the manager role.
Only the local SwarmKit Raft leader evaluates services. A leadership term change
clears signal windows and decision history. Each replica write checks the same
term and the observed service version inside the local store transaction; it
never goes through the control API proxy. Raft rejects proposals after lost
leadership. SwarmKit alone creates, places and replaces tasks.

## Service bounds and pinning

Only a service declaration with explicit `replicaBounds` is autoscaled, for example:

```json
{"replicas": 2, "replicaBounds": {"min": 1, "max": 4}}
```

Bounds must contain the initial replica count and stay inside 1..8. Omitting
`replicaBounds` keeps the exact replica count declared in the service spec. The
existing ts-auth, ts-dashboard and app-canary declarations remain pinned. Data
owners, Postgres services and every-node services keep their declared count; any
explicit bounds must be equal because their lifecycle is managed separately.
Pin any service by omitting bounds or using equal bounds, such as `{"min": 2, "max": 2}`.
Bounds travel with the service spec into SwarmKit labels. Reapplying an unchanged
bound preserves its current scale, including through a release.

Before growing, the autoscaler counts available placements using SwarmKit's
scheduler filters and subtracts every assigned live task's **requests**, including
CPU, memory and generic disk reservations. Readiness, node availability,
constraints, platforms, host ports and per-node replica limits all apply. It adds
only replicas that fit; `region-capacity` explains a hold. It never creates nodes.
C12 must supply more ready regional nodes when these placements are exhausted.

## Signals and decisions

The leader samples every ten seconds. Each node exports task CPU cores and memory
working sets from its current containerd controllers' cgroups at `/replica-load`
on the existing private NetBird metrics listener. Remote endpoints come from the
existing fresh NetBird discovery inventory and must return the expected SwarmKit
node ID. Every desired task must be running and measured. CPU and memory are
normalized by that task's resource requests, then averaged across replicas.

The edge counts requests per routed service only after admission, including body
and WebSocket checks, using per-service atomic counters. Rejected requests and
forwarded peer requests do not count as demand. The leader sums regional counters
and calculates requests per second per replica. Restarted counters, changed membership, missing tasks and stale
collection invalidate the observation. One full minute of continuous observations
is required before using the window. Missing metrics hold the current count and
restart stabilization; they never substitute zero or move a service to minimum.

| Signal | Target per replica |
| --- | --- |
| CPU cores / requested cores | 70% |
| Working set / requested memory | 80% |
| Edge requests / second | 100 |

The latency source for C20 is the edge histogram
`ts_orch_edge_request_duration_seconds{service=...}`. That histogram is absent on
the C11 base, so latency is not yet a decision input. CPU, memory and request
rate are active; latency must join the same complete-window and missing-signal
rules when C20 supplies its observations.

The largest signal recommendation wins. A 10% tolerance band avoids small
oscillations. Growth needs twenty seconds of sustained pressure, a twenty-second
up cooldown, and adds at most two replicas per change. Shrinking requires every
signal to agree for two minutes, waits three minutes after the latest change,
and removes at most one replica per change. Release updates and unready replica
sets hold scaling. Leadership changes restart all cooldowns conservatively.

Each change emits one `service replicas changed` log with service, from, to and
reason. The existing host metrics endpoint exposes:

- `ts_orch_service_replicas_current{service=...}`
- `ts_orch_service_replicas_desired{service=...}`
- `ts_orch_service_replica_decision{service=...,reason=...}`
- `ts_orch_edge_service_requests_total{service=...}`

Follower managers expose no autoscale decisions. The dedicated
`e2e-m1 / autoscale-up` lane drives HTTPS load through the edge into the real
runtime, checks an unbounded service stays pinned while a bounded service grows
from one to two replicas, checks live scheduler capacity excludes current replicas,
and proves SwarmKit replaces a killed task at two replicas.
`e2e-m1 / autoscale-down` starts an idle service at two replicas with bounds 1..2,
asserts it holds through the full 180-second cooldown, then drops to one.
Both jobs retain five-minute limits; the policy and cooldown are unchanged.
