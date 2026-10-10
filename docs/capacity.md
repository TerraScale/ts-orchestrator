# Capacity: nodes, budget and regions (TS-804)

Status: design for TS-804. ts-orchestrator manages capacity by itself:

1. Every region scales between 3 and 12 nodes on CPU, memory, disk and
   request load, without flapping. Scale-down drains a node first.
2. A monthly OCI budget, set on the dashboard, caps growth. Spending 80% of
   it alerts on the dashboard and on ts-status.
3. The orchestrator adds and removes whole regions when load and latency say
   so, inside guardrails.

There is one code path for any number of regions. Nothing in this design has
an on/off switch, a per-region setting or a tuning knob: every value below is
a constant in code ([zero configuration](zero-configuration.md)). The only
operator input is the budget, which is data, not configuration.

It builds on TS-803 ([region-agnostic](region-agnostic.md)): the roster
names the serving regions, every region's rollup
(`ts.orch.v1.<cell>.region.rollup`, TS-805) crosses the links, and `TS_GLOBAL_CONTROL`
is written by the home's global leader and mirrored to every region. It
replaces `internal/cellscale` (deleted), the signed region approvals
(deleted), `internal/hostpool`, the `autoscale.node_pools` and
`region_planner` controller settings and the cell spec `budget`; the rest
are deleted in the last slice ([autoscaling](autoscaling.md) describes
them).

## Who decides what

| Decision | Where | Why there |
| --- | --- | --- |
| How many nodes a region wants | the region's authority leader | it sees its own load and keeps scaling down and repairing when cut off from the home |
| How many nodes a region may have (its allowance) | the home's global leader | one writer spends the one budget, so two regions can never both take the last headroom |
| Which regions exist | the home's global leader | the same writer, the same budget |
| Launching, draining and removing a node | the region's authority leader | only it can drain its own TerraBase, NATS and workloads |

A region grows only up to its allowance. A region that cannot read a fresh
allowance (link down, home down) holds its size, still scales down, and
never needs the home to stay at 3 nodes.

## Nodes

A region's nodes are its 3 **quorum nodes** (the controllers, which run the
NATS JetStream R3 cluster) and 0 to 9 **pool nodes** in one OCI instance
pool. Autoscaling counts both and never removes a quorum node: losing one is
controller membership's repair (TS-796), not a scale-down.

The quorum nodes stay standalone instances. They are not attached to the
pool: OCI replaces or terminates pool instances on pool operations, and a
controller keeps its identity, store and NATS server name for life. So the
pool is created beside the serving cell, in place, and nothing is rebuilt.

### The pool

- One instance pool per region, `ts-<cell>-nodes`, in the leader's own
  compartment, with one placement configuration per availability domain on
  the cell's private subnet. Pool size = nodes − 3. The controllers' dynamic
  group needs `manage compute-management-family` there.
- One instance configuration per launch recipe, `ts-<cell>-node-<digest>`,
  where the digest covers the recipe: shape, image, subnet, NSGs, metadata
  and tags. A new recipe (a new qualified image) creates a new configuration
  and points the pool at it; running nodes are not touched. A configuration
  no pool references is deleted.
- The recipe is read from OCI, never configured: the leader copies its own
  instance (compartment, subnet, NSGs, availability domain, image, OCPUs
  and memory, so all nodes are the same size), its SSH keys and its host
  enrollment bundle (`terrascale-host-enrollment-v1`), and adds the pool
  marker `terrascale-node-pool`. It never copies the controller slot
  (`terrascale-bootstrap`), so a pool node starts only the host agent; the
  agent then updates itself to the current release. Freeform tags:
  `ts-cell`, `ts-role=node`.
- The leader never shrinks the pool by size. A scale-down detaches the one
  drained instance with `DetachInstancePoolInstance` (decrement size,
  terminate), so OCI never chooses which node dies. OCI restores the size
  when a pool instance disappears outside a scale-down; that is the repair.

### Names and admission

OCI names pool instances `inst-…`. The leader gives each new pool instance
the lowest free node name `ts-<cell>-<n>` (`internal/naming`, n ≥ 4 because
the quorum nodes hold 1 to 3) by renaming the instance. The node's
`host-setup` sees the pool marker, waits until its display name is a node
name (its timer retries), then enrolls as that node. The controller admits
a pool node's enrollment only when OCI shows that instance in this cell's
pool, `RUNNING`, with that name, at the request's private IP. It registers
with the roles of the cell spec's reconciled services and its shape's
capacity, and a reused name is unretired. NetBird joins it like any managed
host (TS-796). No grant, list or human step is involved.

## Load and decisions

Every 30 seconds the regional leader reads each node's last host load report
(`internal/hostload`, at most 2 minutes old):

| Signal | Per node | Region utilization |
| --- | --- | --- |
| CPU | `cpu_util` | mean over nodes |
| Memory | `mem_util` | mean over nodes |
| Disk | `disk_util` (data filesystem) | mean over nodes |
| Requests | TerraBase `write_qps` and `connections` | sum ÷ (nodes × per-node capacity) |

Per-node request capacity is a constant per OCPU from the ts-benchmark
baseline (`capacity-benchmarking.md`); TS-806 owns TerraBase's telemetry.

The decision is a pure function (`internal/nodescale`, `Decide`) of the
samples, the node count and the last change:

- **Up** (+1): some signal ≥ 0.75 in every sample of the last 5 minutes, at
  least 10 minutes after the last change, below 12 nodes and below the
  allowance.
- **Down** (−1): above 3 nodes, every signal projected onto one node fewer
  (utilization × n ÷ (n − 1)) ≤ 0.55 in every sample of the last 30 minutes,
  at least 30 minutes after the last change.
- **Hold** otherwise, and whenever a node misses a fresh sample, a node
  operation is running or a scale action is in flight.

The band between 0.55 projected and 0.75 is the hysteresis: a scale-down
leaves every signal at or below 0.55, which cannot trigger a scale-up, and a
scale-up needs 30 quiet minutes before the next scale-down can start. One
action at a time, one node per action.

Bounds repair is not a decision: a pool smaller than nodes − 3 is OCI's
repair, and 3 quorum nodes are always kept.

### Scale-up

1. The allowance admits one more node, or the decision holds as
   `nodescale.budget-capped`.
2. Ensure the instance configuration and the pool; raise the pool size by
   one with the decision's ULID as the retry token.
3. Name the new instance; wait up to 20 minutes for its enrollment and host
   session. A node that never enrolls is detached and terminated
   (`nodescale.launch-expired`).
4. The node is in. The workload reconciler places replicas on it; the edge
   reconciler adds its load balancer backends.

### Scale-down (drain first)

1. Pick the pool node with the least load (ties: the highest `n`).
2. **Cordon**: the host's retire mark. The workload reconciler treats a
   retired host as cordoned: it takes no new replica, and its replicas are
   placed elsewhere and withdrawn within rollout and quorum limits.
3. **Workloads**: wait until nothing is desired on the node.
4. **TerraBase**: a pool node holds no TerraBase member (members are
   placement's); a node that holds one is never picked.
5. **Load balancer**: the edge reconciler removes the backends of a node
   without replicas once they serve nothing; wait until none is left.
6. **Remove**: detach the instance from the pool with terminate; wait until
   OCI reports it terminated.
7. **NATS**: disable its enrollment grant, so its host session and NATS
   credentials end and cannot renew. Its NetBird peer goes offline and
   NetBird peer hygiene (TS-796) removes it.

The action is one record in the `TS_NODESCALE` bucket, written before each
step, so a new leader resumes it, and every step is a decision journal entry
(`scale_up`, `scale_down`, `host_launched`, `host_reclaimed`, `held`). A
drain that cannot finish in 30 minutes fails, uncordons the node and counts
as a change, so scaling holds for the cooldown.

## Budget

### The cap

The budget is one global document in `TS_GLOBAL_CONTROL`
(`globalcontrol.KindBudget`, cell `global`):

```json
{"schema": 1, "id": "01K…", "monthly_cap_cents": 50000, "currency": "BRL",
 "set_by": "mariogk@terrascale.tech", "set_at": "2026-10-10T20:00:00Z"}
```

The dashboard's capacity page sets it. The page posts to the home's global
leader, the only writer; every region reads it from its mirror. The
currency is the tenancy's billing currency. Until a budget is set nothing
grows past its current size, and the page asks for one.

### Spend

Cost data comes from TS-807 (`docs/oci-cost.md`): each region's
leader keeps its own OCI cost report in `TS_OCI_COST`, and
`ocicost.Project` is the one forecast. Each region's capacity status
(below) carries its forecast, projected with its own pool nodes launched
inside the forecast's rate window as pending cost, so a new node counts from
the minute it exists, whatever the usage API's lag. The node price is OCI's
list price for the recipe's shape (`regionops` price list).

### Allowances

Every minute the home's global leader:

1. reads the budget and every roster region's capacity status (below);
2. projects the month: the sum over regions of the larger of the month-end
   and next-month forecasts;
3. gives regions that want to grow one node each, highest pressure first,
   while the projection plus that node's monthly price stays within the cap;
4. writes the `capacity` document (`globalcontrol.KindCapacity`, cell
   `global`): the cap, the projection, each region's nodes, wanted nodes and
   allowance.

An allowance is at least the region's current size, so the budget never
removes capacity. An allowance older than 5 minutes is not fresh. A region
whose status or forecast is missing or older than 6 hours gets no growth,
and its unknown spend makes every region's growth hold: the cap is global,
so a partial sum cannot admit spending.

### Alerts

At 80% projected spend the dashboard shows the `capacity_budget` insight and
the leader opens a ts-status warning (impact none, no amounts, no
components) through ts-status's operator API with the token from OCI Vault
(`ts-status-operator-token`). Below 75% it resolves the warning. At 100%
growth stops (`nodescale.budget-capped`) and the insight turns critical.

### The capacity status

Each regional leader publishes its status in the region rollup it pushes
every 5 seconds (`globalview.Rollup.Scale` on
`ts.orch.v1.<cell>.region.rollup`, TS-805). Every region follows every
rollup, so the home's allocator and planner read all statuses from memory,
with no fan-out and no new subject or grant. A status that does not
validate or names another region is dropped. A region running an older
build has no status: its spend is unknown and growth holds.

```json
{"schema": 1, "cell": "gru", "oci_region": "sa-saopaulo-1", "at": "…",
 "nodes": 4, "quorum_nodes": 3, "want": 5, "pressure": 0.82,
 "signals": {"cpu": 0.82, "memory": 0.40, "disk": 0.31, "requests": 0.12},
 "node_monthly_cents": 4100, "action": "scale-up", "since": "…",
 "cost": {"currency": "BRL", "month_end_cents": 21000, "next_month_cents": 24600,
          "observed_at": "…"},
 "rtt_ms": {"us-sanjose-1": 171, "eu-frankfurt-1": 197}}
```

`rtt_ms` is the region's measured TCP connect time to every OCI region's
public endpoint (`objectstorage.<region>.oraclecloud.com:443`), refreshed
every 10 minutes; the region planner uses it.

## Regions

The home's global leader runs the region planner every 10 minutes, after the
allowances, on the same inputs. It reuses `regionlifecycle` (records, phases,
steps, effectors) and `regionops` (the loop and the subscription effector).

### When

- **Add** a region when a serving region is saturated: it has 12 nodes and
  has wanted more for an hour. The new region is the OCI region (from OCI's
  own region list, `identity.ListRegions`) not serving yet with the lowest
  measured RTT from the saturated region. Client latency joins the same
  signal set when TS-805/TS-808 provide where clients are.
- **Remove** a region that is not the home, has had 3 nodes and every signal
  below 0.15 for 14 days, and homes no database partition
  (`globalcontrol.Directory`).

### Guardrails

- The budget: a new region needs headroom for its 3 nodes at the list price
  for a whole month.
- Never fewer than two serving regions, and never the home.
- One region action at a time; 24 hours between region actions; 30 days
  before a removed region is added again.
- Every action is a decision journal entry (`regionplanner.*`) with a written
  reason (the signals that caused it) and shows on the dashboard's capacity
  page. The planner's current decision, including "hold" and why, is always
  visible there.
- OCI region subscriptions cannot be undone. The planner subscribes only when
  it adds a region, journals the region key, name and OCI request ID (a
  subscription has no OCID), and a removed region keeps its subscription for
  a later re-add.

The planner approves its own proposals inside these guardrails (user
decision 2026-10-10); signed approvals and `Approvers` are deleted.

### Adding

Lifecycle steps, each an effector driven by `regionops`:

1. **Subscribe** the tenancy to the region (exists).
2. **Network**: compartments, VCN, private subnet, NSGs, gateways, Vault and
   buckets (`ociregion/foundation`, as an effector).
3. **NetBird**: groups, routes and a setup key in Vault (`netbird/manager`).
4. **First nodes**: the 3 quorum nodes, with material issued under the
   region's derived identity (TS-803 trust root).
5. **Join**: the region's first heartbeat puts it in the roster (TS-803); it
   then serves and autoscales like every region.

### Removing

1. **Drain**: hold placement in the region; wait until it homes no
   partition and serves no traffic (TerraBase moves data; TS-677/TS-806).
2. **Pool**: drain and remove every pool node (scale-down above).
3. **Unlink** and **terminate** the quorum nodes; the roster drops it.
4. **Network**: delete the foundation (`ociregion/teardown`).

## Simulation

`internal/capacitysim` (test-only package) runs 20 regions in one process: a
fake OCI (pools, instance configurations, region subscriptions, region list,
prices), fake load per region, one regional scaler per region and one home
allocator and planner. Tests assert: every region stays within 3..12, no
region scales up within 30 minutes of scaling down, projected spend never
exceeds the cap, the last two regions are never removed, cooldowns hold, and
a partitioned region holds its size. The fake lives in `_test.go` files only.

## Slices

1. Design (this document).
2. `nodescale.Decide`: signals, hysteresis and bounds; pure, with tests.
3. OCI pool provider: instance configuration, pool, resize, naming, detach
   and terminate; with a fake in tests.
4. Pool node admission: `host-setup` waits for its name; enrollment admits
   pool instances.
5. Regional scaler: leader loop, scale-up, drain-first scale-down, journal,
   capacity status responder.
6. Budget: documents, dashboard capacity page, allowances and 80% alerts.
7. Region planner: signals, guardrails, automatic approval, RTT probe,
   journal and dashboard; switches and knobs deleted.
8. Region effectors: network, NetBird, first nodes, removal (with TS-803).
9. 20-region simulation.
10. Delete `cellscale`, `hostpool`, the cell spec budget and old settings.

## Live

GRU and SFO run it in place as soon as a release reaches them (TS-803's
adoption). Proof for one region: a scale-up to 4 nodes under synthetic CPU
load and the drain-first scale-down back to 3, with the OCI pool, instance
and work request IDs and the decision journal entries, plus the planner's
current decision. No new region is expected.

## Coordination

- **TS-803**: the roster (`globalcontrol.Roster` and `Reader.Follow` of it),
  the region rollups (TS-805) crossing the links, the
  `TS_GLOBAL_CONTROL` mirror, and automated issuance of a new region's
  material under its derived identity (step 4 of adding a region).
- **TS-807**: the per-region cost report and `ocicost.Project`; the cap
  itself is TS-804's `KindBudget`, not a cell spec field.
- **TS-805**: the global dashboard embeds the capacity page.
- **TS-796**: controller membership repairs quorum nodes; NetBird admission
  of new nodes; the link supervisor fetches every region's summary.
- **TS-677/TS-806**: TerraBase membership drain and data moves.
