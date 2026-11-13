# Mesh NATS: one cross-region cluster with JetStream (PIVOT N1)

Decision: PIVOT.md D16, D17 and D25, user 2026-10-29 ("prefer re using the nats
cluster that we already have and use it to the max"); two nodes per region
approved 2026-11-04 (Q-WCAP).

## The rule this replaces

`docs/nats-fabric.md`, `CONTEXT.md` and `docs/multi-region.md` say that a
JetStream quorum never spans regions. That rule no longer holds for the mesh.
The mesh NATS of every region is one NATS cluster, and its JetStream raft
groups place one replica in each region. Where those three files disagree
with this one, this file wins.

## Topology

- Every ts-orch host runs one embedded mesh NATS server
  (`internal/natscell/mesh`).
- All servers in all regions form one NATS cluster named `terrascale`. The
  servers link with routes on tcp/6222, so there are no gateways any more.
  Port 7222 is no longer used.
- Routes use mutual TLS with the mesh CA (`ts-orch-mesh-key` in gru-vault),
  over the private NetBird network. The NetBird policy `servers-mesh-routes`
  admits tcp/6222 between every regional servers group, in both directions,
  and gains each new group the manager discovers (`internal/netbird/manager`).
  - Each server dials `ts-<region>-1.nb.ts.internal:6222` for every founded
    region as a seed.
  - Each server advertises its NetBird IPv4. Route gossip adds every other
    server, so a region the user orders joins without a release.
- An in-region worker also dials its founder's VCN address, which it reads
  from the region join material.
- A founder's server name is its region token, for example `gru`. A worker's
  is `<region>.<hostname>`. JetStream derives a peer's identity from its server
  name, so a founder keeps its identity across hostname changes and host
  replacement. The node reads region membership and per-region route RTT from
  these names.
- The loopback client listener stays on `127.0.0.1:4223`.

## Two nodes per region

Each region runs two hosts in one availability domain and two fault
domains (D16: an in-region ack lands on 2 nodes that do not share hardware):

| Region | Founder (JetStream peer) | Worker |
|---|---|---|
| gru | `ts-gru-1`, FAULT-DOMAIN-3 | `ts-gru-2`, FAULT-DOMAIN-2 |
| sjc | `ts-sjc-1`, FAULT-DOMAIN-1 | `ts-sjc-2`, FAULT-DOMAIN-2 |
| fra | `ts-fra-1`, FAULT-DOMAIN-3 | `ts-fra-2`, FAULT-DOMAIN-1 |

All in AD-1 of their region, launched 2026-11-04 19:43–19:52Z.

Every node is `ts-<region>-<n>` (TS-609, no role names). The gru founder was
`gru-1-ctl-1` with hostname `ts-gru-2`. It was renamed in place to `ts-gru-1`
on 2026-11-04 17:46Z, inside the storage format 21 reset: hostname, OCI display
name, VNIC hostname label, join material founder and the peers file. The cell
was not re-founded: the SwarmKit cluster, the mesh server name `gru` and the
JetStream store stayed. TerraBase's `TS_NODE`, and with it its backup prefix
`nodes/<node>`, follows the hostname. Rename the founder before its region's
second host exists: a new host whose hostname equals the join material's
`founder` would found a second cluster.

- `ts-orch region add <code> --host ts-<code>-<n>` launches the worker
  (`internal/regionhost`): the founder's shape family (A1.Flex 2 OCPU/12 GB),
  the founder's availability domain and a fault domain no live host of the
  region uses. With every fault domain taken it launches nothing.
- Cloud-init installs ts-orch and the NetBird companion
  (`netbird-server.service`). The companion installs the pinned NetBird client
  and enrolls the host into `gru-servers` with `gru-1-netbird-setup-key`
  (gru-vault, instance principal). It skips the NetBird server check on a
  worker, which has no control socket.
- ts-orch joins the region by itself
  ([second host](m1-runbook.md#a-second-host-in-a-region-joins-by-itself)): the
  join material `ts-orch-join-<region>` in gru-vault, the SwarmKit worker
  token, the mesh route to the founder's VCN address.
- Releases: CI pushes only the founders (`deploy/m1/regions.json`). A founder
  that accepts or already runs a ts-orch release relays the same signed
  request on the mesh subject `ts.mesh.release.<region>`; the worker verifies
  the GitHub OIDC token itself and installs it. A worker that was down misses
  that relay and catches up on the next push.
- A mesh service runs on the founder only (`node.role==manager`), because the
  founder's edge serves it on loopback. On 2026-11-04 SwarmKit put TerraBase
  on `ts-sjc-2` before this rule; the task was rejected ("peers file is not
  written yet") and two TerraBase releases paused. The exception is a
  per-node service (below).
- Workers join the mesh before scheduling. Activate each worker with
  `ts-orch member activate <host>` after its predecessor passes readiness.

### Per-node services (R10's second TerraBase)

A mesh service with a data mount and `replicas` > 1 is per node: one task on
each fully joined node of its region, each with its own host's data
directory. TerraBase always requests two nodes, including existing one-replica
declarations. R10 (terrascale `59c46e4ac`) makes the second peer a durable ack
holder; it does not follow customer replicas or start a push stream. The founder
remains the first peer and keeps its existing data and identity.

- **Fully joined.** A worker announces its node name and NetBird IPv4 on
  `ts.mesh.worker.<region>` every 5 s. Its founder counts it while the
  announcement is under 15 s old and SwarmKit has it READY and ACTIVE. A
  drained, paused, silent or half-joined worker is no node.
- **Release targets.** The founder applies a per-node service with
  `replicas = min(spec replicas, 1 + fully joined workers)` and
  `MaxReplicas: 1` per node. The release waits for exactly those tasks. A
  worker that is not fully joined is never a target, and one that leaves
  drops the count at the next 30 s reconcile.
- **Founder restart.** A restarted founder knows no worker yet: announcements
  live only in its memory, and its SwarmKit dispatcher marks every worker
  UNKNOWN until it registers again. A reconcile that would lower a per-node
  service below the replica count SwarmKit runs waits, and an apply waits with
  it, until the first refresh at least 15 s after the founder starts listening
  and no worker that was READY is still UNKNOWN. A worker that re-registers
  keeps its task. One that never comes back stays UNKNOWN until the
  dispatcher's own DOWN, about 30 s after the restart, and the next refresh
  then lowers the count. A worker that is already drained or DOWN leaves the
  count as before. Raising the count still needs a fully joined worker.
- **Release evidence.** Verification admits the founder and the exact
  READY/ACTIVE workers in its fresh mesh inventory, with one task per host.
  Readiness and bake checks probe each worker's own NetBird address. A healthy
  founder cannot satisfy an unhealthy holder's readiness. Catalog and writer
  log checks stay on the founder, which owns that data and runs the customer
  writer; holder logs are not on the founder's disk.
- **Identity.** The executor sets `TS_NODE` to the host that runs the task.
  `TS_REGION` stays the region.
- **Peers file.** Each founder's ping reply lists its fully joined workers. A
  per-node service's file lists each region's founder, then its workers,
  sorted. A restarted founder's reply lists no worker until its worker has
  announced itself again and been counted (5 to 10 s); for that time every
  node's per-node file lists that region's founder alone. TerraBase reaches
  another region at its first line, so cross-region traffic still goes to
  founders. A founder-only service's file lists founders only. A worker writes
  the same file for its own task. It learns the per-node services from its
  founder's desired state.
- **NATS.** TerraBase on a worker dials the worker's own mesh server
  (`127.0.0.1:4223`, same token). That server stores no JetStream, but JetStream
  works through it (`TestFullyJoinedWorkerJoinsPerNodeServices`).
- **Customer traffic.** The edge proxies only to `127.0.0.1`, so a worker's
  TerraBase gets no customer request through a founder.

Activate one region at a time, in order sjc, gru, fra:

1. Ship the two-node placement policy through `ts-ship` and green-main release.
   Existing desired images and credentials remain authoritative. Reconciliation
   requests two TerraBase tasks only when a second node is fully joined.
2. `ts-orch member activate ts-<region>-2` on the founder. No manual service
   apply or binary install is needed.
3. Check: `ts-orch service ps terrabase` shows a running task on both nodes;
   both nodes' peers files list the founder, then the worker; the worker's
   TerraBase answers `/readyz`.

- Capacity: 6 VM.Standard.A1.Flex nodes. Founders: gru 4 OCPU/24 GB, sjc and
  fra 2 OCPU/12 GB. All workers: 2 OCPU/12 GB. São Paulo initially had no A1
  capacity for that size, so `ts-gru-2` launched at 1 OCPU/6 GB on 2026-11-04.
  It was resized in place to 2 OCPU/12 GB on 2026-11-05 before TerraBase
  placement, while drained and holding no data. The serving founder stayed up.
- `region add` tries every free fault domain in turn when OCI is out of host
  capacity.

## JetStream

- JetStream runs on every founder (the host that answers for its region).
  Workers carry messages but store nothing. So the JetStream cluster has 3
  peers, one per region, and a second node per region adds no vote: an R3
  asset keeps one replica per region, and a meta group of 3 tolerates losing
  any one region or founder.
- It runs only when the node is in the cluster. A server with no routes runs
  no JetStream.
- A fatal error inside the embedded server, such as a JetStream store it
  cannot create, fails the mesh start and the mesh retries every 30 s. It never
  exits ts-orch, so the release listener on 4222 keeps serving.
- The store is `<state>/mesh/jetstream`. Each server has 1 GiB of memory and
  16 GiB of file storage.
- Each server has the tag `region:<region>`, and `unique_tag` is `region:`.
  So an R3 stream or bucket always has one replica in each of 3 different
  regions. A region that is down never holds two votes.
- With 3 regions, any 2 keep quorum. Losing a second region stops writes to
  R3 assets. Reads with direct get still answer.

### Raft timers and measured RTT

RTT measured over NetBird with `ping` on 2026-10-29:

| Link | RTT |
|---|---|
| gru – sjc | 168.5 ms |
| gru – fra | 181.2 ms |
| sjc – fra | 138.3–145.1 ms |

The raft timers are the NATS defaults in nats-server 2.15. Each one is many
times the worst RTT (184 ms), so none of them needs a change:

| Timer | Value | Multiple of 184 ms |
|---|---|---|
| Heartbeat | 1 s | 5.4x |
| Election timeout | 4–9 s | 21.7x–48.9x |
| Lost-quorum check | 10 s | 54x |

A commit to an R3 asset waits for the leader and its closest follower, so it
takes about one RTT (138–184 ms). The integration test
`TestMeshJetStreamQuorumSpansRegions` puts 184 ms of RTT on every route. In it:

- the cluster forms;
- compare-and-set works from every region, and a stale revision is refused;
- per-key TTL expires the key;
- the region that leads the bucket is cut off at the network before it shuts
  down, so it cannot hand over leadership. The other 2 elect a new leader and
  commit 7.2–30 s later (local runs: 7.2 s on 2026-10-29, 30.1 s on beta
  2026-11-04, the NATS client retrying the CAS every 200 ms);
- the restarted region's replica reports current with zero lag and stores the
  stream up to its last sequence.

## Rollout from gateways

A server on this release and a server on the previous one cannot talk: the
cluster name, the transport (routes, not gateways) and the account (`ORCH`,
not the global account) all differ. There is no bridge. Reasons:

- The release push now installs one region at a time (`internal/releasepush`)
  and waits for JetStream recovery. A transport or account migration that
  cannot form a mixed-version cluster needs a separate migration design;
  the health gate stops an ordinary push during such a split.
- ts-orch's own updates use the release listener on 4222, not the mesh, so
  they keep working in the window and after it.
- Service applies retry each region every 30 s while they wait, so an apply
  in the window completes when the last region restarts.
- D24 allows production to break during the pivot.

## Orchestrator releases

Releases roll through the region catalog with the first founded region last:
sjc, fra, gru today. Before any install, every target must answer a version
probe within 10 seconds and report health `ok` where available (G0). No
responders or `no health check` accepts version alone for the first push;
other health failures, including an install or restart in progress, stop the
push before any install. G0 accepts any running version. Each region must
serve the requested SHA within its reported probation bound (G1), including
startup planning and the serving window. The pusher reports an accepted release
still in probation while waiting; [release recovery](m1-single-host.md) describes
the delivered units and independent guard. It must then report healthy
JetStream and regional services
continuously for 15 seconds within three minutes (G2). Health requires a
successful server health check, a leader and the configured replica count
for every stream. Every replica must be online, active within two seconds
(twice the Raft heartbeat interval), and at most 128 operations behind;
the instantaneous `Current` flag is not required. A named stream omitted
from stream info fails with `no leader answered`. Health also requires
a READY SwarmKit node and no service below
its desired replicas. Unreadable service state fails the gate; host memory
and disk pressure do not gate releases.

Only after G2 may the next region restart, keeping at most one of the three
JetStream peers down during the rollout. A region already running the release
still passes G1 and the full G2 health gate. A failed gate stops the push
and marks unreached regions skipped. G2 requires health replies from the
requested SHA, polling every two seconds
with an eight-second request timeout around a five-second handler budget.
The next install waits for G2 even when a rerun finds a region already current.

## Accounts

| Account | JetStream | Users | Use |
|---|---|---|---|
| `ORCH` | none | `orch`: the root CLI and the node, with the loopback token in `<state>/mesh/client.token` | service desired state, ping, release bridge |
| `TERRABASE` | 1 GiB memory, 36 GiB file (replicas counted), 64 streams, 4096 consumers | `ts-orch`: the node itself, with an in-memory password made fresh at each start; `terrabase`: each region's TerraBase, by the token in Vault secret `gru-1-terrabase-nats-token`, publishing and subscribing only on `terrabase.>` (plus `_INBOX.>` subscriptions) | the TerraBase fabric (D25): revision notices `terrabase.revision.<home>.<database>` |
| `$SYS` | system | none | JetStream cluster traffic |

- Secrets are random 256-bit values compared in constant time: their entropy
  protects them. One custom authenticator admits the loopback clients, because
  TerraBase's client sends a bare token and NATS cannot mix a token with users.
- TerraBase runs on the host network and dials `TS_NATS_URL=nats://127.0.0.1:4223`
  with `TERRABASE_NATS_TOKEN_FILE` (`deploy/m1/services/terrabase.json`). ts-orch
  creates the token in the gru Vault on first start and reads it on every start.
  Each admitted TerraBase client logs `mesh NATS admitted TerraBase` in the
  ts-orch journal. A refused token logs `mesh NATS refused a TerraBase token`.
- TerraBase uses JetStream inside its own account (D25). It may publish
  `terrabase.>`, `$JS.API.>`, `$KV.>`, `$JS.ACK.>` and `$JS.FC.>`, and subscribe
  to `terrabase.>` and `_INBOX.>`. It cannot reach `ORCH` or `$SYS`.
- TerraBase creates its own streams and buckets (R7 push, R8 leases and epochs,
  F8 provisional, events). The rules:
  - `Replicas: 3`, so region-unique placement puts one copy in each region;
  - stream subjects under `terrabase.`;
  - per-key TTL needs `LimitMarkerTTL` on the bucket (`AllowMsgTTL` on a stream);
  - CAS: `Create` or `Update` with the last revision;
  - deduplication: `Nats-Msg-Id` within the stream's `Duplicates` window.
- The `TERRABASE` account has its own route connection (pinned account).
  Fabric traffic therefore never delays service applies.

## Live facts explained (W0-9, 2026-10-29)

- **Route port 6222.** It is `mesh.ClusterPort`, the in-region cluster listener
  that #109 added. A founder binds it on its VCN address, so that a second host
  in the region can join as a worker. W0-9 read a commit that came before it.
  This change keeps the port and binds it on all interfaces: the NSG admits it
  only inside the VCN, and wt0 (NetBird) is accepted by the host firewall.
- **`ts-gru-1` reported hostname `ts-gru-2`** (renamed 2026-11-04, above). It is the OCI instance
  `gru-1-ctl-1` (10.251.0.11), created 2026-10-21 and tagged
  `terrascale-host-node=ts-gru-1`. Its NetBird peer name is `ts-gru-1`.
  `/etc/hostname` was rewritten to `ts-gru-2` on 2026-10-25 22:05Z. The journal
  no longer holds the writer. `ts-gru-2` was the old controller-cell name of
  10.251.0.12 (`deploy/netbird/README.md`). Its `/etc/hosts` still maps
  127.0.1.1 to `gru-1-ctl-1`, and cloud-init may reset the hostname on reboot.
  Only gru has the `terrascale-host-node` tag (sjc and fra have none). So no
  host property is a stable node identity, and JetStream peers are named by
  region instead. The hostname still appears as `Reply.Server` and `TS_NODE`.
