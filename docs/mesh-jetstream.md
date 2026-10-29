# Mesh NATS: one cross-region cluster with JetStream

Decision: PIVOT.md D17 and D25, user 2026-10-29 ("prefer re using the nats
cluster that we already have and use it to the max").

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

## JetStream

- JetStream runs on every founder (the host that answers for its region).
  Workers carry messages but store nothing.
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
  commit 7.2 s later (locally), inside the 4–9 s election window;
- the restarted region's replica reports current with zero lag and stores the
  stream up to its last sequence.

## Rollout from gateways

A server on this release and a server on the previous one cannot talk: the
cluster name, the transport (routes, not gateways) and the account (`ORCH`,
not the global account) all differ. There is no bridge. Reasons:

- The release push installs the binary in every region at the same time
  (`internal/releasepush`), so the mixed window lasts about one download and
  install.
- ts-orch's own updates use the release listener on 4222, not the mesh, so
  they keep working in the window and after it.
- Service applies retry each region every 30 s while they wait, so an apply
  in the window completes when the last region restarts.
- D24 allows production to break during the pivot.

## Accounts

| Account | JetStream | Users | Use |
|---|---|---|---|
| `ORCH` | none | `orch`: the root CLI and the node, with the loopback token in `<state>/mesh/client.token` | service desired state, ping, release bridge |
| `TERRABASE` | 1 GiB memory, 36 GiB file (replicas counted), 64 streams, 4096 consumers | `ts-orch`: the node itself, with an in-memory password made fresh at each start | the TerraBase fabric (D25) |
| `$SYS` | system | none | JetStream cluster traffic |

- Passwords are stored bcrypt-hashed in the server.
- The `TERRABASE` account has its own route connection (pinned account).
  Fabric traffic therefore never delays service applies.

## Live facts explained (W0-9, 2026-10-29)

- **Route port 6222.** It is `mesh.ClusterPort`, the in-region cluster listener
  that #109 added. A founder binds it on its VCN address, so that a second host
  in the region can join as a worker. W0-9 read a commit that came before it.
  This change keeps the port and binds it on all interfaces: the NSG admits it
  only inside the VCN, and wt0 (NetBird) is accepted by the host firewall.
- **`ts-gru-1` reports hostname `ts-gru-2`.** It is the OCI instance
  `gru-1-ctl-1` (10.251.0.11), created 2026-10-21 and tagged
  `terrascale-host-node=ts-gru-1`. Its NetBird peer name is `ts-gru-1`.
  `/etc/hostname` was rewritten to `ts-gru-2` on 2026-10-25 22:05Z. The journal
  no longer holds the writer. `ts-gru-2` was the old controller-cell name of
  10.251.0.12 (`deploy/netbird/README.md`). Its `/etc/hosts` still maps
  127.0.1.1 to `gru-1-ctl-1`, and cloud-init may reset the hostname on reboot.
  Only gru has the `terrascale-host-node` tag (sjc and fra have none). So no
  host property is a stable node identity, and JetStream peers are named by
  region instead. The hostname still appears as `Reply.Server` and `TS_NODE`.
