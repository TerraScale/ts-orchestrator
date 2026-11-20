# Platform design

This is the target design of the TerraScale platform. It states decisions.
Later pull requests and operators read this page as the one source. Where
today's code differs, a Today line names the pull request or category that
changes it.

## Overview

One orchestrator binary, `ts-orch`, runs on every node of every region. Each
region is one SwarmKit cluster. Regions talk over an embedded NATS mesh.

The orchestrator owns releases, Oracle Cloud (OCI) resources, routing and
scaling. GitHub Actions only tests, builds and nudges.

## Releases

Releases are pull, never push.

CI on `main` tests and builds static `linux/amd64` and `linux/arm64` binaries
with `-trimpath -buildvcs=true`. It publishes them on the GitHub release
`ci-<sha>-run-<id>`. CI holds no long-lived production credential and observes hosts through
authenticated HTTPS 443.

Hosts discover the newest attested orchestrator release. CI publishes binaries,
qualification and Sigstore provenance; hosts verify the workflow, main source,
transparency evidence and exact binary digest before installation.

The region list is `catalog.RolloutOrder` (sjc, fra, gru), written once in the
region catalog. App releases (TerraBase, ts-auth, ts-dashboard) follow it one
region after another. Orchestrator binaries use it in two phases: its first
entry, sjc, is the canary; fra and gru take a tag only after sjc records that
exact tag complete in the fabric pull store and passes its regional health
gate, and then roll out at the same time. A tag that any region is rolling back
or has rolled back is held by every region that has not started it.
Hosts update one at a time inside their region. The completion timestamp is persisted; a new owner restarts any unfinished
bake before recording its verdict, and a passed gate keeps its end time. During
the bake the leader checks every host and regional health; a failed bake starts
rollback in that region and holds the regions that have not started.
Probation still restores a binary that never serves.

Application hosts pull the existing package's release pointer and require both
build provenance and a separate signed release-selection attestation. The
selection must bind the service, image revision and digest, come from the
service's main workflow, and carry an allowed trigger. TerraBase requires a
manual workflow_dispatch selection. The selecting run and attempt identify
the durable rollout, including its hold and rollback.

CI reads authenticated observations on HTTPS 443. See [network exposure](network.md)
for listener owners and staged removal of the live public 4222 rules.

## Identity and access

SSH keys are the identity. The roles are `read`, `operate`, `release` and
`fleet`.

The remote CLI authenticates by signing a challenge with the SSH agent (C4).

A key stored on a shared server where agents run never gets `release` or
`fleet`.

Today: the CLI has no remote access; operators run it on the nodes.
Roles and the SSH login come with C4.

## Cluster shape

Every region has three manager nodes. Further nodes join as workers.

Join material lives in the Vault secret `ts-orch-join-<region>`. The secret
holds the manager token, the manager addresses and the mesh routes. The Raft
leader keeps the secret current (C5a).

Every manager runs the public edge. A request for a service with no ready
replica on that node goes edge-to-edge, once, to a node of the same region
that has one. The hop carries the peer credential and the header
`X-TerraScale-Edge-Hop` (C5b).

Edge certificates are shared per region through Vault secrets
`ts-orch-edge-<region>-<hash>`. Let's Encrypt allows 5 duplicates a week. A
stopping node starts answering 503 on `/healthz` at the stop signal and keeps
the 20 s drain while admitting application requests during load-balancer
propagation (C5c). Mesh preparation overlaps that window and gets at most 5 s.
After the drain, active HTTP requests get at most 5 s before their connections
close, including streamed responses and hijacked WebSockets. Nodes without
recent external health probes skip the 20 s window.

All shutdown joins share a deadline 30 s after the stop starts, including the
SwarmKit node, mesh, edge and background services. An unfinished wait logs its
component once and is abandoned without changing persistence call ordering or
stopping TerraBase containers. The systemd stop timeout is 45 s: the process
budget plus 15 s of margin for service-manager delivery, scheduling and reaping.

Nodes live on private subnets with a NAT gateway. The only public address of
a region is its network load balancer.

Today: each region has one manager and one worker; only the manager serves
the edge; certificates are per node; nodes have public addresses with no
load balancer. C5a, C5b and C5c change the code; the new fleet (C7)
changes the servers.

## OCI ownership

One fleet document, `deploy/fleet/fleet.json`, records every region: its
label, OCI region, compartment, VCN, public subnet (load balancer only),
private subnet (nodes), node count and shape, and the public names it serves.
It also records the DNS zone, the steered names, their TTL and the
health-check path. `internal/fleet` loads and validates it; the binary embeds
it, and `make release-check` runs `ts-orch region validate` on the built
binary so a bad document never ships.

Per region the document holds: label, OCI region, compartment, VCN CIDR,
public subnet CIDR (load balancer only), private subnet CIDR (nodes), nodes
(min, max, shape, OCPUs, memory, boot GB, data volume GB and VPUs per GB,
the data volume created apart from the launch), and the continents its
geo-steering answers. Every continent is answered by exactly one region.
Globally it holds the DNS zone and its compartment, the steered names, their
TTL and the health-check path. A region's plain record is always
`<label>.api.<zone>`, derived from the label.

These live in code, not in the document: the node image (the release pins
it), the spread of nodes across availability domains and then fault
domains, NSG rules, and the network load balancer's reserved address, which
the reconciler reserves. Today's public addresses are ephemeral instance
addresses that OCI cannot turn into reserved ones; the move to the load
balancer goes through DNS.

The document is not signed separately. A change is a reviewed pull request;
only a merged release, trusted through its GitHub build attestation, carries
it to the nodes.

A region has at least 3 nodes and, for now, at most 3. Validation refuses a
minimum below 3, a maximum below the minimum, a maximum above 3, overlapping
CIDRs, a duplicate label and a name outside the zone.

`ts-orch region plan` compares the document with what exists in OCI and
changes nothing; `ts-orch region status` prints the same in one line per
region. A resource is document-made when `ociresource.Ownership{Owner:
"terrascale"}.Owns` accepts its tags for its key: `terrascale-managed-by`
`ts-orchestrator`, `terrascale-owner` `terrascale` and
`terrascale-resource-key` `<CELL>/<kind>/<name>`. The keys are `vcn/vcn`,
`subnet/host-subnet` (public), `subnet/private-subnet`,
`internet-gateway/igw`, `nat-gateway/nat`, `service-gateway/sgw`,
`route-table/public-routes`, `route-table/private-routes`,
`nsg/edge-nsg`, `nsg/host-nsg`, `nsg/node-nsg`, `instance/node`,
`network-load-balancer/nlb`, `public-ip/nlb`, and in the DNS compartment's
cell `dns-zone/zone`, `http-monitor/edge`, `dns-record/<region label>`
and `steering-policy/<first label>`, a steering policy
being named after its steered name. A resource with any other ownership tag
is claimed by another owner; one with none is hand-made (foreign). Neither
is ever changed, except that the DNS pass can adopt an unclaimed zone by
its immutable DNS name while preserving existing records.

`ts-orch region apply <label> <kind>...` runs the named passes of the
single list `fleet.Passes` once for one region; a bare apply refuses and
lists the kinds. The `network` pass reads, and never changes, the VCN, both
subnets, the internet and service gateways and `nsg/edge-nsg` and
`nsg/host-nsg`; it stops if one of them is missing, duplicated or not
document-made. It owns three network kinds:

| Kind | Key | What the pass keeps |
|---|---|---|
| NAT gateway | `nat-gateway/nat` | `<cell>-nat` in the VCN, not blocking traffic; created when missing |
| Route table | `route-table/private-routes` | `<cell>-private-routes`, attached to the private subnet only, with exactly `0.0.0.0/0` to the NAT gateway and the region's Oracle services to the service gateway |
| NSG | `nsg/node-nsg` | `<cell>-node-nsg` with exactly these rules: TCP 80, 443 and 5432 from anywhere, since the network load balancer preserves the client source address; TCP 4222 (NATS client), 6222 (NATS cluster), 7422 (NATS leafnode) and UDP 51820 (NetBird WireGuard) from the VCN; all egress |

The pass refuses to change a route table that is the VCN's default or that
any other subnet uses, so the public subnet's routes are never touched. The
node NSG has no members until nodes join it. How to run and undo it is in
`docs/oci-reconcile.md`.

`ts-orch region apply gru dns` owns the global DNS pass. It uses the fleet
DNS compartment, every region's owned NLB reserved address and the document's
continent assignments. One shared HTTP monitor probes every NLB on :80
`/readyz` every 10 seconds; all five managed OCI steering policies reference
it. Healthy answers prefer the assigned region and then the nearest remaining
region, with TTL 30. Region additions and removals update the monitor,
policies and owned regional A records on the next apply. Public Cloudflare
names become DNS-only CNAMEs into the OCI zone only after a separately gated
cutover; until that gate passes their existing records remain in place.
See [DNS reconciliation](oci-reconcile.md#fleet-dns-pass) and
[the cutover procedure](network/geodns.md).

Each region's SwarmKit Raft leader runs the passes listed in its region's
`reconcile` field of the fleet document once a minute
(`internal/ociresource/runner.go`). gru, sjc and fra list `network`,
`nlb` and `nodes`; gru, the DNS region, also lists `dns`. `compute` joins a region when
that region moves onto document-made nodes. How the loop is fenced, limited and observed is in
`docs/oci-reconcile.md`, "Reconcile loop". Over the regions, the
reconcilers create and update these resources:

- VCNs
- subnets
- NAT gateways
- NSGs
- instances
- volumes
- network load balancers
- reserved addresses
- DNS records
- steering policies
- health checks

The loop authenticates as the instance (instance principal); `region apply`
uses the operator's config when it has one.

The commands are `ts-orch region add`, `ts-orch region edit`, `ts-orch region rm`,
`ts-orch region plan` and `ts-orch region status`. The production bootstrap
gap remains documented in [region bootstrap](region-bootstrap.md).

The reconciler touches only resources that carry its ownership tags. It
never deletes data volumes, buckets or backups by itself. Compartment quotas
cap spend.

It builds on this existing code:

| Code | Already there |
| --- | --- |
| `internal/oci` | OCI package |
| `internal/ociclient` | OCI client |
| `internal/ociresource` | Reconcilers for lb, nsg, seclist, routetable and bucket |
| `internal/ociregion` | foundation, publicapi and peer |
| `internal/edge/geodns` | GeoDNS |

Today: the region leaders keep `network`, `nlb` and gru's `dns` in sync every
minute; the rest was created by operator commands with an API key. The document and
`region plan` exist. `ts-orch region apply <label> nlb` creates and keeps each
region's network load balancer and its reserved address (docs/oci-reconcile.md,
"Network load balancer"); gru, sjc and fra have one since 2026-11-16,
referenced by the staged OCI DNS zone while public names still use nodes.
The network, global DNS, compute (C8) and node count (C12) passes are
implemented; production regions do not list `compute` yet, so their node
count holds at 3.

### Nodes: the compute kind

`ts-orch region apply <label> compute` runs `fleet.ApplyCompute`
(`internal/fleet/compute.go`, resources in `internal/ociresource/compute`).
It needs the document-made private subnet and the node NSG `nsg/node-nsg`
and makes, in the region's compartment:

| Key | Resource |
| --- | --- |
| `instance-configuration/node` | Shape, OCPUs, memory and boot size from the document; the newest Canonical Ubuntu 24.04 image for the shape; the private subnet, the node NSG and no public address; the first-boot script with the newest attested release, refused when that release's fleet document lacks the region in its compartment. |
| `instance-pool/nodes` | One pool, created at `nodes.min`, one placement per availability domain with all its fault domains. Its instances carry `instance/node`. |
| `volume/data-<n>` | One data volume per node, `n` up to `nodes.max`, `data_gb` and `data_vpus_per_gb`, made with `CreateVolume` and `AttachVolume`, never at launch. |

The ts-orch-hosts dynamic group matches every instance in the three region
compartments, so a pool node has the instance principal the join needs.

A pool size below `nodes.min` is raised. The compute kind never shrinks the
pool; the `nodes` kind below removes one drained node at a time. A node without a data volume gets
a kept one from its availability domain, or a new one. Image and release
are fixed when the configuration is made; a newer release reaches the nodes
through the release self-pull, so a second apply changes nothing.

A node's first boot needs no person (`internal/nodeinit`): it waits, with no
deadline, for the apply to record its data volume in the instance metadata,
formats it only when the volume was never bound to another node, mounts it,
installs the pinned release the way `deploy/m1/install.sh` does, and starts
ts-orch. ts-orch reads `ts-orch-join-<region>` from the gru Vault (`internal/regionjoin`),
joins as a worker and is promoted until the region has three managers
(`internal/swarmruntime/manager_promotion.go`).

### Node count: the nodes kind

The `nodes` kind (`internal/fleet/nodes.go`) decides each region's node count
on the region leader every tick, between the document's `nodes.min` and
`nodes.max`; no bound lives in code. The document's floor is 3, the three
managers. Each region lists `nodes`; the scaler only grows or shrinks
the document-made pool, so a region without one holds its count.

| Step | When | What |
| --- | --- | --- |
| Grow | For 3 min the replica autoscaler (C11) could not place more replicas of a service (`region-capacity`, after admission), the count is below `nodes.max`, the pool is `RUNNING` and the last change is 10 min old. | The pool size goes up by one. The next change waits until every pool node has joined the swarm and is ready. |
| Cordon | For 15 min no service was blocked or growing and no task waited for a node, the count is above `nodes.min` (or above `nodes.max`), and the last change is 10 min old. | One pool worker whose tasks fit on the other nodes (SwarmKit's own scheduler filters) is set to drain and labelled `terrascale.drain-since`. Fewest tasks first. |
| Remove | The drained node runs no task and no task of the region waits for a node. | That instance is detached from the pool with the size decremented (never the pool's own termination choice), soft-stopped, its data volume detached and kept, terminated with `preserveDataVolumesCreatedAtLaunch=true`, then removed from the swarm. |
| Retire | An instance carrying the `instance/node` ownership tag is outside the pool and in no swarm, for example because a leader died between the detach and the terminate and the swarm node was then removed. | It is terminated the same way, keeping its data volume. A drained node still in the swarm takes the Remove step instead. |

Refusals, counted every tick in `ts_orch_node_scale_refusals_total{reason}` and logged when they begin:

| Reason | Rule |
| --- | --- |
| `quorum` | Fewer than three ready managers, or the only candidate is a manager. Managers are never drained; promotion keeps three. |
| `last-copy` | The node runs a stateful task (TerraBase or `terrascale.stateful`). The orchestrator has no signal that another copy of that data is caught up, so the guard is per node holding data, not per running copy: a pool worker that holds data is never drained by the scaler. Move or replicate the data by hand, then the node becomes a candidate. |
| `no-room` | The other nodes cannot take the node's tasks. |
| `bounds` | Demand cannot be placed and the count is `nodes.max`. At `nodes.min` with low demand the scaler holds (`at-min`); no step goes below `nodes.min` or above `nodes.max`. |
| `in-flight` | A pool node has not joined yet, or a drain is running: one change per region at a time. |
| `unhealthy` | The leader took over less than 5 min ago, or a node is not ready or not active. |
| `drain-stuck` | The drained node's tasks did not move within 10 min. The node stays cordoned, `NodeDrainStuck` fires, and nothing else changes until a person resolves it: `ts-orch member activate <host>` returns it to service and clears `terrascale.drain-since`, so a later hand drain is never taken for the scaler's. |
| `no-pool`, `no-pool-node` | No document-made pool to grow, or no pool node to remove. Hand-made hosts are never removed. |

Every step is derived from the swarm and the pool, so a new leader resumes a
drain or a join instead of starting another change, and it waits 5 min and a
full 10 min cooldown before its first new change. `ts-orch status` and
`ts-orch region status` print the leader's last decision as
`nodes: <action> <actual> [-> <desired>] (bounds min..max): <reason>`.
Metrics: `ts_orch_node_scale_{actual,desired,decision,decision_timestamp_seconds,drain_stuck}`.
The swarm removal is `swarmruntime.RemoveMember`, the path C14 (self-heal)
and `ts-orch member leave` use; the instance removal is `compute.Pass.Retire`.
The e2e-m1 `operator` lane's `node-scale` case runs on a four-node in-process
region with no OCI: `Decide` refuses a new leader and a manager candidate, cordons
one worker, plans only its removal while it is drained, and after the leader is
stopped the new leader's `Decide` picks the same drained worker; the case then
calls `RemoveMember` on the new leader. It feeds `Decide` chosen times, a pool and
quiet demand. The full resume on a leader change (Authorize, Retire, then
RemoveMember), tasks moving off a drained node and the `last-copy` refusal are
not proven against live OCI here.


A node that stays unhealthy for 5 minutes is rebooted once through OCI and,
if that does not help, replaced by the region leader, one node at a time,
never against Raft quorum, the last healthy copy of a database's data or a
region-wide failure, and at most once a day per region. It only acts where
`compute` is reconciled. See `docs/oci-reconcile.md`, "Self-heal".

## Routing

`dash`, `mcp`, `platform` and `auth` under `terrascale.tech` use GeoDNS. GeoDNS
is an OCI steering policy with health checks. The zone is
`edge.terrascale.tech`, delegated from Cloudflare. Each name resolves to the
nearest healthy region's load balancer.

`<region>.api.terrascale.tech` is a plain record to that region's load
balancer. The labels in use are `gru`, `sjc` and `fra`. Every new region gets
its record automatically.

`api.terrascale.tech` uses GeoDNS too, for testing convenience only. SDKs do
not use it except as the fallback when Atlas is unreachable.

Today: the OCI zone is delegated, its five steering policies and shared
monitor exist, and regional A records point to the reserved NLB addresses.
The eight public names still point directly to node 1 through Cloudflare
DNS. Address-Host readiness and TLS checks have not passed, so the public
CNAME cutover is deferred to C10b. See [the cutover procedure](network/geodns.md).

## Atlas

Atlas is a Cloudflare Worker at `atlas.terrascale.tech`. Its code is
`atlas/` in the terrascale repo.

| Store | Role |
| --- | --- |
| D1 | The record |
| One Durable Object | Every write, in order |
| KV | The worldwide read cache |

The routes are `/v1/discovery`, `/v1/resolve`, `/v1/keys` and a signed
`POST /v1/publish`.

The orchestrator publishes topology every 10 s. TerraBase publishes every
database's home region on create, on move and on delete, through an outbox,
and re-sends every 10 minutes. One placement per database:

```text
{v, project, database, region|null, updated}
```

A region's `api` origin must be `https://<label>.api.terrascale.tech`.

Today: atlas.terrascale.tech is not deployed (C9 rebuilds it, C10
publishes placements).

## SDKs

On first use for a database, an SDK asks Atlas once. It caches the answer in
memory and on disk. The disk cache is the user cache directory, mode `0600`.
From then on the SDK talks straight to `<region>.api.terrascale.tech`.

The SDK asks Atlas again only in two cases. The region answers HTTP 421, and
the SDK reads `X-TerraBase-Database-Home`. Or the region stops answering.

When Atlas is unreachable and nothing is cached, the SDK uses
`api.terrascale.tech`. An explicit base URL skips Atlas. An SDK accepts only
hosts under `api.terrascale.tech`.

Today: SDKs default to api.terrascale.tech and don't use Atlas or
follow 421 (C11).

## ts-auth in every region

Step 1. Replicas run in every region. All of them use one ts-auth database
homed in `gru`. That database stays the single writer. `auth.terrascale.tech`
is geo-routed. There is one SMTP endpoint.

Step 2. Each region has a readable copy, and the home can be promoted.

Today: ts-auth runs only in gru with one replica (C12 removes the code
limit; the new fleet deploys it).

## Scaling and self-healing

Replicas scale on CPU, memory and requests
(`internal/swarmruntime/autoscale.go`).

A node is added when the replica autoscaler cannot place the replicas load
needs. A node is drained and removed when load stays low. The count never
goes below three managers. The last copy of a database is never removed.
See "Node count: the nodes kind".

A region is created automatically when demand from a geography stays high,
and only inside an allowed list and a budget. A region is removed only when
it is empty.

A node that stays unhealthy for too long is replaced.

Today: replicas and the node count scale on the region leader. Every region
requires 3 voting hosts to survive losing one: sjc and fra hold 3 pool
nodes (`nodes.min` = `nodes.max` = 3); gru holds 2 pool nodes plus the
external host `ts-gru-1` (`nodes.external`), which runs NetBird management
and monitoring outside the pool. The document refuses a region whose
`nodes.min` plus its declared external hosts is below 3. Before compute apply
uses those pool bounds, every external name must resolve to exactly one live
OCI instance, re-read by its instance ID: RUNNING, in the region's compartment,
with an attached primary VNIC in that compartment and the region's VCN. It
must carry no regional pool-instance ownership and belong to no live instance
pool in the compartment; an unavailable OCI check refuses the apply.

Provisioning does not prove voting readiness. Promote the hosts with
`ts-orch member promote`, then run `ts-orch region status <label>` on a host
connected to that region's environment mesh. This is the rebuild's quorum
gate and exits unsuccessfully until `swarm quorum` is `ok`. Both `region plan`
and `region status` read live SwarmKit membership through regional health
requests over NATS and require at least 3 distinct node IDs, OCI instance IDs
and hostnames. Each must be a current and desired manager, READY and
Raft-reachable, with the region's admission label and an identity matching a
RUNNING regional pool host in the private subnet or a verified external host.
A worker-only external host never supplies a vote. Missing membership or an
invalid external host keeps the gate closed. Without a label, the commands
report every fleet region. Load beyond the fixed host count is absorbed by
replicas and the shape.

## What was removed

C2 deleted the old controller, the host agent, the cell spec and signed
channel generation.

C4 deleted the second runtime, the managed/root runtime that production never
started, so the binary has one runtime, `ts-orch node` (renamed in C5). C4
removed:

- the commands `managed-host-start`, `managed-runtime-start`,
  `function-worker`, `root-oci-qualification`,
  `root-oci-qualification-read`, `root-oci-qualification-probe`,
  `bootstrap-credential-check`, `bootstrap-admit-initial`,
  `bootstrap-admit-restart`, `identity-rekey-completion-check`,
  `qualification real-caller`, `runtime-priority`, `image`, `selfupdate`
  and the `release` receipt, delegation, channel and cell commands
  (`release deploy`, `apply`, `sign-*`, `verify-binary`, `verify-image`,
  `verify-production`, `service-deploy`, `fleet-status`, `observed-digests`
  and the rest of the old signed-receipt set), and `region create`, the
  old founding path (C4b);
- every package only those commands reached, among them the root OCI,
  root capacity, root secret, root release, managed material, container
  material, function worker, runtime-priority, rollout executor, host image
  and A/B self-update packages;
- the managed-host systemd units and self-update drop-ins under
  `deploy/systemd`, the host image build scripts under `deploy/image`, the
  udev rule, `make image` and the D15 probe publication in CI;
- the root-rotation runbook (C4b).

Release recovery stays: a node pulls or receives a release, runs
`release preflight` on the candidate and `release recover` from its recovery
unit. The node autoscaler and OCI reconciler packages stay for the next
categories, which rebuild them on `ts-orch node`.

## Order of work

| Phase | Work | Done when |
| --- | --- | --- |
| 0 | Scouts and this document | This document is the design source |
| 1 | Purge | C2 has deleted the old controller, host agent, cell spec and signed channel generation |
| 2 | Signed pull releases and the SSH CLI | Nodes accept only a signed manifest with a higher sequence, and the remote CLI signs a challenge (C3, C3b, C4) |
| 3 | Three managers and the edge everywhere | Join material, the one edge hop and shared edge certificates match Cluster shape (C5a, C5b, C5c) |
| 4 | Fleet document, reconciler, load balancers, private subnets | The fleet document reconciles those resources, and a region's only public address is its network load balancer |
| 5 | New fleet from bootstrap, data restored, DNS switched, old servers deleted | The production bootstrap path has founded the fleet, data is restored, DNS points at it and the old servers are gone |
| 6 | GeoDNS, regional names, Atlas, SDK resolvers, ts-auth step 1 | Routing, Atlas, the SDKs and ts-auth step 1 match this document |
| 7 | Autoscaling of replicas, nodes and regions, ts-auth step 2 | Scaling and self-healing and ts-auth step 2 match this document |
| 8 | Drills: node loss, region loss, bad release, Atlas down, region add and remove | Each drill has linked proof |
