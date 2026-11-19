# Regional OCI reconciliation

Regional reconciliation is always on at a fixed one-minute cadence. The ordinary
controller calls the concrete `rootoci.Client.ReconcileFoundation` endpoint; it
has no OCI SDK fallback. Root reconciles the signed regional foundation before
reconciling signed amendments. An absent `controller.oci_reconcile` section means
there are no configured amendments; foundation reconciliation still runs.

The retired `enabled`, `interval_seconds`, `tag_mode` and `tag_namespace` fields
are rejected. Ownership always uses the region owner and the existing freeform
`terrascale-managed-by`, `terrascale-owner` and `terrascale-resource-key` tags.
Foreign resources are reported and never adopted or changed.

## Signed amendment authority

Root independently opens the exact accepted controller configuration, current
root chain and current root-signed cell spec. `oci_reconcile.desired` supplies
the installed baseline; a current root-signed `oci_desired` cell-spec section
replaces that baseline. A leaf-signed current spec cannot authorize amendments.
All admitted desired entries enforce their signed specs.

Root uses ordered stream-leader reads. A missing stream, deletion, purge or
missing source after prior history fails closed. An untouched, empty source
stream can represent the installed baseline. The protected journal retains the
accepted spec generation even when there are no desired resources, so a later
pass cannot silently roll back to the baseline.

The ordinary controller supplies no desired payload, provider or cloud target
through IPC. Root derives these values and checks the sealed call, exact runtime
candidate, deployment, own cell, current lease and original deadline. Observing
a lease never promotes it into root mutation authority. Source, drain and
placement facts are reread at mutation fences. Renewed leases or credentials
cannot extend an operation's original effect deadline.

## Managed amendments

| Kind | Desired state | Effect |
|---|---|---|
| `nsg-rules` | Signed `desired.nsg_rules` | Converges rules on an already owned, region-admitted NSG. |
| `security-list-rules` | Signed `desired.security_lists` | Replaces rules under If-Match on an owned security list. |
| `route-table-rules` | Signed `desired.route_tables` | Replaces static routes under If-Match; OCI `LOCAL` routes stay untouched. |
| `bucket-protection` | Signed `desired.buckets` | Observes versioning and marked retention rules; property mutations require CAP admission. |
| `lb-backends` | Signed `public_lb` plus the TerraBase profile and drain records | Converges one owned L7 backend set while preserving the serving-health guard. |

NSGs, security lists, route tables, buckets and load balancers themselves are
never created or deleted by these amendment reconcilers. Member hosts and data
volumes remain with the journaled regional fleet.

## Network load balancer (`nlb` kind)

`ts-orch region apply <label> nlb` reconciles one public network load balancer
per region from the fleet document (`internal/fleet/nlb.go`). It needs the
document-made public subnet (`subnet/host-subnet`) and both NSGs
(`nsg/edge-nsg`, `nsg/host-nsg`) and refuses without them.

| Resource | Key | Desired state |
|---|---|---|
| Reserved public IP `<label>-1-nlb-ip` | `<CELL>/public-ip/nlb` | Created once, owned by the reconciler, never released by it. |
| Network load balancer `<label>-1-nlb` | `<CELL>/network-load-balancer/nlb` | Public, IPv4, in the public subnet, the reserved IP, NSGs edge and host, source/destination preservation off. |
| Backend sets `tcp-80`, `tcp-443`, `tcp-5432` | inside the NLB | Five-tuple hash, source address preserved, fail-open, no instant failover. Backends are every RUNNING instance whose primary VNIC is in the region's VCN, on its private address and the same port, weight 1. |
| Health check | each backend set | HTTP :80 `/readyz`, 200, every 2 s, 1 s timeout, 2 failures (1 retry). |
| Listeners `tcp-80`, `tcp-443`, `tcp-5432` | inside the NLB | TCP on the same port to the backend set of the same name. |

Every resource carries `terrascale-managed-by`, `terrascale-owner` and
`terrascale-resource-key`; a load balancer or address with other tags is never
used or changed. A backend is referenced by its private address only, so a
hand-made host is unchanged by joining. A second apply prints `ok` and changes
nothing. Backend set, listener and NSG drift is corrected in place; a different
subnet, address or source mode cannot be changed by OCI and is reported.

The edge answers `/readyz` over :80 for an address Host (what the NLB checker
sends: no SNI, no name) with its own readiness: 503 while draining or not
ready, 200 when ready. NLB probes read cached readiness while the background
worker probes backends. The edge keeps admission open for the derived six-second
withdrawal bound when the live policy matches, or twenty seconds when it is
unverified or differs. Startup and stop-time fleet reads protect mixed versions
and rollback. Existing flows retain the edge's 25 s completion share. Apply
and verify the new policy before the binary; see `docs/host-install.md`. When every
backend of a set is unhealthy, OCI's default (`isFailOpen` false) drops all
traffic; the pass sets fail-open so the NLB keeps distributing to every backend
and the region's DNS health check decides whether the region gets traffic.

Undo, per region (nothing else references these resources until DNS steering
points at the address):

```sh
oci nlb network-load-balancer delete --region <oci-region> --force \
  --network-load-balancer-id <id of <label>-1-nlb> --wait-for-state SUCCEEDED
oci network public-ip delete --region <oci-region> --force \
  --public-ip-id <id of <label>-1-nlb-ip>
```

Deleting the load balancer leaves the hosts untouched; deleting the reserved IP
gives its address back to OCI for good.

## Compute pass

`ts-orch region apply <label> compute` reconciles a region's nodes from the
fleet document with the operator's `~/.oci/config` (or the instance
principal). It reads the document-made private subnet
(`subnet/private-subnet`) and node NSG (`nsg/node-nsg`) and refuses to run
without them. Keys are `<CELL>/instance-configuration/node`,
`<CELL>/instance-pool/nodes`, `<CELL>/instance/node` (every pool instance,
from the configuration's launch tags) and `<CELL>/volume/data-<n>`.

| Step | Effect |
| --- | --- |
| Instance configuration | Kept when shape, OCPUs, memory, boot size, subnet, NSG and no public address match; otherwise a new one is made, the pool switched to it for new nodes, and the old one deleted. Running nodes are not replaced. |
| Pool | Created at `nodes.min` across every availability domain and its fault domains; raised to `nodes.min` when below. The pass waits up to 20 minutes for the pool to be `RUNNING` with every instance running before it changes anything, and stops with the pool's state otherwise. |
| Size | Never lowered by this pass. The `nodes` kind grows and shrinks the pool one drained node at a time (`docs/platform.md`, "Node count: the nodes kind"). |
| Data volumes | A node with an attached owned data volume keeps it. Otherwise it gets the lowest kept volume in its availability domain, or a new one (at most `nodes.max`). The volume records the node in `terrascale-data-instance`; the node's metadata gets `terrascale-data-volume`, `terrascale-data-may-format` (true only while `terrascale-data-instance` is empty or names this node) and `terrascale-data-uuid`, the filesystem UUID chosen at volume creation. |

No step deletes a data volume; `VOLUME_DELETE` is not granted. A node waits
for its binding with no deadline, so a pool that settles late still mounts and
joins on the next apply. A volume that fails the `internal/nodeinit` checks
stops the first boot and installs nothing. A node
whose join fails keeps ts-orch running and retries the Vault read every 30
seconds, logging the error, until it joins or the pass scales it in.

Undo a region's nodes (operator credentials; data volumes stay):

```sh
oci compute-management instance-pool list -c <compartment> --query "data[?\"freeform-tags\".\"terrascale-resource-key\"=='<CELL>/instance-pool/nodes'].id"
oci compute volume-attachment list -c <compartment> --instance-id <node>   # detach each data volume first
oci compute volume-attachment detach --volume-attachment-id <attachment> --force
oci compute-management instance-pool terminate --instance-pool-id <pool> --force
oci compute-management instance-configuration delete --instance-configuration-id <configuration> --force
```


## Protected operations and observations

Amendment desired state and operation history live in `OCIResources` inside the
existing protected own-cell foundation object. They share its unchanged
128 KiB whole-object bound and compare-and-set revision. Each update rereads the
whole record and preserves unrelated foundation, IAM, capacity and original
create history. A conflicting or uncertain conditional write is not retried
blindly.

Before each cloud mutation, root checkpoints its exact method, URL, body,
If-Match, retry token, start and original deadline. Authorization headers are
never stored. Each operation retains at most 128 requests; each body is bounded
at 64 KiB, with the smaller shared whole-object limit still applying. Retries
retain original bytes, token and deadline. An uncertain request prevents a
different mutation until its original outcome is resolved. Revoked desired
authority may still be observed to confirm an original operation; it cannot
start a new effect.

`TS_OCI_OBSERVED` remains an observation store for drift insights. It does not
authorize cloud writes. Seat rollout obtains fresh backend observations through
root IPC on every request. Root checks exact load-balancer identity, ownership
and signed TerraBase membership, with bounded backend and health rows.

## Pruning and protection

Pruning requires current signed removal authority over a prior protected entry.
It first records a tombstone with removal provenance and a not-before time.
NSG and load-balancer cleanup remains fenced and ownership checked; a later
observation confirms removal before the protected entry is purged.

Security-list, route-table and bucket tombstones relinquish management without
changing cloud protection. Locked retention rules are never created, shortened
or deleted. Retention rules outside this reconciler's display-name marker remain
untouched. Existing empty-rule, empty-route and serving-backend safeguards still
apply.

## Open integration requirements

Unsigned legacy `TS_OCI_DESIRED` records are never imported as authority. Their
migration is **OPEN**; discovering legacy desired state stops the amendment pass.

The additive protected-object schema requires final ROOT and security approval.
Bucket property-spend admission requires CAP authority; absent that authority,
property mutations fail closed. Source fixtures do not qualify the full real
root-IPC and OCI-SDK amendment path. That end-to-end qualification remains
**OPEN** until the integrated candidate passes its leased QA run.

## Region apply

`ts-orch region apply <label> <kind>...` is an operator command that runs the
named passes once for one region of the fleet document, in the order of
`fleet.Passes`. A bare `ts-orch region apply <label>` refuses and lists the
registered kinds. It uses the operator's `~/.oci/config` when that file exists
and the instance principal otherwise, like `region plan`. Run `region plan`
before and after:

```sh
ts-orch region plan
ts-orch region apply gru network
ts-orch region apply gru network
ts-orch region plan
```

Each line of the output is `ok`, `created` or `updated` with the resource. A
second apply prints only `ok` lines.

The `network` pass changes only resources carrying its own keys
(`docs/platform.md`, "OCI ownership"): it creates the NAT gateway and the node
NSG when missing, sets the private route table's rules and attaches that table
to the private subnet. It stops before changing anything if the VCN, a subnet,
the internet or service gateway, the edge or host NSG is missing or not
document-made, if a NAT gateway without its key is in the VCN, if two live
resources carry the same key, or if the private route table is the VCN default
or used by another subnet. Every step can be run again: a half-failed apply
leaves only finished steps behind, and the next apply continues from there.

Two applies at once: OCI allows one NAT gateway per VCN and answers the second
create with 409 Conflict. The route table update carries its `If-Match` ETag,
so one of two writers fails with 412. Two node NSGs can be created; the next
apply then stops with `2 live resources carry <key>` and the extra one is
deleted by hand. Duplicate NSG rules are removed by the next apply.

Undo, newest first, with the IDs the apply printed:

```sh
oci network nsg delete --nsg-id <node-nsg id> --force
oci network route-table update --rt-id <private-routes id> --force \
  --route-rules '[{"destination":"<all-<label>-services-in-oracle-services-network>","destinationType":"SERVICE_CIDR_BLOCK","networkEntityId":"<service gateway id>"}]'
oci network nat-gateway delete --nat-gateway-id <nat id> --force
```

The node NSG must have no members to be deleted. The route-table update puts
back the services-only rule set it had before the first apply; the NAT gateway
can be deleted only after no rule targets it. When the apply created the
private route table (`created route table` in its output), detach it from the
private subnet with `oci network subnet update --route-table-id` to the table
it used before, then `oci network route-table delete --rt-id <id> --force`.

`ts-orch oci-region network` and `ts-orch region add` create
`<cell>-private-routes` empty when it is missing and attach it to the private
subnet, but never change its rules; `region apply <label> network` alone
writes them.

## Reconcile loop

`ts-orch node` runs one loop per region (`fleet.Reconciler`, run by
`ociresource.Runner`). Every minute, on the region's SwarmKit Raft leader only,
it starts each kind listed in the region's `reconcile` field of
`deploy/fleet/fleet.json` (production: `network`, `nlb` and `nodes`, and the global
`dns` pass on gru, the DNS region; the document rejects `dns` anywhere else). The kinds run side
by side; a kind whose pass from an earlier tick is still running is not
started again. The CLI's `region apply <label> <kind>...` is unchanged and runs
any registered kind once.

- **Plan, then apply exactly that plan.** Each kind first runs as a plan: it
  reads OCI and prints one line per logical change (a created resource, one
  NSG rule, one route, one backend set) while every OCI write is refused
  (`ociresource.ErrPlanWrites`). An empty plan ends the kind's tick with no
  write. Otherwise the kind runs again with writes allowed, and announces
  each change before its write; a change that is not a still-unused line of
  the checked plan ends the pass before that write (`ErrUnplanned`,
  `replanning: OCI changed since the plan`) and the next tick plans again.
  So a pass never writes a change its checked plan did not hold.
  A resource created in a tick ends that branch for the tick: what depends on
  its new ID (the NAT gateway's route, a new NSG's rules, a new route table's
  routes and subnet, a new zone's records and attachments, the steering
  policies of a new monitor) is planned on the next tick. `compute` has no
  plan mode yet, so its plan fails at its first write and it cannot join a
  `reconcile` list until it gets one (C17). `nodes` plans at most one line
  per tick (grow the pool, cordon a node, remove a drained one, or retire an owned instance left outside the pool and the swarm); its
  SwarmKit writes (cordon, node removal) pass the same fence first
  (`ociclient.Authorize`). A grown node waits for its data volume until
  `compute` runs, so a region that scales needs `compute` in its list too.
- **Fence.** Each tick reads the leader's Raft term and checks through the
  SwarmKit control API that this node leads it. Every OCI write is checked
  again at the final dispatch, after the request is signed and after any
  instance-principal credential refresh (`ociclient.WithAuthority`, checked
  in the client's dispatcher): the term and leader must still be the ones the
  tick started with. After a leadership change the deposed leader's next
  write fails with `OCI resource mutation authority was fenced` and the new
  leader runs the kind from its next tick.
- **Change limit.** A plan may hold at most 16 logical changes
  (`ociresource.MaxChangesPerTick`). Building a kind's part of a region from
  nothing is the most it ever legitimately plans in one tick: at most 10 for
  `network` (second tick: the node NSG's 8 rules and ownership tag, and the
  route table), 7 for
  `nlb` (balancer, 3 backend sets, 3 listeners) and 8 for `dns` at 3 regions
  (5 steering policies and one A record per region). A steady state plans
  none and a hand-made drift a few. A larger plan writes nothing: the kind
  stops on that leader until ts-orch restarts there (a release or a leader
  change), the plan is logged with the error, and
  `ts_orch_oci_reconcile_stopped` raises the `OCIReconcileStopped` alert.
- **Throttling and outages.** The loop's OCI client does not retry. A 429 or
  5xx ends that kind's pass, is counted as an error and logged as
  `backed off until the next tick`; the other kinds keep running.
- **Invalid document or no credentials.** The leader builds its passes on its
  first tick and again on every tick until that succeeds. A document that does
  not load or validate, has no entry for the node's region, or an instance
  principal that cannot be fetched yet starts no pass that tick;
  `ts-orch status` shows the error.
- **Visibility.** One `OCI change` log line per change, none for unchanged
  resources. On port 9108, per region and kind:
  `ts_orch_oci_reconcile_last_run_timestamp_seconds`,
  `ts_orch_oci_reconcile_last_success_timestamp_seconds`,
  `ts_orch_oci_reconcile_duration_seconds`,
  `ts_orch_oci_reconcile_changes_total`, `ts_orch_oci_reconcile_errors_total`
  and `ts_orch_oci_reconcile_stopped`, plus `ts_orch_oci_reconcile_leader` per
  region. `ts-orch status` and `ts-orch region status`, run on a node, print
  each region leader's last result per kind.

## Self-heal

The region leader runs self-heal (`internal/selfheal`) on every reconcile loop
tick, beside the kinds, fenced by the same Raft term. It replaces a node that
stays unhealthy, one node at a time per region.

- **Unhealthy.** SwarmKit reports the node down, disconnected or unknown, or
  its manager unreachable; its document-made OCI instance (`instance/node`,
  matched by display name and hostname) is not `RUNNING`; or its own node checks
  (mesh and edge readiness, not the services it serves, read over
  `ts.mesh.pull.<region>.<node>` with twice the 5 s health budget) fail or do
  not answer. A node created, launched or rebooted less than 10 minutes ago is
  booting and never counts.
- **Grace: 5 minutes, continuous.** SwarmKit marks a node down after 3 missed
  5 s heartbeats, a release restart and its readiness wait take at most
  3 minutes, and the loop ticks every minute. Any healthy observation resets
  the clock, so a flapping node never triggers a repair. A new leader starts
  the clock again.
- **Repair.** A node whose instance is running gets one OCI `RESET`, then
  10 minutes to come back. The reset's send time is saved after OCI accepts
  it; a reboot step without one (a throttled call, a leader that died) sends
  it again. If it is still unhealthy, or its instance was not
  running, it is replaced: drained, demoted if it is a manager, removed from
  the swarm (`swarmruntime.RemoveMember`, the path `ts-orch member leave` and
  the node autoscaler share), and its instance is terminated with
  `preserveDataVolumesCreatedAtLaunch=true`. The pool launches a new instance,
  the compute pass attaches the kept data volume of that availability domain
  to it (the C8 rule, whether or not the data has another replica), and the
  node joins by itself.
- **Only document-made nodes.** Every reset, removal and terminate first
  checks that `compute` is reconciled, that self-heal is not stopped, and that
  the repair's instance is a document-made `instance/node` of this region's
  compartment, listed this tick, whose name is the node's hostname.
- **Durable.** The repair in flight, the last repair, the last replacement time
  and a stop live in the JetStream key-value bucket `TS_ORCH_SELF_HEAL`, one key
  per region, written before each action with a revision check. A new leader
  continues the step it reads. The bucket is in the TERRABASE fabric account,
  and TerraBase's own credential is denied every subject of it
  (`orchOnlyBuckets` in `internal/natscell/mesh/fabric.go`).
- **Refusals**, each logged as `self-heal refused to repair a node` and counted
  in `ts_orch_self_heal_refusals_total{reason}`:

  | Reason | When |
  | --- | --- |
  | `compute-not-reconciled` | `compute` is not in the region's `reconcile` list (every production region until C17). |
  | `stopped` | A replacement did not join; see below. |
  | `several-unhealthy` | More than one node is unhealthy at once: a region or network problem. `SelfHealRefused` fires. |
  | `scaling` | The node scaler (C12) is draining another node to remove it; the scaler likewise changes no node while one is unhealthy. |
  | `not-a-pool-node` | No document-made instance carries the node's name, so hand-made hosts are never touched. |
  | `leader` | The unhealthy node is the Raft leader itself. |
  | `quorum` | Demoting the manager would lose the Raft majority, or a role change is pending. |
  | `last-copy` | The node runs a stateful task whose service has no running task on another healthy node. |
  | `budget` | A replacement already happened in this region in the last 24 hours. |

- **A replacement that does not join.** If no new node joins and turns healthy
  within 30 minutes of the terminate, self-heal stops for the region:
  `ts_orch_self_heal_stopped` raises `SelfHealStopped`, and no other instance
  is touched. It resumes by itself once the region is back to its size with
  every node healthy, which means a person fixed it.
- **Visibility.** One `self-heal repair` log line per step and result, and
  `ts_orch_self_heal_repairs_total{step,result}`,
  `ts_orch_self_heal_unhealthy_nodes` on port 9108. `ts-orch status` and
  `ts-orch region status` print each leader's self-heal line: healthy, booting
  and unhealthy nodes, what it would refuse, the repair in flight and the last
  repair.
- **IAM.** Reboot is `INSTANCE_POWER_ACTIONS` and terminate `INSTANCE_DELETE`,
  both already in the statements below.

## Reconciler IAM policy

The ts-orch hosts call OCI with their instance principal (dynamic group
`ts-orch-hosts`, every instance in `gru-1-control`, `sjc-1-control` and
`fra-1-control`). Policy `ts-orch-reconciler` in compartment `TerraScale`
(`ocid1.policy.oc1..aaaaaaaahiqdf3yvddxxi52hqmhai4ep5dywq4dl45bqhs2p252ziikwhnkq`,
created 2026-11-16) grants exactly what the regional reconciler owns. Nothing is
granted in the tenancy root or in any other compartment, and there are no IAM,
bucket, backup or Vault grants beyond the separate `ts-orch-hosts-vault` policy.
Registry reads are the separate `ts-orch-hosts-ocir` policy ([OCIR](ocir.md)).

| Statement (per control compartment) | Why |
|---|---|
| `manage virtual-network-family` limited to VCN, subnet, NAT gateway, route table and NSG permissions, plus `READ`/`ATTACH`/`DETACH` on security lists and DHCP options | Create, update and prune the VCN, subnets, NAT gateway, route tables and NSGs. Subnet create/delete needs the security-list and DHCP attach/detach permissions; their create, update and delete are not granted. Internet, service and DRG gateway create, update and delete are not granted. |
| `manage virtual-network-family` limited to VNIC, private-IP and public-IP permissions | Instance launch and terminate create and delete VNICs; network load balancers use private IPs; reserved public IPs are created, assigned, moved between private IPs and released. |
| `manage instance-family` limited to instance and image read permissions | Launch, update, power-cycle and terminate instances, attach and detach volumes. No console connections, custom images, agent commands or compartment moves. |
| `manage compute-management-family` limited to instance-configuration and instance-pool permissions | Instance configurations and pools. No cluster networks or compartment moves. |
| `use volumes` | Read, update and attach boot and block volumes. `VOLUME_DELETE` (also used by `DeleteBootVolume`) and `VOLUME_MOVE` are not in the `use` verb. |
| `manage virtual-network-family` limited to `INTERNET_GATEWAY_READ`, `SERVICE_GATEWAY_READ` and `SERVICE_GATEWAY_ATTACH` | The network pass lists the VCN's internet and service gateways to adopt them, and restores the private route table's Oracle-services route through the service gateway. No gateway is created, updated or deleted. Added 2026-11-16 (C28). |
| `manage volumes where request.permission = 'VOLUME_CREATE'` | Create data volumes; the only `manage` permission granted on volumes. |
| `manage volume-attachments` | Attach and detach volumes. Detaching never deletes data. |
| `manage network-load-balancers` | Network load balancers, listeners, backend sets and backends. |

| Statement (gru-1-control only) | Why |
|---|---|
| `manage dns-zones` for `edge.terrascale.tech`, plus `DNS_ZONE_INSPECT` and `DNS_ZONE_CREATE` | List zones and create the edge zone; update and delete only that zone. |
| `manage dns-records` for `edge.terrascale.tech` | Records of the edge zone only. |
| `manage dns-steering-policies` | The traffic-management steering policy. |
| `read dns-steering-policy-attachments` | Attachment create and delete are covered by `use` on the zone plus `read` on the policy; this adds get and list. |
| `manage health-check-monitor` | HTTP(S) monitors the steering policy reads. |
| `inspect health-check-results` | Monitor results. |

No statement is conditioned on the `terrascale-managed-by` tag. OCI policy
conditions read only defined tags (`target.resource.tag.<namespace>.<key>`), and
the ownership tags are freeform. Even with a defined tag, create and list
requests have no target resource to test. Ownership stays enforced by the
reconciler, which never changes resources without its tags. The instance shape
(`VM.Standard.A1.Flex`) cannot be conditioned either; OCI exposes no shape variable.

Two OCI behaviours the policy cannot block, so the reconciler must handle them:
`TerminateInstance` and `TerminateInstancePool` delete the boot volume, and any
data volume created at launch through `launchVolumeAttachments`, without
`VOLUME_DELETE`. Data volumes must be created with `CreateVolume` and attached
with `AttachVolume`, never at launch, and terminations must pass
`preserveDataVolumesCreatedAtLaunch=true`.

Staging has its own dynamic group and policy, both named `ts-orch-stg`,
written by `ts-orch region bootstrap`: the per-compartment statements below for
`stg-1-control` only, plus Vault statements limited to `stg-vault` and
`stg-key` and `read repos` in `stg-1-control` ([OCIR](ocir.md)). Neither production group nor policy names staging, and staging's
names no production compartment
([region bootstrap](region-bootstrap.md#staging-region)).

### Statements

Read back from the live policy on 2026-11-16 after the C28 change (33 statements):

```text
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment gru-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment gru-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment gru-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment gru-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment gru-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment sjc-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment sjc-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment sjc-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment sjc-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment sjc-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment fra-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment fra-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment fra-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment fra-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment fra-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage dns-zones in compartment gru-1-control where any {request.permission = 'DNS_ZONE_INSPECT', request.permission = 'DNS_ZONE_CREATE', target.dns-zone.name = 'edge.terrascale.tech'}
Allow dynamic-group ts-orch-hosts to manage dns-records in compartment gru-1-control where target.dns-zone.name = 'edge.terrascale.tech'
Allow dynamic-group ts-orch-hosts to manage dns-steering-policies in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to read dns-steering-policy-attachments in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage health-check-monitor in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to inspect health-check-results in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment gru-1-control where any {request.permission = 'INTERNET_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_ATTACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment sjc-1-control where any {request.permission = 'INTERNET_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_ATTACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment fra-1-control where any {request.permission = 'INTERNET_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_READ', request.permission = 'SERVICE_GATEWAY_ATTACH'}
```

Before the C28 change (30 statements; C28 appended the last three above, one per control compartment):

<details><summary>Statements before 2026-11-16 C28</summary>

```text
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment gru-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment gru-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment gru-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment gru-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment gru-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment sjc-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment sjc-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment sjc-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment sjc-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment sjc-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment fra-1-control where any {request.permission = 'VCN_READ', request.permission = 'VCN_CREATE', request.permission = 'VCN_UPDATE', request.permission = 'VCN_DELETE', request.permission = 'VCN_ATTACH', request.permission = 'VCN_DETACH', request.permission = 'SUBNET_READ', request.permission = 'SUBNET_CREATE', request.permission = 'SUBNET_UPDATE', request.permission = 'SUBNET_DELETE', request.permission = 'SUBNET_ATTACH', request.permission = 'SUBNET_DETACH', request.permission = 'NAT_GATEWAY_READ', request.permission = 'NAT_GATEWAY_CREATE', request.permission = 'NAT_GATEWAY_UPDATE', request.permission = 'NAT_GATEWAY_DELETE', request.permission = 'NAT_GATEWAY_ATTACH', request.permission = 'NAT_GATEWAY_DETACH', request.permission = 'ROUTE_TABLE_READ', request.permission = 'ROUTE_TABLE_CREATE', request.permission = 'ROUTE_TABLE_UPDATE', request.permission = 'ROUTE_TABLE_DELETE', request.permission = 'ROUTE_TABLE_ATTACH', request.permission = 'ROUTE_TABLE_DETACH', request.permission = 'NETWORK_SECURITY_GROUP_INSPECT', request.permission = 'NETWORK_SECURITY_GROUP_READ', request.permission = 'NETWORK_SECURITY_GROUP_CREATE', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE', request.permission = 'NETWORK_SECURITY_GROUP_DELETE', request.permission = 'NETWORK_SECURITY_GROUP_LIST_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_SECURITY_RULES', request.permission = 'NETWORK_SECURITY_GROUP_LIST_MEMBERS', request.permission = 'NETWORK_SECURITY_GROUP_UPDATE_MEMBERS', request.permission = 'SECURITY_LIST_READ', request.permission = 'SECURITY_LIST_ATTACH', request.permission = 'SECURITY_LIST_DETACH', request.permission = 'DHCP_READ', request.permission = 'DHCP_ATTACH', request.permission = 'DHCP_DETACH'}
Allow dynamic-group ts-orch-hosts to manage virtual-network-family in compartment fra-1-control where any {request.permission = 'VNIC_READ', request.permission = 'VNIC_CREATE', request.permission = 'VNIC_UPDATE', request.permission = 'VNIC_DELETE', request.permission = 'VNIC_ATTACH', request.permission = 'VNIC_DETACH', request.permission = 'VNIC_ATTACHMENT_READ', request.permission = 'VNIC_ASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_DISASSOCIATE_NETWORK_SECURITY_GROUP', request.permission = 'VNIC_ASSIGN', request.permission = 'VNIC_UNASSIGN', request.permission = 'PRIVATE_IP_READ', request.permission = 'PRIVATE_IP_CREATE', request.permission = 'PRIVATE_IP_UPDATE', request.permission = 'PRIVATE_IP_DELETE', request.permission = 'PRIVATE_IP_ASSIGN', request.permission = 'PRIVATE_IP_UNASSIGN', request.permission = 'PRIVATE_IP_ASSIGN_PUBLIC_IP', request.permission = 'PRIVATE_IP_UNASSIGN_PUBLIC_IP', request.permission = 'PUBLIC_IP_READ', request.permission = 'PUBLIC_IP_CREATE', request.permission = 'PUBLIC_IP_UPDATE', request.permission = 'PUBLIC_IP_DELETE', request.permission = 'PUBLIC_IP_ASSIGN_PRIVATE_IP', request.permission = 'PUBLIC_IP_UNASSIGN_PRIVATE_IP'}
Allow dynamic-group ts-orch-hosts to manage instance-family in compartment fra-1-control where any {request.permission = 'INSTANCE_INSPECT', request.permission = 'INSTANCE_READ', request.permission = 'INSTANCE_CREATE', request.permission = 'INSTANCE_UPDATE', request.permission = 'INSTANCE_POWER_ACTIONS', request.permission = 'INSTANCE_DELETE', request.permission = 'INSTANCE_ATTACH_VOLUME', request.permission = 'INSTANCE_DETACH_VOLUME', request.permission = 'INSTANCE_IMAGE_INSPECT', request.permission = 'INSTANCE_IMAGE_READ', request.permission = 'IMAGE_READ'}
Allow dynamic-group ts-orch-hosts to manage compute-management-family in compartment fra-1-control where any {request.permission = 'INSTANCE_CONFIGURATION_INSPECT', request.permission = 'INSTANCE_CONFIGURATION_READ', request.permission = 'INSTANCE_CONFIGURATION_CREATE', request.permission = 'INSTANCE_CONFIGURATION_UPDATE', request.permission = 'INSTANCE_CONFIGURATION_DELETE', request.permission = 'INSTANCE_CONFIGURATION_LAUNCH', request.permission = 'INSTANCE_POOL_INSPECT', request.permission = 'INSTANCE_POOL_READ', request.permission = 'INSTANCE_POOL_CREATE', request.permission = 'INSTANCE_POOL_UPDATE', request.permission = 'INSTANCE_POOL_DELETE', request.permission = 'INSTANCE_POOL_POWER_ACTIONS', request.permission = 'INSTANCE_POOL_INSTANCE_ATTACH', request.permission = 'INSTANCE_POOL_INSTANCE_DETACH'}
Allow dynamic-group ts-orch-hosts to use volumes in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage volumes in compartment fra-1-control where request.permission = 'VOLUME_CREATE'
Allow dynamic-group ts-orch-hosts to manage volume-attachments in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage network-load-balancers in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to manage dns-zones in compartment gru-1-control where any {request.permission = 'DNS_ZONE_INSPECT', request.permission = 'DNS_ZONE_CREATE', target.dns-zone.name = 'edge.terrascale.tech'}
Allow dynamic-group ts-orch-hosts to manage dns-records in compartment gru-1-control where target.dns-zone.name = 'edge.terrascale.tech'
Allow dynamic-group ts-orch-hosts to manage dns-steering-policies in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to read dns-steering-policy-attachments in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to manage health-check-monitor in compartment gru-1-control
Allow dynamic-group ts-orch-hosts to inspect health-check-results in compartment gru-1-control
```

</details>

### Verification (2026-11-16, from ts-gru-1 with the instance principal)

| Request | Result |
|---|---|
| List VCNs in gru-1-control, sjc-1-control, fra-1-control | 200 |
| List instance pools, network load balancers, DNS zones, HTTP monitors in gru-1-control | 200 |
| List VCNs in `ts-dev` and `ops`, list instances in `ts-dev` | 404 NotAuthorizedOrNotFound |
| List DNS zones in sjc-1-control, volume backups and IAM policies in gru-1-control | 404 NotAuthorizedOrNotFound |
| Update the gru-1-ctl-1 boot volume and gru-1-vcn with a wrong `If-Match` | 412 NoEtagMatch (authorized, nothing changed) |
| Delete the same boot volume with a wrong `If-Match` | 404 NotAuthorizedOrNotFound (refused before the etag check) |

OCI answers 404 NotAuthorizedOrNotFound for both a missing grant and a missing
resource. The boot-volume pair separates them: the same existing volume returns
412 for an allowed update and 404 for the delete.

### Rollback

```sh
oci iam policy delete --force \
  --policy-id ocid1.policy.oc1..aaaaaaaahiqdf3yvddxxi52hqmhai4ep5dywq4dl45bqhs2p252ziikwhnkq
```

Deleting the policy restores the state from before 2026-11-16. No existing policy
or dynamic group was changed.

## Fleet DNS pass

`ts-orch region apply gru dns` reconciles the global DNS resources in
`Fleet.DNSRegion()`; another region label refuses this pass. It reads the
embedded fleet document and discovers each region's reserved NLB address
by `<CELL>/public-ip/nlb`, never by display name or public DNS. A missing
or duplicate address stops the pass. `region plan` observes the same desired
state through the DNS and Health Checks APIs, without Resource Search lag.

| Resource | Key in the DNS compartment's cell | Desired state | Undo |
|---|---|---|---|
| Public primary zone | `dns-zone/zone` | The fleet zone; adopt only an unclaimed public primary zone with that exact DNS name, preserving its records | Remove delegation first; retain the zone if it contains any other owner's data. Delete a newly created, otherwise empty zone by its recorded OCID only. |
| Shared HTTP monitor | `http-monitor/edge` | Every fleet region's owned NLB reserved address, HTTP GET :80 at the fleet health path (`/readyz`), every 10 seconds with a 10-second timeout; OCI chooses vantage points | Restore the prior monitor body, or delete the recorded monitor OCID after removing references from policies. |
| Steering policy | `steering-policy/<first label>` | One policy for every fleet steered name; A answers for all regions, TTL 30, health filtering, continent priority, nearest other region, then remaining regions | Restore its prior body by OCID, or delete its attachment and then its policy by recorded OCID. |
| Steering attachment | `steering-attachment/<first label>` | The owned policy attached to the exact name in the owned zone; ownership follows the zone and policy OCIDs, since OCI attachments have no tags | Delete only the recorded attachment OCID after verifying its zone and owned policy. |
| Regional A record | `dns-record/<region label>` | `<label>.api.<zone>` to that region's NLB, TTL 30; an ownership TXT record at `_ts-orch.<name>` carries the key and last written address | Restore the saved A and ownership TXT together, or remove that exact pair under the zone-record ETag. |

The zone, monitor and policies carry `terrascale-managed-by=ts-orchestrator`,
`terrascale-owner=terrascale` and `terrascale-resource-key`. Discovery uses
these tags, not display names, and rejects duplicate keys. The sole adoption
exception uses the zone's immutable DNS name and refuses any prior claim.
Attachments are accepted only with the owned zone and policy OCIDs; an
existing A, AAAA or CNAME prevents attachment creation. An attachment of a
different policy is never replaced.

OCI accepts only one health-check monitor per steering policy. **An answer
whose address is absent from that monitor's targets is assumed healthy.**
Therefore all five policies share one owned monitor containing every NLB.
Adding a region expands the monitor before updating any policy. Removing a
region first removes its answers from every policy, then shrinks the monitor.
No fixed list of regions or vantage points is kept in the pass.

Continent assignments come from the document: GRU serves SA and AN, SJC
serves NA, OC and AS, FRA serves EU and AF. Within a continent's case,
the assigned region ranks first and the others rank by great-circle distance
from it. An unmatched location uses document order. The HEALTH rule removes
unhealthy answers while any healthy answer remains. OCI's steering rule
processing retains the previous nonempty answer set when a rule would remove
every answer; if all regions are unhealthy DNS still returns an NLB address,
rather than NXDOMAIN or an empty answer. DNS cannot guarantee service when
all regions are down.

Records have no OCI tags. The ownership TXT stores both the key and the last
written A value: a changed or extra A, AAAA or CNAME, a conflicting marker,
or missing proof prevents replacement. A zone-record PATCH changes only
specific owned A/TXT pairs and uses `If-Match`; it never replaces the zone's
record collection. Removed regions' owned pairs are removed with the same
proof. Unknown records remain untouched. Monitor, policy and zone updates
also require current ownership and their read ETag; unrelated tags survive.

Public delegation and cutover are separate from `region apply`. Follow
[the DNS cutover procedure](network/geodns.md); a successful apply does not
claim that TLS or application traffic is ready for public cutover.
