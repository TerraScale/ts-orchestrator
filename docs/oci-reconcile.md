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
| Health check | each backend set | HTTP :80 `/readyz`, 200, every 10 s, 5 s timeout, 1 retry. |
| Listeners `tcp-80`, `tcp-443`, `tcp-5432` | inside the NLB | TCP on the same port to the backend set of the same name. |

Every resource carries `terrascale-managed-by`, `terrascale-owner` and
`terrascale-resource-key`; a load balancer or address with other tags is never
used or changed. A backend is referenced by its private address only, so a
hand-made host is unchanged by joining. A second apply prints `ok` and changes
nothing. Backend set, listener and NSG drift is corrected in place; a different
subnet, address or source mode cannot be changed by OCI and is reported.

The edge answers `/readyz` over :80 for an address Host (what the NLB checker
sends: no SNI, no name) with its own readiness: 503 while draining or not
ready, 200 when ready. A draining node leaves rotation within about 15 s, inside
the edge's 20 s drain grace; existing connections finish on it. When every
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
| Scale-in | Only when the pool is above `nodes.max`: the newest owned node is detached from the pool (size decremented, not auto-terminated), soft-stopped, its data volume detached, then terminated with `preserveDataVolumesCreatedAtLaunch=true`. |
| Data volumes | A node with an attached owned data volume keeps it. Otherwise it gets the lowest kept volume in its availability domain, or a new one (at most `nodes.max`). The volume records the node in `terrascale-data-instance`; the node's metadata gets `terrascale-data-volume`, `terrascale-data-may-format` (true only for a volume never bound before) and `terrascale-data-uuid`, the filesystem UUID chosen at volume creation. |

No step deletes a data volume; `VOLUME_DELETE` is not granted. A node that
finds no bound volume within 20 minutes, or a volume that fails the
`internal/nodeinit` checks, stops its first boot and installs nothing. A node
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

## Reconciler IAM policy

The ts-orch hosts call OCI with their instance principal (dynamic group
`ts-orch-hosts`, every instance in `gru-1-control`, `sjc-1-control` and
`fra-1-control`). Policy `ts-orch-reconciler` in compartment `TerraScale`
(`ocid1.policy.oc1..aaaaaaaahiqdf3yvddxxi52hqmhai4ep5dywq4dl45bqhs2p252ziikwhnkq`,
created 2026-11-16) grants exactly what the regional reconciler owns. Nothing is
granted in the tenancy root or in any other compartment, and there are no IAM,
bucket, backup or Vault grants beyond the separate `ts-orch-hosts-vault` policy.

| Statement (per control compartment) | Why |
|---|---|
| `manage virtual-network-family` limited to VCN, subnet, NAT gateway, route table and NSG permissions, plus `READ`/`ATTACH`/`DETACH` on security lists and DHCP options | Create, update and prune the VCN, subnets, NAT gateway, route tables and NSGs. Subnet create/delete needs the security-list and DHCP attach/detach permissions; their create, update and delete are not granted. Internet, service and DRG gateways are not granted. |
| `manage virtual-network-family` limited to VNIC, private-IP and public-IP permissions | Instance launch and terminate create and delete VNICs; network load balancers use private IPs; reserved public IPs are created, assigned, moved between private IPs and released. |
| `manage instance-family` limited to instance and image read permissions | Launch, update, power-cycle and terminate instances, attach and detach volumes. No console connections, custom images, agent commands or compartment moves. |
| `manage compute-management-family` limited to instance-configuration and instance-pool permissions | Instance configurations and pools. No cluster networks or compartment moves. |
| `use volumes` | Read, update and attach boot and block volumes. `VOLUME_DELETE` (also used by `DeleteBootVolume`) and `VOLUME_MOVE` are not in the `use` verb. |
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

### Statements

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
