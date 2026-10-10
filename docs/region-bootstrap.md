# Manual regional bootstrap

This is legacy implementation and recovery inventory. The required
[operating contract](zero-configuration.md) automatically admits private NetBird
nodes, discovers every region and infers local identity. OCI Vault creates,
delivers and configures first-party production secrets; vendor keys are stored
once and picked up automatically. There are no regional enable steps.

**Current gap (TS-796):** foundation and first-controller bootstrap still require
explicit reviewed plans and material. The procedures recorded below do not
establish automatic production bootstrap and authorize no live operations.
Historical target/cost approvals do not carry forward to new resources.
Keep signed authority handoff, exact-ID ownership, cost/quality checks and
explicit approval for destructive recovery. Fakes belong only in test binaries.

## Supported scope and ownership

### Current GRU reset

The operator-requested testing reset removed the GRU controllers, workload
hosts, disks, images, buckets and every object version, networking, public
load balancer, bastion, IAM grants and workload storage identity. GRU NetBird
peers, setup keys, group, policies, network and DNS zone are also removed.
Forgejo, its storage and network, shared Email Delivery, and the NetBird
manager/routing peer remain available. The checked-in example now has no
operator gateway, enrollment secret/policy binding or cell LPG ID; recreate
those only from a newly reviewed live inventory.

OCI has accepted delayed deletion of all 502 cell secrets for
`2026-10-05T01:45:58.728Z` and the dedicated vault/key for
`2026-10-11T01:48:37.642Z`. The network and workload compartments are
deleted. The control compartment remains until that purge; the shared
TerraScale parent stays. The [2026-10-04 inventory](evidence/gru-teardown-20261004.md)
lists what remains and its reviewed teardown plan. Rerun
`ts-orch oci-region teardown --plan docs/evidence/gru-teardown-20261004-plan.json`
to print the diff, and add `--apply` only with the owner's approval: it deletes
the listed resources in dependency order, never touches one already deleting,
and deletes the control compartment only once everything else is gone.
Current cleanup state is in the
[HomeLab ts-ops runbook](https://git.terrascale.tech/mariogk/HomeLab/src/branch/main/fleet/hosts/ts-ops.md#netbird-operator-gateway).
COS relayed the user's 2026-10-04 decision: keep these purge dates, do not
run OCI `--apply` now, and wait for COS to request it after 2026-10-11.
The approved stale Cloudflare `gru.api.terrascale.tech` A record was deleted
and its absence verified; both email DKIM records remain. See the
[confirmed dry-run and DNS evidence](evidence/gru-teardown-dryrun-20261004.md).
The old OpenBao `/infra/netbird/servers-gru` entry stays unchanged, including
its two versions. Its old group/key IDs are invalid for enrollment; the
rebuild prepares a new local key and a fresh OCI secret without reading,
deleting or overwriting this entry.

### TS-470 rebuild preparation

TS-466 (#148), TS-467 (#147), and TS-468 (#146) are merged. The proposed rebuild uses
`deploy/oci-region/plan.json`, a new attempt owner `ts-470-gru-rebuild-2`,
three controllers `gru-1-ctl-1`..`3`, and two database hosts
`gru-1-db-1`..`2`. Keep the plan's two-member count; the three-member profile
in [TerraBase deployment](terrabase-deployment.md) is an example.

The new foundation uses `gru-1-control`, `gru-1-network`, and
`gru-1-workload`, distinct from the pending old `terrascale-control`.
Its [itemized create proposal](evidence/gru-rebuild-plan-20261004.md) names
every target, cost, dependency, and hold. Before any live create, present
that exact stage as `NEEDS CONFIRM` and wait for COS to relay approval.
The new compartment names allow foundation preparation while old purges
continue. Every resource ID remains unset until a confirmed create and
authenticated readback. NetBird requires an LPG in the shared ts-ops VCN
and additive route/NSG changes; these are explicitly proposed for separate
approval. Forgejo, the manager, shared storage and Email Delivery remain.

Use TS-467's C# release path after controllers are healthy. The bootstrap
attempt now provides its inputs: controller material carries the member CA
for every controller, `sign` renders `controller.workloads.terrabase` into
each signed controller config, `members` launches the two database hosts,
which enroll themselves with role `terrabase` and no managed Rust placement
binding, and `terrabase` verifies and rolls out the `terrabase-linux-arm64`
release. Follow the exact
[bring-up runbook](terrabase-deployment.md#gru-1-bring-up-runbook).
Pin the asset SHA-256 and source commit before requesting rollout approval.
The profile's peer list is:

```text
gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443
```

These are the supported commands, prepared here but not executed:

```sh
ts-orch terrabase member-ca --cell gru-1 --out /var/lib/terrascale-operator/terrabase-ca-gru-1
ts-orch operator hosts --config /var/lib/terrascale-operator/operator.json
ts-orch operator terrabase-release \
  --config /var/lib/terrascale-operator/operator.json \
  --binary "$WORK/terrabase-linux-arm64" --sha256 "$WORK/terrabase-linux-arm64.sha256" \
  --source-checkout "$WORK/terrabase" --commit "$COMMIT" \
  --environment canary --profile /var/lib/terrascale-operator/terrabase-gru-1-profile.json \
  --wait 10m
```

`WORK` and `COMMIT` come from the verified release workflow. Capture controller
health, both members' digest/status, static NetBird peer names, and ts-status
reachability in `docs/evidence`. The current C# runtime has no replication
implementation or readiness endpoint: a `running` report proves process
liveness only. TS-470's replication acceptance remains open until TerraBase
TS-464/TS-469 support it; do not report the rebuilt cell as replicating based
on this rollout gate alone.

`generate-controller-material`, the first-seed commands, and the preview
helper validate only the three mappings listed above. The checked-in
`deploy/oci-region/plan.json` remains populated for GRU, including its existing
ts-ops resources. Its [operator gateway](#operator-gateway-peering)
and NetBird enrollment use ts-ops at `10.250.10.155`, with all fresh LPG,
secret and IAM IDs deliberately unset until approved creation. For SFO or FRA,
copy it to a separate reviewed plan and fill
the cell, region, tenancy, availability domain, compartments, network, Vault,
key, buckets, IAM identities, host credential secret, resource inventory, and
cell-specific host profiles. Changing only `cell` and `region` is not enough.
The plan and signed genesis must agree on the cell, region, controller
endpoints, image, and launch profiles.
The preview plan currently accepts `VM.Standard.A1.Flex` for its host profiles;
the seed preflight binds controller A to the exact reviewed profile. Other
shapes are outside this procedure.

`render-host-enrollment-public` accepts reviewed material for all three mapped
cells. It derives the public bundle's cell, environment, region, and
controller/NATS endpoints from the material record; the CA comes from its
matching owner-only source and must match the digest in that record. Use a
separate reviewed plan and matching material for each cell; do not reuse the
GRU example for SFO or FRA. See the
[Managed host image](production-role-config.md#managed-host-image) section for
the renderer invocation and image binding. The bundle is public JSON pinned by
SHA-256 during the image build, not a signed envelope. The GRU/SFO
managed-enrollment integration uses local NATS and a fake OCI provider; it is
not live OCI or VM qualification, and rendering a bundle does not show that a
cell has been deployed.

| Resources or action | Owner in this flow |
| --- | --- |
| Regional foundation, bootstrap material, and first controller A | Runbook operator; assistant for the currently authorized GRU qualification, until explicit identity, authority, and inventory handoff |
| Controllers B and C in the admitted cell | `ts-orchestrator` founder after the handoff |
| ARM managed workload hosts, persistent volumes, enrollment, and workload deployment | `ts-orchestrator` through its reviewed runtime path after the required cell-specific enrollment bundle is available |
| Operator gateway peering: the LPG pair, the cell and ts-ops peering routes, and the gateway NSG rules | Runbook operator; `ts-orchestrator` never changes them |
| NetBird manager, routing peer and configuration | `ts-orchestrator` ([`deploy/netbird`](../deploy/netbird/README.md)) |
| Shared Email Delivery | `ts-infra` (four email resources) |

The handoff is a real ownership boundary. Do not launch B or C manually, run a
second resource manager against the same regional resources, or depend on a
`ts-infra` output or Terraform receipt to establish regional readiness. As of
`ts-infra` main commit `e347f13a313ebb2b9d0a0b631ba0aed56af65126`, its guarded
workflow manages only the four Email Delivery resources. The former regional
Terraform definitions and regional workflow were removed from that source.
The preceding state-only handoff removed 24 OCI resource addresses and one
local propagation marker from Terraform state without creating, changing, or
destroying OCI resources; this is ownership bookkeeping, not evidence of
regional resource health or a live controller. For the current GRU lane, the
assistant as runbook operator prepares the regional network, IAM, and bootstrap
inputs and starts controller A; after the
explicit identity, authority, and inventory handoff, `ts-orchestrator` forms
B/C and manages the ARM workload hosts and TerraBase deployment.

## Before creating resources

1. Select one of the three fixed cell-to-region mappings above. Start from a
   reviewed copy of `deploy/oci-region/plan.json`; for SFO or FRA, populate the
   complete mapped-cell plan and do not edit the shared GRU example in place.
   Identify the tenancy, compartments, availability domain, owner, resource
   namespace, and exact IDs. Preserve unrelated and existing resources.
2. Configure the OCI CLI `DEFAULT` profile for the selected tenancy and
   principal. The Python preview helper invokes `oci` without a profile
   argument, so live inventory and readback use that default profile. The Go
   commands below use `--oci-profile DEFAULT`; configure that SDK profile with
   the same identity and target region. The helper passes the plan's region to
   regional OCI commands and records ready subscriptions and live inventory.
   The preview, inventory, inspect-foundation, `import-image`, `public-api`
   and `dns` commands now reach OCI through the Go SDK inside `ts-orch`,
   reading the same `~/.oci/config` `DEFAULT` profile; the Python `oci` CLI is
   no longer required for them. `TS_OCI_BACKEND=auto` (default) serves every
   supported command in-binary and falls back to the CLI only for an
   unsupported one, `sdk` never runs the CLI, and `cli` restores the previous
   CLI behavior. `import-image` accepts a repeatable `--region` and imports
   the same verified QCOW2 into each catalog region in parallel.
3. Before creating the foundation, capture and review current inventory and a
   cost admission:

   ```sh
   ts-orch oci-region preview inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   ts-orch oci-region preview admit \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --out /ABSOLUTE/PATH/cost-admission.json
   ```

   These commands are read-only. The inventory covers subscribed regions and
   resources in the plan's scoped compartments, including existing buckets and
   retained resources used by the estimate. The estimate is not an OCI spending
   limit. Repeat inventory and admission after foundation creation; admission
   expires after 15 minutes.
4. Prepare an itemized estimate for all required compute, boot and data
   storage, networking, object storage, and retained resources. Include
   quantities and durations, verify free allowances, and keep the combined
   qualification and preview estimate within the combined **US$200/month**
   ceiling. Use a qualified plan and CLI revision whose configured limit and
   validator match this authority; never bypass admission or edit its receipt.
   This ceiling is not a hard spending control and does not replace the current
   GRU authorization or the runbook's remaining gates.
5. Review the foundation and security configuration against the signed cell
   plan. The controller dynamic group must match only instances in the
   controller compartment, for example:

   ```text
   ALL {instance.compartment.id = '<control-compartment-ocid>'}
   ```

   Review the controller's policy scopes against the signed plan:

   | Controller permission | Action and compartment scope |
   | --- | --- |
   | Instance and volume provisioning | `manage instance-family` and `manage volume-family` in the control and workload compartments |
   | VNIC and network configuration | `use virtual-network-family` in the network compartment |
   | Image lookup | `read instance-images` in the control compartment |
   | Controller material | `read secret-bundles` in the dedicated controller/Vault compartment |
   | Bootstrap ledger and encryption | Object Storage and KMS grants scoped to the exact configured buckets and keys |

   Managed workload hosts must not match the controller dynamic group. Give
   hosts a separate dynamic group that matches only the planned workload
   compartment. Select and record both the secret compartment OCID and exact
   `LiveS3Credential` secret OCID explicitly: the signed OCID/version reference
   does not provide the compartment needed to derive that IAM scope. Attach
   this policy to the selected secret compartment:

   ```text
   Allow dynamic-group <host-dynamic-group> to read secret-bundles in compartment id <secret-compartment-ocid> where target.secret.id = '<exact-secret-ocid>'
   ```

   Review attached and inherited policies to ensure hosts have no compute,
   volume, network, Object Storage, or KMS grants. The inspector checks the
   named host dynamic group and exact secret policy, but does not establish
   that no other policy grants access. These are required configuration checks,
   not evidence that OCI has granted or live-tested each permission. Image read
   permission alone does not authorize peer or workload provisioning.

   Also check Vault/KMS and Object Storage access, private routes,
   service-gateway routes, the operator gateway peering route and LPG pair,
   and network security rules against the signed plan.
   The source plan may pin these values, but do not claim an automated check
   for any field unless the frozen inspector actually checks it.
6. A stale inventory, expired admission, mismatched region or resource ID, or
   cost above the ceiling is a stop condition. The ceiling is an admission
   condition and remains a constraint on each resource action.

## Second region

SFO (`sfo-1`, `us-sanjose-1`, TS-640) is founded with the same tools as GRU.
The next region runs them all with one command, `ts-orch region create`
([new region](new-region.md)). What differs from GRU:

- **Plan.** `deploy/oci-region/sfo-1-plan.json`: three colocated nodes
  `ts-sfo-1`..`3` (controller, TerraBase member and ts-auth on each, no
  `member-*` hosts, `database_members` 0) in `10.252.0.0/25`, the load
  balancer's public subnet `10.252.0.128/26`, and `public_api.terrabase_members`
  naming the nodes. The controller NSG admits the TerraBase client port from
  the public subnet, as a colocated cell needs. `orchestrator_owner` stays
  null: the cell spec's `release_fence` names a role for `terrabase`,
  `terrabase-primary` and `ts-auth`, so the leader's edge reconciler (TS-632)
  owns their backends, not `oci_reconcile.public_lb`.
- **No operator gateway.** A local peering gateway only peers VCNs of one
  region, and ts-ops is in `sa-saopaulo-1`. The plan sets `operator_gateway`
  and `netbird` to null. The nodes enroll in NetBird through the cell's NAT
  gateway to the manager's public address (group `sfo-servers`, NetBird SSH
  only); operators reach NATS through an OCI Bastion port-forwarding session
  to each node's private address.
- **Cost.** Always Free covers A1 compute and block storage only in the home
  region. The native estimate bills another region's hosts in full and keeps
  Forgejo's share within the home allowance. The plan's Forgejo dimensions
  are an upper bound: TS-645 resizes it.
- **Attempt.** `ts-orch oci-region attempt` takes the cell and OCI region from
  the plan: identity, material, anchor, manifests, founder records, image
  import region and receipts, spec delegation and fleet config. Its
  `services` phase derives the cell's TerraBase and ts-auth profiles and
  host grants from the plan. TS-703 releases need `ts_auth_profile` and
  `ts_auth_service` set to the reviewed regional files after the scoped Vault
  publisher is provisioned; the plan cannot derive its IAM identity. See
  [the signing publisher](secrets.md#ts-703-signing-publisher). It installs
  the operator material of a cell other than GRU in
  `/var/lib/terrascale-operator-<cell>` (`-sfo`), never over GRU's.
- **Trust.** The cell uses the same root, release leaf, operator key and
  recipient signer as GRU, so one update delegation scoped to both cells
  covers CI auto-deploy.
- **Edge (TS-662).** `public-api cert` and `apply` built `sfo-1-api` like
  `gru-1-api`, including `terrabase-primary` and its Management route, plus
  `sfo.orch` for the Machines API. Vault's `gru-1-cloudflare-dns-edit-token`
  cannot read the zone's configuration rules, so the `dns` steps (the
  `ts-orch-sfo-1-api-ssl-strict` rule and the proxied records) were made with
  the `cf` CLI; see the [evidence](evidence/ts-662-sfo-public-edge-20261007.md).
- **Host setup.** The image's `host-setup` ran its baked binary, which
  refused `ts-sfo-N` names, so the nodes never enrolled. sfo-1's nodes got
  the self-update drop-in (`60-selfupdate.conf`) by hand before #283 made
  `selfupdate prepare` install it.
- **Fabric.** The NATS link to GRU (TS-562) needs `nats.embedded.interregion`
  in both regions' signed controller configs, and only a re-found changes a
  signed config today. sfo-1 runs as its own cell until an in-place path
  exists.

## Static names

Every cell server has one static name from `internal/naming`. A cell is
`<region>-<index>` (`gru-1`; every region runs cell 1 today). A node is
`ts-<region>-<n>` (`ts-gru-1`, `ts-sfo-2`), with no role in the name: every
node runs the colocated controller, TerraBase member and ts-auth (TS-609).
Its retained data volume is `<node>-data` (`ts-gru-1-data`).

Servers named before TS-609 keep their names until they are renamed, and
`naming.Validate` accepts both schemes: `<cell>-<role>-<n>` with role `ctl`
(controller), `db` (TerraBase member) or `gw` (gateway), and a member's data
volume `<member>-data` (`gru-1-db-1-data`). The GRU rebuild has
`gru-1-ctl-1`..`3` (`gru-1-db-1`..`2` were retired by TS-578); its public edge
is the OCI L7 Load Balancer `gru-1-api`. `naming.Validate` rejects any other
name, such as `gru-controller-a`, `controller-b`, a deployment- or
digest-derived name, or an unknown region. No cell server takes the `gw` role
yet. A region other than GRU is founded on node names: its controller slots
`controller-a`, `-b` and `-c` are `ts-sfo-1`..`3` for the seed launch, the
founder, NATS server and TLS names, NetBird peers and the public API
backends. GRU keeps `gru-1-ctl-1`..`3` until its servers are renamed (TS-632):
a controller refuses a NATS store of another server name. Node pools and the
cell autoscaler still generate the old names.

A host agent gives its TerraBase member the host's node as
`TERRABASE_NODE_NAME`, the member's name in `TERRABASE_PEERS`. The member no
longer takes the OS hostname, so renaming a host's OS does not change the
member's identity.

Signed controller slots map by letter: in GRU `controller-a`, `-b` and `-c`
are `ctl-1`, `-2` and `-3`; elsewhere they are the region's nodes 1, 2 and 3. Member seats map in placement order: the permanent
seat is `db-1` and elastic seat k is `db-(k+1)` (`elastic-gru` is
`gru-1-db-2`). GRU's fixed addresses are `10.251.0.11`–`.13` for
`gru-1-ctl-1`..`3` and `10.251.0.21`–`.22` for `gru-1-db-1`..`2`.

The name is the OCI display name of controller A (`ts-orch oci-region preview
seed-launch`), of the founder-launched B and C, of each managed member host
and of its retained data volume. It is also the controller's NATS server name
and TLS certificate common name, the NetBird peer name and the peer DNS name
(`gru-1-ctl-1.nb.ts.internal`); the cell zone record uses the role and number
(`ctl-1.gru.ts.internal`). The NATS cluster name and JetStream domain
stay the cell token (`gru`), which also names the cell's NATS subjects; the
zone `gru.ts.internal` and its role aliases `nats.gru.ts.internal` and
`terrabase.gru.ts.internal` keep their names. Preview inventory admission
recognises B and C as `gru-1-ctl-2` and `gru-1-ctl-3`, and `ts-orch
oci-region attempt` phase status lists the instances whose names start with
`gru-1-`.

Names never carry a release, deployment ID, date, generation or digest, so a
rollout, a new bootstrap attempt (a new deployment ID such as
`ts-preview-gru-20260929-r4`) or a host replacement keeps them. Release
identity lives in launch metadata and tags: the deployment ID in the
`terrascale-bootstrap-identity-v1` and controller manifest launch metadata and
in the `BootstrapCreateKey` tag. Managed hosts and volumes keep the
`terrascale-owner`, `terrascale-generation`, `terrascale-create-key` and
`terrascale-host-node` freeform tags.

The OCI fleet refuses to launch a host or create a volume whose name is not a
member name of its own cell, before any OCI call. Founder launch refuses a
slot other than `controller-<letter>`. A GRU TerraBase deployment plan must
put member i on the cell address of `gru-1-db-i`, so the OCI name (seat
order) and the NetBird name (address) are the same host. NetBird desired
state and every `netbird.json` reader, including the image builder, reject a
peer name outside the scheme.

These names do not follow the scheme:

- Host node IDs (`host-<hash>`). They identify one host incarnation in tags
  and `terrascale_host_node` metadata and are not display names.
- Image display names (`terrascale-arm64-<rev>-<sha>`), which are release
  artifacts.
- `orchestrator_owner` in `deploy/oci-region/plan.json`. It is the bootstrap
  attempt's deployment ID, which managed hosts carry in their
  `terrascale-owner` tag, so set it to the attempt's deployment ID in the
  reviewed plan for each attempt. The plan's foundation buckets are static
  (`gru-1-ledger`, `-head`, `-backup`, `-material`).
- Backup names, which stay per backup.

A cell hosts one TerraBase database's member pair: its members occupy the
cell's fixed member addresses, so a second database in a region needs a second
cell (`gru-2`).

GRU is rebuilt from scratch under these names (TS-470). Nothing renames or
adopts a server launched before this scheme. JetStream derives a server's Raft
node ID from its name, so a controller records its server name in its NATS
store and refuses to start on a store of another name, including a pre-scheme
store of `gru-controller-a`: such a cell must be rebuilt.

## Operator gateway peering

Operators reach the private cell through a NetBird routing peer on the ts-ops
host (Forgejo and NetBird; private IP `10.250.10.155` in `ts-ops-vcn`
`10.250.0.0/16`). The NetBird manager, routing peer and configuration are
documented in [`deploy/netbird/README.md`](../deploy/netbird/README.md). This runbook
owns the OCI peering and automatic server enrollment inputs: one local peering
gateway (LPG) in each VCN, one route in each VCN's subnet route table, and the
gateway rules in the cell NSGs. The routing peer masquerades, so every operator
packet reaches the cell from `10.250.10.155`. Controllers and workload hosts
also enroll as individual NetBird peers through their image's boot services.

| Cell NSG | Gateway access |
| --- | --- |
| Controller (`network_security_group`) | TCP 4222, the NATS mTLS bridge, and TCP 22, OpenSSH |
| Member workload (`workload_network_security_group`) | TCP 9465, the TerraBase client API, and TCP 22, OpenSSH |

The OCI Bastion endpoint (`10.251.0.18/32`) reaches TCP 22 through the same two
NSGs.

The gateway never reaches 8443: host enrollment accepts only the enrolling
instance's own private IP. Servers initiate NetBird management, signal and
WebSocket relay connections to the gateway `/32` on TCP 443, plus STUN on UDP
3478. These two stateful egress rules and matching ts-ops NSG ingress from
the private subnet are required. Responses use the stateful rules. The private
subnet keeps no internet route, NAT gateway, or public IP. The cell's only internet gateway serves the
[public TerraBase API](#public-terrabase-api) subnet. The OCI Bastion and `operator --nats-forward` remain the break-glass
path. LPGs have no separate charge, and the NetBird server adds no OCI resource
to the cost admission.

`ts-orch oci-region preview` enforces this boundary. In the plan, `operator_gateway` must be a
private address inside its own VCN that does not overlap the cell. Every NSG
and security-list ingress source must be inside the cell or exactly the gateway
`/32` on the ports above, and a source that overlaps the public API subnet must
be exactly that subnet on the member client port. Egress may reach only the
cell, NTP, Oracle services, and the gateway `/32` on TCP 443 and UDP 3478; both
NetBird rules must be present. The private route table must hold only the
service-gateway route and the `10.250.10.155/32` peering route. Inventory
admits only ts-ops's internet gateway, the recorded public API gateway and
network load balancer, and the recorded LPG pair. `inspect-foundation`
reads back both LPGs (`PEERED`, each other's peer, no LPG route table, exact
advertised CIDRs), the member workload NSG, and the gateway VNIC (one primary
VNIC at `10.250.10.155` with source/destination checks enabled). It discovers
the gateway's attached NSGs and requires explicit stateful HTTPS and STUN
ingress from the planned private subnet, while preserving ts-ops's unrelated
public and owner-access rules.

### Automatic server enrollment

The qualified image installs the pinned NetBird client, `netbird.service`, and
`terrascale-netbird-enroll.service` alongside the orchestrator binary. The
enrollment service runs as root at boot and retries failures. It reads the
public `/etc/terrascale-orchestrator/netbird.json` configuration, fetches the
server setup key from OCI Vault through its instance principal, and runs the
orchestrator's `netbird-enroll` command. Controllers A/B/C and managed hosts use
the same image; their existing role installation and signed host enrollment
remain automatic. NetBird enrollment does not depend on a controller becoming
healthy first.

Set `plan.netbird.management_url` to `https://netbird.terrascale.tech` and
`management_ip` to the ts-ops private gateway address. The enrollment command
maintains an `/etc/hosts` entry for that hostname and address, so TLS keeps the
public certificate name while traffic follows the private LPG route. Public
DNS resolves the same hostname to ts-ops's public address for operator
devices. The manager's signal and WebSocket relay endpoints must use that
same hostname on 443; STUN uses 3478. Existing within-cell egress already
permits direct peer traffic. Keep the server setup key restricted to the
`gru-servers` group; `ts-orch netbird sync` reconciles the operator access
policies.

Enrollment is tuned for a fast boot. `netbird.service` is `Type=simple`, so
`netbird-enroll` waits up to 15 s for the daemon's control socket rather than
failing, and it retries transient Vault errors (transport, 429, 5xx) with
jittered backoff inside one 15 s deadline. The enrollment unit starts after
`systemd-time-wait-sync.service`, because instance-principal federation,
Vault and the manager's TLS need a synced clock, and it restarts after 5 s
when enrollment still fails. NetBird 0.79 does not dial any manager for a
just-created configuration, so the first boot never contacts the default
NetBird manager: enrollment pins the hosts entry, then runs a single
`netbird up` with the setup key and skips the `down` that only an active
client needs. On reboot, a daemon already reconnecting its saved identity is
awaited instead of receiving a second `up`. Status checks back off from
100 ms to 1 s.

Cell servers reach NetBird only through the gateway `/32` and have no
internet route, so ICE between a server and an operator device or the
routing peer can never succeed. `netbird.service` therefore sets
`NB_FORCE_RELAY=true`, which skips the ICE listener and goes straight to the
manager's relay, and `NB_LAZY_CONN=on`, which opens a tunnel only when an
operator connects. Both are daemon environment variables in NetBird 0.79;
`netbird up --enable-lazy-connection` has had no effect since 0.74.1.

#### Traffic boundaries

Intra-region orchestrator traffic never uses NetBird. NATS client and route
connections, host enrollment and TerraBase replication use OCI VCN private
IPv4 addresses inside the cell; TerraBase replication endpoints come from
the members' VCN seats and must be private IPv4 addresses. NetBird peers use
`10.200.0.0/16`, which is private too, so that check does not exclude a
NetBird address. No
orchestrator unit orders after or requires a NetBird unit, so the cell forms
and heals without the manager. NetBird is the operator access and
cross-region management overlay only: operators reach private IPs through
the ts-ops routing peer, and per-server peers exist for NetBird SSH.
Enrollment keeps NetBird DNS and client and server routes disabled. Future
cross-region orchestrator traffic (NATS gateways or leaf nodes) should use OCI
private peering with the existing route mTLS, not NetBird.

Record `secret_compartment_id`, `setup_key_secret_id`, `policy_id`, and
`policy_name` in `plan.netbird`; foundation inspection requires every one. The
checked-in plan records the selected server-enrollment secret and policy.
Keep the key value in Vault. The image and launch metadata contain only
the manager address and secret reference. Install a separate IAM policy in the
selected secret compartment with exactly these two statements, in this order:

```text
Allow dynamic-group <controller-dynamic-group> to read secret-bundles in compartment id <netbird-secret-compartment-ocid> where target.secret.id = '<netbird-setup-key-secret-ocid>'
Allow dynamic-group <host-dynamic-group> to read secret-bundles in compartment id <netbird-secret-compartment-ocid> where target.secret.id = '<netbird-setup-key-secret-ocid>'
```

`inspect-foundation` checks this policy and the active secret's compartment
without reading secret contents. Preserve the host's separate exact
`LiveS3Credential` policy. Update the Vault value when rotating the manager's
server setup key so subsequent server enrollment remains available.

For GRU, set `setup_key_secret_id` in the checked-in
`deploy/image/inputs/netbird-gru.json` to the plan's value and keep its
`peer_names`, which a test checks against the `ts-orch netbird` desired state
(see [Fresh cell enrollment](../deploy/netbird/README.md#automatic-cell-admission)).
Another region's servers enroll in its `<cell>-servers` group, which the
desired state derives from the catalog. Generate its input from the reviewed
plan and the Vault secret holding the region's server setup key; its peer
names are the plan hosts' node names
(see [new region NetBird](../deploy/netbird/README.md#names)):

```sh
ts-orch netbird image-input --plan "$PLAN" --setup-key-secret-id "$SECRET_OCID" \
  --out deploy/image/inputs/netbird-<cell>.json
```

Pin this file's digest in the image inputs and supply it to the image builder.
After each new controller or host starts, verify `systemctl is-active
netbird.service terrascale-netbird-enroll.service` and `netbird status --json`:
management and signal must be connected to the configured manager. Match its
peer entry in the manager to the server's instance identity. Reboot one server
and confirm that its existing peer identity reconnects.

### Operator SSH and internal tools

Every controller and managed host serves two independent SSH paths, so one can
debug a server whose other path is broken:

- **NetBird SSH** on the server's NetBird address. A session requires the
  operator's NetBird identity provider login (JWT) and a manager policy.
- **OpenSSH** on the server's private IP, through the routing peer or the OCI
  Bastion. The image keeps Noble's `ssh.socket` enabled and the image build
  fails without it. The operator's Ed25519 key (`owner_ssh_public_key` in the
  attempt configuration) travels in OCI's standard `ssh_authorized_keys` launch
  metadata: `ts-orch oci-region preview seed-launch` sets it on controller A, which forwards it
  with its other launch material to controllers B and C and to every managed
  host. cloud-init authorizes it for the `ubuntu` user (passwordless `sudo`);
  password login stays off.

For NetBird SSH, enrollment enables root login, SFTP and local port
forwarding, and keeps remote port forwarding and unauthenticated machine access
off. It re-applies these settings whenever a server's effective NetBird
configuration differs. `netbird.service` therefore runs unconfined, like
`ssh.service`, and the server clock must stay in sync for JWT validation (the
image's timesyncd configuration provides this).

Peer traffic to a server's NetBird address is filtered by that server's NetBird
firewall, independently of the OCI NSGs, and the manager denies it unless a
policy allows it. The server setup key auto-assigns `gru-servers`; the
`netbird-ssh` policy targeting that group also makes the manager enable each
server's SSH server. ts-orchestrator owns these policies (see
[`deploy/netbird/README.md`](../deploy/netbird/README.md)):

| Policy | Protocol and ports |
| --- | --- |
| `operators-to-gru-servers-ssh` | `netbird-ssh` (port 22 is redirected to the SSH server's 22022) |
| `ops-automation-to-gru-servers-ssh` | `netbird-ssh`, for the [operator automation peer](../deploy/netbird/README.md#operator-automation-peer) |
| `operators-to-gru-cell-ops-ports` | TCP 22, 4222 (controllers), 9465 (members), routed through ts-ops |

Do not allow 6222 or 8443 to operators. Servers enroll under their
[static names](#static-names) (`gru-1-ctl-1`..`3`, `gru-1-db-1`..`2`) in
`nb.ts.internal`, and operators resolve stable cell names in `gru.ts.internal`.
From an enrolled operator device:

```sh
netbird ssh root@gru-1-ctl-1.nb.ts.internal
netbird ssh -L 8080:127.0.0.1:8080 root@gru-1-ctl-1.nb.ts.internal   # loopback-only tool
```

Agents and scripts use `ts-orch netbird ssh` on the
[operator automation peer](../deploy/netbird/README.md#operator-automation-peer)
instead: it completes the login without a browser and takes the same
arguments. Plain `ssh` to a NetBird name also uses NetBird SSH, through the NetBird
client's OpenSSH drop-in. For OpenSSH, dial the private address over the
routing peer:

```sh
ssh -i ~/.ssh/terrascale-owner ubuntu@ctl-1.gru.ts.internal
```

Controller A prints its host key to the serial console at first boot. For the
other servers, compare the host key on first connection with
`netbird ssh root@gru-1-db-1.nb.ts.internal ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
The OCI Bastion remains the break-glass path.

### Apply

Start from a reviewed plan copy that declares `operator_gateway` with null LPG
IDs. Set `NETWORK_COMPARTMENT`, `CELL_VCN`, `CELL_RT`, `CONTROL_NSG`,
`WORKLOAD_NSG`, and `CELL_SL` from that plan, and
`OPS_COMPARTMENT`, `OPS_VCN`, `OPS_RT`, and `OPS_NSG` from the
ts-ops resource manifest and primary VNIC.

1. Take a read-only snapshot. Save both route tables with their ETags and
   both cell NSGs, and confirm that no LPG exists and that the only internet
   gateways are ts-ops's and the public API's:

   ```sh
   oci network route-table get --rt-id "$CELL_RT" > cell-rt-before.json
   oci network route-table get --rt-id "$OPS_RT" > ops-rt-before.json
   oci network security-list get --security-list-id "$CELL_SL" > cell-sl-before.json
   for nsg in "$CONTROL_NSG" "$WORKLOAD_NSG" "$OPS_NSG"; do
     oci network nsg rules list --nsg-id "$nsg" --all > "nsg-rules-$nsg-before.json"
   done
   for compartment in "$NETWORK_COMPARTMENT" "$OPS_COMPARTMENT"; do
     oci network local-peering-gateway list --compartment-id "$compartment" --all
     oci network internet-gateway list --compartment-id "$compartment" --all
   done
   ```

   Then run `ts-orch oci-region preview inventory` and `admit` against the plan copy.
2. Create and connect the LPGs. Do not pass `--route-table-id`: an LPG route
   table would let the peering carry traffic for other networks.

   ```sh
   CELL_LPG=$(oci network local-peering-gateway create \
     --compartment-id "$NETWORK_COMPARTMENT" --vcn-id "$CELL_VCN" \
     --display-name terrascale-gru-netbird --wait-for-state AVAILABLE \
     --query data.id --raw-output)
   OPS_LPG=$(oci network local-peering-gateway create \
     --compartment-id "$OPS_COMPARTMENT" --vcn-id "$OPS_VCN" \
     --display-name ts-ops-netbird-gru --wait-for-state AVAILABLE \
     --query data.id --raw-output)
   oci network local-peering-gateway connect \
     --local-peering-gateway-id "$CELL_LPG" --peer-id "$OPS_LPG"
   ```

   Both LPGs must read back `peering-status` `PEERED`, with the other VCN's CIDR
   as `peer-advertised-cidr`.
3. Add the gateway NSG rules while no route reaches them yet. Narrow the
   controller rules from the whole VCN to the private subnet, so the public API
   subnet never reaches NATS or enrollment. Add the `/25` rules first, then
   remove every `/24` controller rule, including the unused 7422 and 8080:

   ```sh
   tcp_rule() {
     printf '[{"direction":"INGRESS","protocol":"6","source":"%s","sourceType":"CIDR_BLOCK","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":%s,"max":%s}}}]' "$1" "$2" "$2"
   }
   udp_rule() {
     printf '[{"direction":"INGRESS","protocol":"17","source":"%s","sourceType":"CIDR_BLOCK","isStateless":false,"udpOptions":{"destinationPortRange":{"min":%s,"max":%s}}}]' "$1" "$2" "$2"
   }
   oci network nsg rules add --nsg-id "$CONTROL_NSG" --security-rules "$(tcp_rule 10.250.10.155/32 4222)"
   oci network nsg rules add --nsg-id "$WORKLOAD_NSG" --security-rules "$(tcp_rule 10.250.10.155/32 9465)"
   for nsg in "$CONTROL_NSG" "$WORKLOAD_NSG"; do
     for source in 10.250.10.155/32 10.251.0.18/32; do
       oci network nsg rules add --nsg-id "$nsg" --security-rules "$(tcp_rule "$source" 22)"
     done
   done
   oci network nsg rules add --nsg-id "$OPS_NSG" --security-rules "$(tcp_rule 10.251.0.0/25 443)"
   oci network nsg rules add --nsg-id "$OPS_NSG" --security-rules "$(udp_rule 10.251.0.0/25 3478)"
   for port in 4222 6222 8443; do
     oci network nsg rules add --nsg-id "$CONTROL_NSG" --security-rules "$(tcp_rule 10.251.0.0/25 "$port")"
   done
   WIDE_RULE_IDS=$(oci network nsg rules list --nsg-id "$CONTROL_NSG" --all \
     --query "data[?source=='10.251.0.0/24'].id")
   oci network nsg rules remove --nsg-id "$CONTROL_NSG" --security-rule-ids "$WIDE_RULE_IDS"
   ```

   Prepare the cell security list's complete egress rule list from the saved
   readback. Add exactly two stateful rules with destination `10.250.10.155/32`:
   TCP 443 and UDP 3478. Preserve the existing cell, Oracle service, and NTP
   rules. Review the diff, use the saved security-list ETag with `--if-match`
   on `oci network security-list update`, and read back the result. The ts-ops
   host firewall must allow these same private-subnet destinations and retain
   the public NetBird listener rules.
4. Add the routes. `route-table update` replaces the whole rule list, so derive
   each list from the saved table, review the diff, and guard the write with
   the saved ETag. The ts-ops table must keep its default route to the
   internet gateway; losing it takes Forgejo and NetBird offline.

   ```sh
   route_rules() {
     jq --argjson extra "${2:-null}" '[.data["route-rules"][]
       | {destination, destinationType: .["destination-type"],
          networkEntityId: .["network-entity-id"], description}
       | with_entries(select(.value != null))] + (if $extra then [$extra] else [] end)' "$1"
   }
   route_rules cell-rt-before.json > cell-rt-restore.json
   route_rules ops-rt-before.json > ops-rt-restore.json
   route_rules cell-rt-before.json \
     "{\"destination\":\"10.250.10.155/32\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$CELL_LPG\"}" \
     > cell-rt-rules.json
   route_rules ops-rt-before.json \
     "{\"destination\":\"10.251.0.0/25\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$OPS_LPG\"}" \
     > ops-rt-rules.json
   diff cell-rt-restore.json cell-rt-rules.json
   diff ops-rt-restore.json ops-rt-rules.json
   oci network route-table update --rt-id "$CELL_RT" --route-rules file://cell-rt-rules.json \
     --if-match "$(jq -r .etag cell-rt-before.json)" --force
   oci network route-table update --rt-id "$OPS_RT" --route-rules file://ops-rt-rules.json \
     --if-match "$(jq -r .etag ops-rt-before.json)" --force
   ```

   Each diff must add exactly one rule. Right after the ts-ops update, confirm
   `curl -fsS https://git.terrascale.tech/api/v1/version` and Git SSH still
   work. If either fails, restore `ops-rt-restore.json` before anything
   else.
5. Record `CELL_LPG` as `resource_ids.local_peering_gateway` and `OPS_LPG`
   as `operator_gateway.local_peering_gateway_id` in the reviewed plan copy.
   Then run `inventory`, `admit`, and `inspect-foundation`; all three must pass.
6. From an enrolled NetBird operator device, check that TCP 4222 on the
   controllers, 22 on every controller and member, and 9465 on members
   connect, and that 8443 and 6222 do not. `operator ... --config FILE` then
   dials the controllers' private IPs directly, without `--nats-forward`. Then check that `netbird ssh`
   opens a root session on every controller and member over its NetBird
   address, that `ssh ubuntu@PRIVATE_IP` with the owner key opens one over the
   routing peer, and that a device outside the operators group is refused.

### Rollback

Remove access in reverse order, so that no route outlives its target:

1. Restore both route tables from `cell-rt-restore.json` and
   `ops-rt-restore.json`, using the same ETag-guarded
   `route-table update` with a fresh `get`.
2. Remove every NSG rule whose source is the gateway:

   ```sh
   for nsg in "$CONTROL_NSG" "$WORKLOAD_NSG"; do
     ids=$(oci network nsg rules list --nsg-id "$nsg" --all \
       --query "data[?source=='10.250.10.155/32'].id")
     oci network nsg rules remove --nsg-id "$nsg" --security-rule-ids "$ids"
   done
   ```
3. Delete both LPGs with `oci network local-peering-gateway delete
   --local-peering-gateway-id ID --force --wait-for-state TERMINATED`.
4. In a new reviewed plan copy, set `operator_gateway` to `null` and remove the
   gateway rules and the peering route. Then rerun `inventory`, `admit`, and
   `inspect-foundation`.

The controller rules stay narrowed to the private subnet, and the 7422 and 8080
rules are not restored; nothing listens on those ports.

## Public TerraBase API

The cell's public API is an OCI flexible load balancer behind proxied
Cloudflare DNS. `gru.api.terrascale.tech` reaches TerraBase and
`gru.auth.terrascale.tech` reaches ts-auth (TS-487): regional hosts follow
`<region>.<service>.terrascale.tech`, and ts-atlas fronts the global
`api.terrascale.tech` and `auth.terrascale.tech`. Names come from
`internal/naming`: load balancer `gru-1-api`, `gru-1-api-igw`,
`gru-1-api-routes`, `gru-1-api-security`, `gru-1-api-subnet`,
`gru-1-api-nsg`, and the Vault secret `gru-1-api-origin`.

The plan declares `public_api` as `subnet_cidr`, `listener_port`,
`client_port`, `min_mbps`, `max_mbps` (10 and 100 for gru-1) and
`terrabase_members`, and prices
the load balancer from `budget.rates.lb_hour` and `lb_mbps_hour` at its
bandwidth ceiling. A plan without the bandwidth keys describes the older TLS
passthrough network load balancer. `resource_ids.network_load_balancer`
records either balancer.

- Network: an internet gateway, a route table with `0.0.0.0/0` to it, the
  public subnet `10.251.0.128/26`, and a security list with no ingress whose
  egress is TCP 9465 and 8080 to the private subnet. The workload NSG admits
  TCP 9465 and the controller NSG admits TCP 8080 from the public subnet;
  both are plan rules (the 8080 rule with TS-487), and `apply` adds them if
  missing.
- Origin lock: `gru-1-api-nsg`, attached only to the load balancer, admits
  TCP 80 and 443 from each of Cloudflare's published IPv4 ranges and nothing
  else. Every HTTPS listener requires the customer-issued
  [zone origin-pull client certificate](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/)
  (Authenticated Origin Pulls), verified against the dedicated CA in
  `public_api.origin_pull`. Cloudflare's shared client CA is refused: it
  authenticates other Cloudflare accounts too.
- Listeners: two HTTPS listeners on 443 route by hostname and serve the
  Cloudflare Origin CA certificate. Port 80 answers with a 301 to HTTPS.
  Responses gain HSTS and `X-Content-Type-Options: nosniff`.
- Backend sets: `terrabase` sends HTTPS to the members at 9465, verified
  against the member CA, with `GET /readyz` health checks (TerraBase TS-483
  adds `/readyz`; until then the set reports unhealthy). The plan's
  `terrabase_members` seeds the set when `apply` creates the load
  balancer; it lists `gru-1-db-1` until TS-561 replicates the catalog.
  When the plan names `orchestrator_owner`, the controller's
  `oci_reconcile.public_lb` owns the set's backends afterwards (TS-571,
  [OCI reconcile](oci-reconcile.md)): `apply` stamps the controller's
  ownership of `GRU/lb-backends/public-terrabase`, still converges an
  existing load balancer's bandwidth, hostnames and ts-auth backends, but
  never rewrites the TerraBase ones. Without an owner, apply keeps the
  TerraBase backends equal to `terrabase_members`, and refuses, before any
  change, a load balancer that already carries ts-orchestrator ownership.
  `ts-auth` sends HTTP to
  every controller on 8080 with `GET /readyz`, so controllers without a
  replica drop out.
- Machines API (optional): with `public_api.orch: true` the load balancer
  also serves `<region>.orch.terrascale.tech` on a third HTTPS listener.
  Backend set `ts-orch` sends HTTPS to every controller at 8444, verified
  against the cell CA bundle `cell-ca` (`apply --cell-ca`, the controller
  material's `ca.pem`), with `GET /healthz` health checks. The controller NSG
  admits 8444 from the public subnet, the Origin CA certificate names the
  third host, and `dns` publishes it. The controllers serve the API once the
  cell spec carries `machines_api` ([Machines API](machines-api.md)).
- Timeouts: Cloudflare ends a proxied request after 100 seconds. The
  listeners' idle timeout is 120 seconds, so Cloudflare rather than the load
  balancer cuts a slow request. Keep long-polls, including shape long-polls,
  under 100 seconds.

Before provisioning, prepare one customer-owned zone AOP certificate using
Cloudflare's [zone-level setup](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/zone-level/).
Use a dedicated self-signed signing CA and a directly signed client leaf
with `CA:FALSE` and Client Authentication usage. Upload only the leaf and
its private key to the `terrascale.tech` zone. Store the CA private key and
the client leaf's private key with `ts-orch vault put` as
`gru-1-cloudflare-aop-ca-key` and `gru-1-cloudflare-aop-client-key` in the
operator-only `TerraScale` compartment ([secrets](secrets.md)), and nowhere
else. The complete zone certificate list
must contain exactly one active certificate. Add its public inputs to the
reviewed plan (never add either private key). With the logged-in `cf` CLI
(see [AGENTS.md](../AGENTS.md#cloudflare-use-the-cf-cli)), upload and list
the zone certificate with (`@file` keeps the key out of `ps`; delete the
temporary key file afterwards):

```sh
cf origin-tls-client-auth zone-certificates create -z terrascale.tech \
  --certificate @client-leaf.pem --private-key @client-leaf.key
cf origin-tls-client-auth zone-certificates list -z terrascale.tech
```

The plan entry:

```json
"origin_pull": {
  "ca_certificate": "-----BEGIN CERTIFICATE-----\n...dedicated CA PEM...\n-----END CERTIFICATE-----\n",
  "certificate_id": "<Cloudflare zone AOP certificate ID>"
}
```

A hostname-level origin pull association overrides zone AOP, so neither
target may have one. Check both:

```sh
cf origin-tls-client-auth hostnames get gru.api.terrascale.tech -z terrascale.tech
cf origin-tls-client-auth hostnames get gru.auth.terrascale.tech -z terrascale.tech
```

Each must answer `404` with error `1553` ("Auth origin pull setting for this
hostname not found"), which is how Cloudflare reports no association, or
succeed with an explicit `enabled: null`. Cloudflare cannot store a voided
association: `PUT .../hostnames` with `enabled: null` and no certificate
fails with `1404` (verified live 2026-10-05). `dns` accepts exactly those two
answers and refuses an enabled or disabled association, a foreign hostname,
and every other error. Remove an existing association by hand first.

Unbound plans can be previewed without these inputs; `cert`, `apply`, and
DNS security validation require them. Every cell uses the same reviewed
zone certificate. Each cell publishes only its own regional names,
`<region>.api.terrascale.tech` and `<region>.auth.terrascale.tech`. The global
`api.terrascale.tech` and `auth.terrascale.tech` are ts-atlas Worker routes
that forward to them; `dns` never touches them. Zone AOP also affects other origins
in this zone that request client certificates: coordinate their trust before
enabling it. The DNS command does not upload, replace, or delete AOP keys.

Run the steps in order. Each is idempotent; `cert`, `origin-ips` and `dns`
print their plan and change nothing without `--apply`:

```sh
export CF_API_TOKEN="$(oci secrets secret-bundle get-secret-bundle-by-name --vault-id "$VAULT" \
  --secret-name gru-1-cloudflare-dns-edit-token \
  --query 'data."secret-bundle-content".content' --raw-output | base64 -d)"
ts-orch oci-region public-api preview --plan deploy/oci-region/plan.json
ts-orch oci-region public-api cert --plan deploy/oci-region/plan.json
ts-orch oci-region public-api cert --plan deploy/oci-region/plan.json --apply
ts-orch oci-region public-api apply --plan deploy/oci-region/plan.json --member-ca member-ca.pem
ts-orch oci-region dns --plan deploy/oci-region/plan.json
ts-orch oci-region dns --plan deploy/oci-region/plan.json --apply
```

1. `preview` lists every resource, certificate, rule and record without any
   call.
2. `cert` generates an RSA key, has Cloudflare's Origin CA sign it for both
   names for 15 years, and stores the certificate and key in the Vault secret
   `gru-1-api-origin` (plan `vault`, `key` and `control_compartment`). When
   the load balancer already exists without the certificate, `cert` installs
   it. Reused Vault bundles must name both planned hostnames. The key never
   leaves Vault, the load balancer and `ts-orch`'s memory.
   When the stored certificate misses a planned name or expires within a
   year, `cert` issues a new one into a new version of the same secret,
   installs it on the load balancer as `origin-<hash>` and points every HTTPS
   listener at it, `ts-orch` included. The previous certificate stays
   installed, and its Origin CA certificate stays in Cloudflare, until an
   operator removes them. `apply`
   refuses to rename a hostname until the served certificate names it, then
   updates the hostname in place.
3. `apply` reads that secret, fetches Cloudflare's ranges, creates the
   network and NSG rules, and creates the load balancer with its
   certificates, listeners, backend sets and rule sets. On an existing load
   balancer it updates the bandwidth and backend sets to the plan, and fails
   when the installed member CA differs from `--member-ca` or when any other
   setting has drifted, including the origin-pull CA, subnet and NSG
   attachments, and subnet security-list rules. It prints the IDs to
   record in `resource_ids`: `internet_gateway`, `public_route_table`,
   `public_security_list`, `public_subnet` and `network_load_balancer`.
4. `dns` first validates the load balancer's exact listeners, catch-all
   redirect, serving backends, customer CA, network attachments, subnet
   security, and Cloudflare-only NSG rules, including on a dry run. It
   verifies the unique active Cloudflare zone client certificate against
   the reviewed CA and refuses conflicting hostname AOP overrides. It sets
   SSL Full (strict) for both names with a configuration rule
   (`ts-orch-gru-1-api-ssl-strict`), last in the zone's configuration
   ruleset or followed only by rules that set nothing but Full (strict),
   such as another cell's, enables custom zone AOP through
   `origin_tls_client_auth/settings`, and verifies it before publishing
   proxied A records. Missing, ambiguous, pending, expired, or unrelated
   client certificates stop publication. Names holding other record types
   are refused.
5. `ts-orch oci-region public-api origin-ips --plan PLAN [--apply]` re-reads
   Cloudflare's ranges and adds and removes NSG rules, including duplicates,
   to match. Run it when Cloudflare announces a range change.

The Cloudflare token needs Zone DNS Edit, Config Rules Edit and SSL and
Certificates Edit on `terrascale.tech`. `cert` and `apply`
refuse `TS_OCI_BACKEND=cli` and OCI SDK debug or endpoint overrides such as
`OCI_GO_SDK_DEBUG`, so key material never appears in `oci` arguments or
SDK logs.

`inspect-foundation` reads the load balancer back with the same check
`apply` uses: active, flexible at the planned bandwidth, public, in the
public subnet, whose security list egress also covers 8444 with
`public_api.orch`; every hostname bound to its own HTTPS listener and backend
set, each serving `origin` and verifying the client certificate; port 80
only redirecting; `terrabase` verifying member TLS; `ts-auth` holding
exactly every controller; and `terrabase` holding only planned members at the
client port, any of them drained by the controller but one serving. It fetches
Cloudflare's published ranges and requires the one NSG to admit exactly TCP
80 and 443 from each of them; after a Cloudflare change it fails until
`origin-ips --apply` runs. Inventory admission accepts only that recorded
load balancer, and only while its live bandwidth ceiling is within the
priced `max_mbps`.

For the TS-470 GRU rebuild, the user's 2026-10-04 edge decision approves
the load balancer `gru-1-api`, its Origin CA certificate and both proxied
records; the plan has no `gru-1-gw-1` host, Caddy, Let's Encrypt or network
load balancer. After the image, three controllers and two database hosts
with data volumes have clean readbacks, refresh inventory and native cost
admission, which now prices the load balancer; the combined forecast must
stay below USD 200/month. Use TS-487's ts-auth deployment path as it merges.
Verify each edge resource and certificate binding by readback, both DNS
records' `proxied=true`, backend health, and both public HTTPS URLs. Keep
certificate private key material out of logs and evidence. Stop on the
first error; deletes and terminations still require user approval.

## Inter-region private networking (future authorization only)

The current GRU qualification requires no inter-region link. Its reviewed plan
uses VCN `10.251.0.0/24` and a local Oracle Services Network service-gateway
route; it declares no DRG, remote peering connection (RPC), or inter-cell peer
route or ingress rule. Its only peering is the same-region
[operator gateway](#operator-gateway-peering) LPG pair. Do not make another cell
or a private link a GRU acceptance condition, and do not append a DRG route to
the GRU example.

For a separately reviewed pair, the `inspect-private-peer` subcommand in
`ts-orch oci-region preview` accepts `--pair-intent`, `--left-plan`,
`--left-inventory`, `--left-admission`, the corresponding `--right-*` paths,
and `--out`. It makes read-only OCI CLI calls and writes a hash-bound
configuration receipt. It checks disjoint RFC1918 VCN and subnet ranges,
reciprocal connected RPCs and attachments, exact subnet and DRG routes and
import distributions, scoped peer security rules, and each region's existing
local service-gateway route. This command does not change the GRU-only plan,
provision another region, or gate the current GRU launch.

The receipt reports each regional estimate separately and sets
`budget_admission.status` to `blocked`: the per-region estimates repeat shared
resource baselines and apply free allowances independently, so they cannot
prove the combined USD 200 monthly ceiling. The receipt is configuration
readback only. It does not test private endpoint reachability, verify
application mTLS, or establish signed runtime peer consumption or native
replication readiness. Complete those checks through separately authorized
network testing and the later `ts-orchestrator` runtime ownership path.

Before enabling cross-region member replication or required inter-cell control
traffic, the regional foundation operator owns steps 1–4 through authenticated
OCI readback. After controller A's identity, authority, and inventory handoff,
`ts-orchestrator` owns step 5 through signed runtime state:

1. Confirm that the destination region is subscribed and in the tenancy's
   realm, and review tenancy limits, cost admission, and ownership. Choose VCN
   CIDRs that do not overlap each other or GRU's `10.251.0.0/24`.
2. Attach a DRG to each VCN and create and connect the two named RPCs using
   Oracle's [remote VCN peering procedure for upgraded DRGs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/scenario_e.htm).
3. Configure each upgraded DRG's route tables and import distributions to
   admit only the approved paired VCN/RPC routes. Add reciprocal rules for only
   the approved peer subnet CIDRs in each VCN's subnet route table, targeting
   that VCN's DRG. Permit only the required replication and control ports from
   the peer CIDRs in the applicable NSG and security-list rules. Keep each
   region's service-gateway route local; do not use the peer as transit for OCI
   services or unrelated networks.
4. Before runtime traffic or handoff, record OCI readback for both VCN/DRG
   attachments, DRG route tables and import distributions, connected RPC state,
   subnet routes, and network security rules.
   Check private endpoint reachability and that unrelated peer paths remain
   denied.
5. Publish the reviewed private peer IP and port and matching trust material
   through the signed runtime ownership path. Keep TerraBase replication mTLS
   and signed member-authority checks: private addressing and OCI's documented
   inter-region MACsec protection between data centers do not authenticate a
   TerraBase member.

Oracle's [VCN FAQ](https://www.oracle.com/cloud/networking/virtual-cloud-network/faq/)
says remote VCN peering has no separate charge; outbound transfer charges still
apply after the applicable allowance. Use the current
[networking price list](https://www.oracle.com/cloud/price-list/#pricing-networking)
to estimate outbound usage from both regions against the allowance and the
combined monthly ceiling. Do not assume an allowance per RPC, pair, or direction,
or a private-peering bandwidth discount. Select peering for private addressing
and the intended network boundary.

### Create a pair's peering with `ts-orch oci-region peer`

`peer` creates what `inspect-private-peer` reads back (steps 2 and 3): per
cell a DRG `<cell>-drg` with the VCN attached, an RPC `<cell>-rpc-<peer>`, DRG
route tables `<cell>-drg-{vcn,rpc}-routes` whose import distributions accept
only the paired attachment, the peer subnet's route through the DRG, and the
intent's TCP ports from and to the peer subnet in the controller NSG and the
security list. The left RPC connects to the right one. Like the inspector, it
checks only the peer path: the plan's subnet routes must be present, and only
the peer's own route and rules may reach into the peer VCN; other live rules,
such as a NAT gateway default route or HTTPS egress, are kept. It only adds:
route table and security list updates resend every live rule and carry the
read's ETag, and a conflicting live rule is refused, never removed.

1. Write the pair intent with null resource OCIDs. `plan_sha256` is the
   SHA-256 of each bound plan file:

   ```json
   {"schema_version": 1, "tenancy_id": "ocid1.tenancy.oc1..…", "realm": "oc1", "allowed_tcp_ports": [7422],
    "cells": {"SFO": {"plan_sha256": "…", "monthly_cross_region_egress_gb": 10,
                      "drg_id": null, "vcn_attachment_id": null, "rpc_id": null, "rpc_attachment_id": null,
                      "vcn_drg_route_table_id": null, "rpc_drg_route_table_id": null,
                      "vcn_import_distribution_id": null, "rpc_import_distribution_id": null},
              "GRU": {"…": "the same fields for gru-1"}}}
   ```

2. Review the changes; nothing is written:

   ```sh
   ts-orch oci-region peer --pair-intent pair.json --left-plan sfo-1-bound.json \
     --right-plan gru-1-bound.json --out pair-bound.json
   ```

3. Rerun with `--apply`. It refuses before any change if either side would
   fail inspection, writes `pair-bound.json` with the OCIDs bound and runs the
   inspector's live network checks on it. A rerun resumes and changes nothing
   once complete.
4. Read back the receipt with `inspect-private-peer --pair-intent
   pair-bound.json` and both cells' plans, inventories and admissions.

To test failover off the private path, `--drop-port PORT` (instead of
`--out`) removes only the controller NSG's ingress rule for that intent port
from the peer subnet, on both sides; without `--apply` it prints the
removals. The NSG is stateful, so connections already open stay up until they
reconnect. Rerun step 3 to restore the rules.

`inspect-foundation` still compares each cell's rules exactly with its plan,
so it reports the peer rules, and sfo-1's hand-added NAT route and egress, as
drift until the plans carry them.

## Bootstrap sequence

1. Create the reviewed regional foundation under the selected ownership
   boundary only after the pre-create inventory, capacity, security, and cost
   review passes. `ts-orch oci-region foundation` creates it from the plan
   (TS-663); do not create these resources by hand with the `oci` CLI:

   ```sh
   ts-orch oci-region foundation \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/bound-region-plan.json          # dry run: prints the creates
   ts-orch oci-region foundation \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/bound-region-plan.json --apply
   ```

   It finds each resource by its static name in its compartment and creates
   only what is missing, so a rerun creates nothing and an interrupted run
   resumes. For cell `<cell>` (`sfo-1`) the names are the plan's
   `preview_compartment_names` under `parent_compartment_id`; in the network
   compartment `<cell>-vcn` (DNS label `<cell>` without the dash),
   `<cell>-service-gateway` (the plan's `service_gateway_service_id`, all
   services of the region key), `<cell>-private-routes`,
   `<cell>-private-security`, the private subnet `<cell>-private` (no public
   IPs), and the NSGs `<cell>-controllers-nsg` and, when the plan declares
   `workload_nsg_rules`, `<cell>-databases-nsg`, with the plan's rules; in the
   control compartment the DEFAULT vault `<cell>-vault`, its HSM AES-256 key
   `<cell>-key` and the `foundation_buckets`, encrypted with that key (head
   and material versioned, ledger and backup under `bucket_retention_days`).
   The plan's `identity` dynamic groups and the controller and Object Storage
   key policies are written in the home region, `sa-saopaulo-1`, the only
   region OCI accepts IAM writes in. With a null `netbird`, it also creates
   `<cell>-netbird-enrollment` in the control compartment, letting both
   dynamic groups read the secret named `<cell>-netbird-setup-key` once it is
   stored. A same-named resource that differs from the plan (another CIDR,
   compartment, matching rule or statements) is refused, never adopted.
   With `--apply` it runs `inspect-foundation`'s live checks on the result
   and only then writes the bound plan: the plan with `resource_ids` filled.
   It never overwrites a different file. It does not create the operator
   gateway peering, a host `LiveS3Credential` policy or egress: a NAT gateway
   is still outside the plan boundary below.
2. Review the bound plan, with an explicit `bootstrap_object_prefix`, before
   capturing a fresh inventory and cost admission. Choose the canonical prefix intended for the signed
   bootstrap storage domain; an empty string is valid if the domain is
   deliberately unprefixed. The foundation inspection provisionally checks
   the controller IAM object grants against this plan prefix because the
   signed anchor does not exist yet. Inspect that live foundation before
   proceeding:

   ```sh
   ts-orch oci-region preview inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   ts-orch oci-region preview admit \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --out /ABSOLUTE/PATH/cost-admission.json

   ts-orch oci-region preview inspect-foundation \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --out /ABSOLUTE/PATH/foundation-readback.json
   ```

   The inspector performs live reads for the plan-bound compartments, Vault
   and KMS key, network and rules, buckets and retention, controller dynamic
   group and policy, including ledger and HEAD grants for both `bootstrap/v1/*`
   and `bootstrap/v1/*` beneath the plan prefix. It also checks the
   workload-host dynamic group, and the Rust-era `LiveS3Credential` secret
   policy and public API resources only when the plan binds them; a C# cell
   leaves both unbound, and a partial binding fails. It writes
   a readback bound to the plan and
   inventory hashes, with the tenancy, cell, region, compartment, Vault, and key
   identities and inspection time. It does not create resources, prove there
   are no other inherited or separately attached IAM grants, or authorize a
   write. Keep the exact output and its SHA-256.
3. Create the owner-only local material source with `generate-controller-material`
   as described in [production role configuration](production-role-config.md).
   Hash the reviewed config, then generate the source and public record:

   ```text
   ts-orch bootstrap generate-controller-material \
     --config /ABSOLUTE/PATH/controller-material.json \
     --config-sha256 CONTROLLER_MATERIAL_CONFIG_SHA256 \
     --directory /ABSOLUTE/PATH/controller-material \
     --out /ABSOLUTE/PATH/controller-material-record.json
   ```

   The config binds the mapped cell and region, deployment and cluster IDs,
   controller slots, addresses, and validity. Keep the local directory
   owner-only and outside the checkout. Its public record and generated PEMs
   do not contain private key bytes. Its `cell.jwt` already holds the role
   signer, so the region's roles get NATS identities without a
   [role claim](broker-claim-rotation.md#role-claim).
4. After the live readback and current budget admission pass, publish the
   versioned Vault material and public reference record with:

   ```text
   ts-orch bootstrap provision-controller-material \
     --directory /ABSOLUTE/PATH/controller-material \
     --manual-readback /ABSOLUTE/PATH/foundation-readback.json \
     --manual-readback-sha256 MANUAL_READBACK_SHA256 \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --inventory-sha256 MANUAL_INVENTORY_SHA256 \
     --cost-admission /ABSOLUTE/PATH/cost-admission.json \
     --cost-admission-sha256 COST_ADMISSION_SHA256 \
     --cost-plan-sha256 MANUAL_PLAN_SHA256 \
     --oci-config /ABSOLUTE/PATH/oci-config --oci-profile DEFAULT \
     --out /ABSOLUTE/PATH/controller-material-references.json
   ```

   The readback must be authenticated and no more than 15 minutes old. The
   supplied readback, inventory, admission, and plan digests must match the
   exact files; the admission must be current and within the US$200/month
   ceiling. The OCI profile's tenancy and region must match the readback. The
   output path must be new and outside the owner-only source directory. Record
   the public reference output and SHA-256 of it and the associated PEM files.
5. Prepare and sign the cell identity, anchor, manifests for controller A/B/C,
   and founder plan from the reviewed target and live resource inventory. Keep
   root signing keys and private controller material in their owner-controlled
   stores; never put secrets in the image, user-data, evidence bundle, or
   command output.
6. Run the read-only seed preflight against the current plan, inventory,
   admission, signed anchor and controller-A manifest, and signed image receipt.
   It verifies the anchor, manifest, and image through the supplied Go tools
   and repeats live foundation reads. The verified anchor's namespace must
   match live Object Storage; its prefix, ledger and HEAD buckets, KMS keys,
   cell, region, and digest must agree with the plan and verified manifest.
   It then rechecks live IAM using the signed prefix, checks the exact
   controller-A profile, and writes the reviewed launch record. It does not
   create an OCI instance:

   ```sh
   ts-orch oci-region preview seed-preflight \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --bootstrap-tool /ABSOLUTE/PATH/ts-orch \
     --anchor /ABSOLUTE/PATH/anchor.signed.json \
     --manifest /ABSOLUTE/PATH/controller-a.manifest.json \
     --identity /ABSOLUTE/PATH/identity.json \
     --bootstrap-root /ABSOLUTE/PATH/bootstrap-root.pub \
     --image-ocid EXACT_IMAGE_OCID \
     --release-tool /ABSOLUTE/PATH/ts-orch \
     --image-receipt /ABSOLUTE/PATH/image-receipt.signed.json \
     --release-delegation /ABSOLUTE/PATH/release-delegation.signed.json \
     --release-root /ABSOLUTE/PATH/release-root.pub \
     --image-file /ABSOLUTE/PATH/controller-image.qcow2 \
     --base-image-file /ABSOLUTE/PATH/base-image.qcow2 \
     --kernel-file /ABSOLUTE/PATH/kernel \
     --out /ABSOLUTE/PATH/reviewed-seed-plan.json
   ```

   Keep the exact output and SHA-256. Use the output's `create_identity` value
   for the reservation and the controller-A `BootstrapCreateKey` tag. If the
   reviewed plan sets `seed_a_create_identity`, preflight carries that value;
   otherwise it derives one from the reviewed plan, manifest, anchor, and image
   receipt. Do not substitute another value after preflight. The first-seed
   signing, observation, and fresh completion commands bind to this file and
   digest. Renewed inventory or admission requires a new preflight.
7. Render the complete controller-A launch input from the reviewed seed plan:

   ```sh
   ts-orch oci-region preview seed-launch \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --reviewed-plan /ABSOLUTE/PATH/reviewed-seed-plan.json \
     --manifest /ABSOLUTE/PATH/controller-a.manifest.json \
     --identity /ABSOLUTE/PATH/identity.json \
     --anchor /ABSOLUTE/PATH/anchor.signed.json \
     --host-enrollment /ABSOLUTE/PATH/host-enrollment-public.json \
     --owner-ssh-public-key /ABSOLUTE/PATH/owner-ed25519.pub \
     --out /ABSOLUTE/PATH/controller-a-launch.json
   ```

   The image carries only trust roots. Every deployment-specific input travels
   in OCI instance metadata: the slot descriptor, the signed manifest, the
   deployment identity, the signed anchor and the host enrollment bundle. The
   controller installer verifies the anchor against the image roots before it
   installs any of them, write-once, beside those roots; the founder and the
   placement fleet forward the same material to controllers B/C and to
   managed hosts. One qualified image therefore serves every deployment and
   bootstrap attempt. The helper refuses a manifest or anchor that differs
   from the reviewed seed plan and metadata above OCI's 32,000-byte limit.
   `--owner-ssh-public-key` is optional; the minimal cloud-init user-data only
   authorizes that key and prints the SSH host key to the serial console.

8. Before creating controller A, sign and publish its exact seed reservation.
   Use the create identity from the reviewed seed plan without changing it:

   ```text
   ts-orch bootstrap sign-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json \
     --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reviewed-plan /ABSOLUTE/PATH/reviewed-seed-plan.json \
     --reviewed-plan-sha256 REVIEWED_SEED_PLAN_SHA256 \
     --create-identity EXACT_PREFLIGHT_CREATE_IDENTITY \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-reservation.json

   ts-orch bootstrap publish-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json \
     --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json \
     --oci-config /ABSOLUTE/PATH/oci-config --oci-profile DEFAULT
   ```

   Do not launch controller A until the exact signed reservation is published.
9. Start only controller A with the rendered launch input. Import the image
   with `ts-orch oci-region import-image` first: it applies the UEFI
   firmware, paravirtualized-device and A1-only shape contract that an ARM
   instance needs to boot. An imported image without that capability schema
   launches with BIOS firmware and never boots.

   If a metadata key is missing after launch, do not submit a partial
   metadata map as though OCI will merge it. `UpdateInstance` replaces the
   metadata map: start from an authenticated current instance readback, retain
   the exact existing `user_data`, and use the current ETag with `If-Match`.
   OCI does not allow changing `user_data` after launch. Re-read the metadata
   after an update and rerun the observer; do not sign completion on the
   update response alone.

   Leave `launchOptions` absent unless the reviewed profile explicitly
   requires an override. This launch uses OCI's default firmware and boot
   volume options. Submit the file with the configured profile and region:

   ```sh
   oci compute instance launch \
     --config-file /ABSOLUTE/PATH/oci-config \
     --profile DEFAULT \
     --region <REVIEWED_REGION> \
     --from-json file:///ABSOLUTE/PATH/controller-a-launch.json
   ```

   `ts-orch oci-region attempt --config attempt.json launch` submits the same
   file in-binary through the OCI Go SDK instead (no Python CLI): it refuses
   unknown or missing members, carries `subnetId`, `privateIp`, `nsgIds` and
   `assignPublicIp` in `createVnicDetails` exactly as the CLI did, and sends
   an `opc-retry-token` bound to the file bytes.

   Record the exact OCI instance OCID returned by the CLI. OCI accepting the
   launch request is not proof that the signed network profile was applied.
10. Re-read controller A, its primary VNIC, and boot-volume sizing with
    `ts-orch bootstrap observe-external-seed`, then compare them with the reviewed
    plan before signing anything. Require the exact instance in `RUNNING`,
    the exact `BootstrapCreateKey`, signed image and shape, primary VNIC on
    the reviewed subnet and reserved private IP, both signed NSGs, and no
    public IP. Require the attached boot volume to report the signed image
    and exact requested size and VPU setting. Any missing or different field
    must make observation fail. Do not sign or publish completion, refresh
    inventory, or hand off controller A after a failed observation. A launch
    with VNIC settings only under nested `createVnicDetails` previously
    produced the wrong private IP and no NSGs, and the observer rejected that
    instance.

    After observation succeeds, sign the resulting completion bundle offline
    with `ts-orch bootstrap sign-external-seed-completion`, then publish it with
    `ts-orch bootstrap publish-external-seed-completion`. Follow steps 4 and 5 in
    [Initial founder authority](founder-genesis-cli.md#first-external-seed-transaction)
    for the exact flags. Do not hand off controller A until completion
    publication succeeds or its exact uncertain outcome is reconciled.
    Before any later inventory or admission refresh, use a new plan copy with
    `resource_ids.instances.controller-a` set to A's exact OCID and
    `seed_a_create_identity` set to the preserved preflight value. The helper
    rejects post-launch inventory if A's exact OCID and `BootstrapCreateKey`
    are not recorded. Preserve the original preflight-bound plan and evidence.
11. Completion publication records the observed seed reservation; it does not
    prove that the controller's signed bootstrap gate admitted A. Before
    handoff, require the controller to complete its current signed anchor,
    slot, image, credential, and founder-floor checks. A failed or pending gate
    holds the handoff even when OCI readback and completion publication passed.
    Then explicitly hand controller A's identity, authority, and inventory to
    the orchestrator owner. The admitted founder launches only the signed
    same-cell B/C peers. Preserve the signed plan and exact IDs so retries and
    reconciliation use the same intent. Do not create replacement seed
    instances to resolve an uncertain handoff or publication result.
12. After the cell is running, the read-only NATS topology/availability helper
    can report controller and JetStream metadata:

    ```sh
    go build -trimpath -o /tmp/natsdiag tests/firecracker/natsdiag.go
    /tmp/natsdiag \
      --controller-config /etc/terrascale-orchestrator/controller.json \
      --phase steady
    ```

    This is a topology and availability diagnostic. It does not establish
    durable recovery, verify the OCI launch, or prove live deployment or
    production readiness. Use the reviewed deployment evidence procedure for
    those claims.

The detailed founder-object formats and seed transaction are documented in
[Initial founder authority](founder-genesis-cli.md). Use that page together
with the frozen CLI help and reviewed plan for the source revision being
operated; do not copy a command from an older OpenTofu-based seed procedure.

## Services after bootstrap

The controller config is accepted once and never edited. A running cell's
generic services (ts-auth and later ones) change with signed cell specs:
see [Add a service to a running region](cell-spec.md#add-a-service-to-a-running-region).
`oci-region attempt`'s `services` phase adds the attempt config's services the
same way, derives TerraBase's and ts-auth's profiles from the plan when the
config names none, and grants every controller node its host (see
[cell spec](cell-spec.md#commands)).

## Stop conditions and limits

Stop before a write if the current live readback, signed plan, image, cell,
compartment, network, shape, or cost admission disagree. Stop if the signed
plan or admission expires. For an uncertain result, reconcile using the exact
preserved transaction and evidence; do not create a second A or change the
intent to make a retry pass. Record mismatches and route them to the owner of
the resource or signed plan.

This procedure covers one cell's manual first-controller boundary for the
three fixed mappings above, subject to the host-enrollment limitation. It does
not establish cross-region replication, continuous management during controller
loss, database serving, a live SFO/FRA deployment, or production readiness.
Those require their own current source and runtime evidence.

The post-handoff owner for ARM workload hosts and TerraBase also owns their
disposable-preview removal. For the current GRU cost cutoff and exact workload
teardown procedure, see [Explicit disposable workload teardown](disposable-workload-teardown.md).
