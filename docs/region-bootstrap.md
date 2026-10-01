# Manual regional bootstrap

This runbook describes setup of a regional foundation and its first
controller, followed by the identity and authority handoff to
`ts-orchestrator`. The current authorized qualification target is GRU
(`sa-saopaulo-1`): the assistant operates this runbook for the foundation,
controller A, and required credential/image prerequisites instead of leaving
those provisioning steps to the user. Use the OCI CLI to get or create required
Vault secrets where they are runbook inputs. Publish generated controller
material through the documented `ts-bootstrap provision-controller-material`
flow, which binds the material to authenticated readback and current cost
admission. After the explicit controller-A handoff, `ts-orchestrator` alone
owns B/C, the ARM workload hosts, and signed TerraBase deployment. The
bootstrap tools accept these fixed cell-to-region
mappings: GRU / `sa-saopaulo-1`, SFO / `us-sanjose-1`, and FRA /
`eu-frankfurt-1`. The checked-in regional plan is a concrete GRU example; a
different mapped cell needs its own reviewed plan populated with that cell's
live resource IDs and signed genesis. This is an operating procedure, not
evidence that a region has been deployed or that the system is
production-ready. See the [workspace GOAL](../../GOAL.md) and the
[shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md)
for current scope and evidence.

## Supported scope and ownership

`generate-controller-material`, the first-seed commands, and the preview
helper validate only the three mappings listed above. The checked-in
`deploy/oci-region/plan.json` remains populated for GRU, including its existing
ts-ops resources and the [operator gateway](#operator-gateway-peering) that
the ts-ops host runs. For SFO or FRA, copy it to a separate reviewed plan and fill
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
| NetBird server and routing peer on the ts-ops host | ts-ops host owner (HomeLab `ops/ts-ops/netbird/`) |
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
3. Before creating the foundation, capture and review current inventory and a
   cost admission:

   ```sh
   python3 deploy/oci-region/preview.py inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   python3 deploy/oci-region/preview.py admit \
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

## Operator gateway peering

Operators reach the private cell through a NetBird routing peer on the ts-ops
host (Forgejo and NetBird; private IP `10.250.10.155` in `ts-ops-vcn`
`10.250.0.0/16`). The NetBird server and routing peer belong to that VM's owner
and are documented in HomeLab `ops/ts-ops/netbird/`. This runbook
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

`preview.py` enforces this boundary. In the plan, `operator_gateway` must be a
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
NetBird server group and configure explicit operator access policies in the
manager.

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

Generate the public image input from the fully populated reviewed plan:

```sh
jq '{management_url: .netbird.management_url, management_ip: .netbird.management_ip,
     region, setup_key_secret_id: .netbird.setup_key_secret_id}' "$PLAN" > netbird.json
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
  metadata: `preview.py seed-launch` sets it on controller A, which forwards it
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
policy allows it. The server setup key auto-assigns `ts-orch-servers`; a
`netbird-ssh` policy targeting that group also makes the manager enable each
member's SSH server. Add operator policies from the `operators` group to it:

| Policy | Protocol and ports |
| --- | --- |
| Operator SSH | `netbird-ssh` (port 22 is redirected to the SSH server's 22022) |
| Operator internal tools | TCP 4222 (controllers), 9465 (members) and any other required tool port |

HomeLab `ops/ts-ops/netbird/admin.py configure-cell` reconciles the SSH policy
as `operators-ssh-to-ts-orch-servers`, next to the routed `operators-to-gru-cell`
policy. Do not allow 6222 or 8443 to operators. From an enrolled operator
device:

```sh
netbird ssh root@SERVER_NETBIRD_NAME
netbird ssh -L 8080:127.0.0.1:8080 root@SERVER_NETBIRD_NAME   # loopback-only tool
```

Plain `ssh` to a NetBird name also uses NetBird SSH, through the NetBird
client's OpenSSH drop-in. For OpenSSH, dial the private IP over the routing peer:

```sh
ssh -i ~/.ssh/terrascale-owner ubuntu@10.251.0.12
```

Controller A prints its host key to the serial console at first boot. For the
other servers, compare the host key on first connection with
`netbird ssh root@SERVER_NETBIRD_NAME ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
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

   Then run `preview.py inventory` and `admit` against the plan copy.
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

`deploy/oci-region/public-api.py` exposes the members' TerraBase HTTPS API
through a public Network Load Balancer. It creates an internet gateway, the
public subnet `10.251.0.128/26` with its own route table and security list, a
TCP passthrough NLB on 443 to each member's client port, and the one
workload-NSG rule that admits the client port from the public subnet. Members
keep private addresses, and TerraBase terminates TLS and authenticates every
request.

The plan declares this as `public_api` (`subnet_cidr`, `listener_port`,
`client_port`). After `public-api.py` runs, record `internet_gateway`,
`public_subnet`, `public_route_table`, `public_security_list`, and
`network_load_balancer` in the reviewed plan copy. `load_plan` requires the
public subnet to be inside the VCN and outside the private subnet, and admits
it only as the member client-port source. `inspect-foundation` reads back:

- the gateway: enabled, in the cell VCN, with no route table of its own;
- the public subnet: public IPs allowed, with its own route table and security
  list;
- the route table: exactly `0.0.0.0/0` to the gateway;
- the security list: exactly TCP 443 in from anywhere and the client port out
  to the private subnet;
- the NLB: public, TCP only, with one listener on 443, no NSGs, and
  source/destination preservation off, whose backends are only the planned
  members on the client port.

## Inter-region private networking (future authorization only)

The current GRU qualification requires no inter-region link. Its reviewed plan
uses VCN `10.251.0.0/24` and a local Oracle Services Network service-gateway
route; it declares no DRG, remote peering connection (RPC), or inter-cell peer
route or ingress rule. Its only peering is the same-region
[operator gateway](#operator-gateway-peering) LPG pair. Do not make another cell
or a private link a GRU acceptance condition, and do not append a DRG route to
the GRU example.

For a separately reviewed pair, the `inspect-private-peer` subcommand in
`deploy/oci-region/preview.py` accepts `--pair-intent`, `--left-plan`,
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

## Bootstrap sequence

1. Create the reviewed regional foundation under the selected ownership
   boundary only after the pre-create inventory, capacity, security, and cost
   review passes. Record the exact compartment, network, routing, security,
   Vault/KMS, IAM, and bootstrap-storage identities. Do not rely on an old
   Terraform plan or receipt as proof of current live state.
2. Update the reviewed plan with the exact created resource IDs and an
   explicit `bootstrap_object_prefix` before capturing a fresh inventory and
   cost admission. Choose the canonical prefix intended for the signed
   bootstrap storage domain; an empty string is valid if the domain is
   deliberately unprefixed. The foundation inspection provisionally checks
   the controller IAM object grants against this plan prefix because the
   signed anchor does not exist yet. Inspect that live foundation before
   proceeding:

   ```sh
   python3 deploy/oci-region/preview.py inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   python3 deploy/oci-region/preview.py admit \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --out /ABSOLUTE/PATH/cost-admission.json

   python3 deploy/oci-region/preview.py inspect-foundation \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --out /ABSOLUTE/PATH/foundation-readback.json
   ```

   The inspector performs live reads for the plan-bound compartments, Vault
   and KMS key, network and rules, buckets and retention, controller dynamic
   group and policy, including ledger and HEAD grants for both `bootstrap/v1/*`
   and `bootstrap/v2/*` beneath the plan prefix. It also checks the selected
   workload-host dynamic group and `LiveS3Credential` secret policy. It writes
   a readback bound to the plan and
   inventory hashes, with the tenancy, cell, region, compartment, Vault, and key
   identities and inspection time. It does not create resources, prove there
   are no other inherited or separately attached IAM grants, or authorize a
   write. Keep the exact output and its SHA-256.
3. Create the owner-only local material source with `generate-controller-material`
   as described in [production role configuration](production-role-config.md).
   Hash the reviewed config, then generate the source and public record:

   ```text
   ts-bootstrap generate-controller-material \
     --config /ABSOLUTE/PATH/controller-material.json \
     --config-sha256 CONTROLLER_MATERIAL_CONFIG_SHA256 \
     --directory /ABSOLUTE/PATH/controller-material \
     --out /ABSOLUTE/PATH/controller-material-record.json
   ```

   The config binds the mapped cell and region, deployment and cluster IDs,
   controller slots, addresses, and validity. Keep the local directory
   owner-only and outside the checkout. Its public record and generated PEMs
   do not contain private key bytes.
4. After the live readback and current budget admission pass, publish the
   versioned Vault material and public reference record with:

   ```text
   ts-bootstrap provision-controller-material \
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
   python3 deploy/oci-region/preview.py seed-preflight \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --bootstrap-tool /ABSOLUTE/PATH/ts-bootstrap \
     --anchor /ABSOLUTE/PATH/anchor.signed.json \
     --manifest /ABSOLUTE/PATH/controller-a.manifest.json \
     --identity /ABSOLUTE/PATH/identity.json \
     --bootstrap-root /ABSOLUTE/PATH/bootstrap-root.pub \
     --image-ocid EXACT_IMAGE_OCID \
     --release-tool /ABSOLUTE/PATH/ts-release \
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
   python3 deploy/oci-region/preview.py seed-launch \
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
   ts-bootstrap sign-external-seed-reservation \
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

   ts-bootstrap publish-external-seed-reservation \
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
   with `deploy/oci-region/import-image.py` first: it applies the UEFI
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

   Record the exact OCI instance OCID returned by the CLI. OCI accepting the
   launch request is not proof that the signed network profile was applied.
10. Re-read controller A, its primary VNIC, and boot-volume sizing with
    `ts-bootstrap observe-external-seed`, then compare them with the reviewed
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
    with `ts-bootstrap sign-external-seed-completion`, then publish it with
    `ts-bootstrap publish-external-seed-completion`. Follow steps 4 and 5 in
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
