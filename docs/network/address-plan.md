# TerraScale address plan (TS-675)

Keep the verified, disjoint live allocations: NetBird `10.200.0.0/16`,
GRU `10.251.0.0/24`, SFO `10.252.0.0/24`, and Fly
`fdaa:2:ebb9::/48`. Reserve a stable `/16` for each region under
`10.240.0.0/12`; the current `/24` VCNs occupy only part of their reservations.
Changing a reservation does not change a live VCN or subnet.

This plan records **observed** non-overlap, not a promise that no future client
LAN uses the same RFC1918 space. Inspect every new host/client before enrollment.
Tailscale's `100.64.0.0/10` is always excluded from TerraScale allocation.

Tailscale runs on user clients and the operator's PCs, not TerraScale servers
(user clarification, 2026-10-07). Clients with both meshes must retain their
Tailscale routes and MagicDNS while reaching TerraScale over NetBird. Regional
servers require NetBird connectivity and disjoint routes; Tailscale enrollment
and MagicDNS are not server requirements.

## Reservations

Parent pools and their child allocations intentionally contain one another.
Sibling allocations, separate overlays and independently routed networks must
be disjoint. A route to an existing subnet is not another allocated network.

| Owner / network | Dedicated IPv4 allocation | Dedicated IPv6 allocation | State / rule |
| --- | --- | --- | --- |
| NetBird account mesh | `10.200.0.0/16` | `fd9c:200:2182:65f2::/64` | Live, shared by all account peers; never use the default CGNAT range |
| OCI regional parent pool | `10.240.0.0/12` | No OCI IPv6 allocation today | Reserve individual `/16`s below; never advertise the entire parent pool |
| GRU region | `10.251.0.0/16` | None | Live VCN `10.251.0.0/24`; private `10.251.0.0/25`; API `10.251.0.128/26` |
| SFO region | `10.252.0.0/16` | None | Live VCN `10.252.0.0/24`; private `10.252.0.0/25`; API `10.252.0.128/26` |
| FRA region | `10.253.0.0/16` | None | Reserved; derived initial VCN `10.253.0.0/24`; this ticket does not claim a live FRA audit |
| Shared ts-ops infrastructure | `10.250.0.0/16` | None in OCI | Excluded dependency; live subnet `10.250.10.0/24`; never mutate for TS-675 |
| Additional regional reservations | `10.240.0.0/16` through `10.249.0.0/16`, `10.254.0.0/16`, `10.255.0.0/16` | Not assigned | Twelve free `/16`s; add explicit reviewed mappings before use |
| TerraScale container-bridge parent pool | `10.208.0.0/12` | Not assigned | Reserve unique `/24`s per host and network; do not advertise the pool or reuse defaults |
| Tailscale, external owner | `100.64.0.0/10` | `fd7a:115c:a1e0::/48` | Retain addresses, routes and MagicDNS; never allocate to NetBird, OCI or bridges |
| Fly organization `personal`, provider owner | No customer IPv4 private pool observed | `fdaa:2:ebb9::/48` | Reserve full organization 6PN; per-machine `/112`s lie within it; use `.internal` DNS for moving machines |

The reservation implementation is `internal/networkplan/plan.go`.
Regional allocations are explicit, independent of catalog order. Adding a
catalog region without its address reservation fails validation. The invariant
test compares every assigned region with meshes, external exclusions, bridge
space and Fly; it also verifies that all regions fit the regional parent pool.

Initial private/API subnets keep `.0/25` and `.128/26` inside each region's
`.0.0/24`. Additional VCNs/subnets require separate, disjoint suballocations
inside that region's `/16`; never expand a shared live VCN just to match the
reservation. Existing NATS client/cluster traffic uses controller VNIC seats
`.11`, `.12`, `.13` in the private subnet (TCP4222/6222). It allocates no overlay
or bridge. DRG/RPC peering forwards the opposite private `/25` and allocates no
third host range; leafnode TCP7422 uses the same private addresses, with reviewed
NetBird addresses as a fallback (TS-668).

## Container bridge allocations

No active Docker or Podman bridge was found on the nine inspected hosts.
All three T3 hosts nevertheless have duplicate unused `podman` definitions
`10.88.0.0/16` in both rootful and rootless stores. These definitions are not
approved TerraScale bridge allocations. Do not activate or route them; give a
TerraScale container its planned network explicitly. The current operator
container uses host networking and requires no bridge migration.

| Host / store | First reserved bridge subnet | State |
| --- | --- | --- |
| delta / rootful | `10.208.0.0/24` | Reserved, not configured |
| delta / rootless | `10.208.1.0/24` | Reserved, not configured |
| beta / rootful | `10.208.2.0/24` | Reserved, not configured |
| beta / rootless | `10.208.3.0/24` | Reserved, not configured |
| mariogk-dev / rootful | `10.208.4.0/24` | Reserved, not configured |
| mariogk-dev / rootless | `10.208.5.0/24` | Reserved, not configured |
| mariogk-desktop / Docker `bridge` | `10.208.6.0/24` | Reserved, not configured |
| mariogk-desktop / Docker `ku_machine-control` | `10.208.7.0/24` | Reserved, not configured |
| mariogk-desktop / Docker `ku_default` | `10.208.8.0/24` | Reserved, not configured |

Additional bridges must receive an unused `/24` within `10.208.0.0/12` and a
record here before ts-orchestrator creates them. Moving an active container
requires its own orchestrator-owned, health-checked rollout; do not renumber
an active bridge using a direct Docker/Podman command. Unused duplicate
definitions remain an explicit inventory finding, not proof of global bridge
uniqueness or a completed migration.

The refreshed desktop audit found dormant Docker definitions `bridge`
(`172.17.0.0/16`), `ku_machine-control` (`172.18.0.0/16`) and `ku_default`
(`172.19.0.0/16`), with no endpoints or running containers. These do not overlap
the audited LAN or other networks, but remain outside the TerraScale bridge
plan. Their reserved `/24`s above apply before future TerraScale use; this
ticket does not change the owner's unrelated desktop containers.

## External exclusions and live evidence

Do not allocate `10.0.0.0/24`, `10.10.0.0/16`, `192.168.0.0/16`, or
Docker's `172.17.0.0/16`. Also retain the observed `10.11.99.0/24` host network,
the dormant Podman `10.88.0.0/16` definitions, LAN ULA `fd10:10:10::/64`,
and the public LAN `2804:16a8:1:3fed::/64` outside TerraScale's pools.
Loopback, link-local, multicast, OCI metadata/DNS `169.254.169.254`,
and provider service destinations are protocol/provider scopes, not allocatable
TerraScale networks. Default routes are forwarding entries, not reservations.

| Audited scope | Ranges / observations | Evidence |
| --- | --- | --- |
| GRU + SFO OCI APIs | All accessible active compartments and tenancy root: three VCNs, five subnets, two DRGs, reciprocal PEERED RPCs; no OCI IPv6 | [OCI inventory and object IDs](../evidence/ts-675-oci-audit-20261007.md) |
| Six regional nodes | VCN private `/25`s, mesh IPv4/IPv6; NATS4222/6222 on private VNICs; no active bridges or Tailscale; no7422 listener at cutoff | Same OCI/node inventory |
| delta + beta + mariogk-dev | LAN10.10.10/24; dev10.11.99/24; NetBird10.200/16; Tailscale CGNAT; IPv6 scopes disjoint; six unused Podman defaults | [Host, route, DNS and client inventory](../evidence/ts-675-host-audit-20261007.md) |
| mariogk-desktop, refreshed audit | LAN10.10.10/24; both meshes; Docker172.17/16,172.18/16,172.19/16 are dormant without endpoints | Same refreshed host inventory |
| NetBird management0.80 | IPv4/IPv6 settings,12 peers, GRU `/25` resource, scoped DNS objects and policy IDs | [Management API inventory](../evidence/ts-675-mesh-fly-audit-20261007.md) |
| Fly | Organization `/48`, nine machines and16 registered WireGuard connections; guest IPv4/DNS/bridges not inspectable from the dashboard image | Same management/Fly inventory |

The supplied `mariogk-dev` facts actually identify **delta**:
`10.200.87.10`, `100.77.52.68`. Verified mariogk-dev uses
`10.200.35.107`, `100.89.133.91`. Verify hostname, interface address and mesh
identity before any operation. Fifteen additional Tailscale clients are visible
but were not OS-audited; three were offline. Manager inventories cannot prove
their LANs, routes, DNS or installed software.

The audit table is posted on Ku TS-675 (comment
`1219f465-ad8b-425c-a0f6-46292064ce36`). Audit documents retain their original
timestamps; later DNS/deployment changes need a new check result.

## Config validation and coexistence check

`ts-orch oci-region` validates each plan's VCN against its cell's dedicated
`/16` before any OCI request. The existing nested-subnet and sibling-subnet
checks still apply. `ts-orch region plan` derives its `/24` from the same stable
reservation. NetBird desired-state validation rejects any account mesh range
other than `10.200.0.0/16` and any routed cell subnet outside that cell's
reservation before contacting the manager. Tests cover CGNAT, LANs, broad
supernets, another region's allocation, host bits and manager mutation rejection.

Build once at low priority, then run the read-only checker:

```sh
nice -n 19 make build
scripts/check-network-coexistence.sh --all \
  --vault-id ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq \
  --netbird 'sudo -n netbird-wt0'
```

On an operator using the automation container, pass its existing client as
`--netbird`, as documented in `deploy/netbird/README.md`. No client is installed,
enrolled or changed by this check. `--all` inspects the three T3 hosts using
strict known-host SSH and every regional server the operator client lists
using the existing Vault-backed NetBird SSH session. Use `--host SSH_ALIAS`
or `--node PEER_NAME` to limit a check. `--host` checks a PC/user client with
both meshes; `--node` checks a regional server with NetBird only. Without
targets it checks the local Linux client. Add an enrolled client outside the
T3 defaults explicitly, for example `--host mariogk-desktop`; `--all` does not
mean every Tailscale peer must install NetBird.

The Go implementation collects host addresses and every routing table in both
families, discovers the actually connected TerraScale NetBird daemon (including
the dev automation container). PCs/clients require a separately enrolled
Tailscale interface, native `getent` lookups and live probes through both
meshes. Tailscale MagicDNS must continue to resolve through `100.100.100.100`.
Regional servers require a live cross-region NetBird TCP probe; their NetBird
DNS may be disabled, as in the manager's server policy. All targets reject
routes into the other overlay or local LAN/bridge, NetBird default routes,
DNS default-route takeover and DNS scope outside NetBird's own zones and
reverse zones. The checker reads systemd-resolved scope evidence and also
recognizes a Tailscale-managed `/etc/resolv.conf` for client MagicDNS.
An unavailable resolver-scope inspection fails; successful lookups alone
cannot prove suffix scoping. TS-672 installed systemd-resolved on mariogk-dev
during the live check.

NetBird DNS is restricted to `nb.ts.internal`, the managed `gru.ts.internal`
zone and their reverse zones; no `~.`, `~ts.net`, or Tailscale reverse-zone
claim. With a Fly `.internal` resolver, these more-specific NetBird suffixes
must keep their own resolver. Neither NetBird nor Fly replaces MagicDNS.
TS-672 owns live scoped DNS, TS-674 owns the NetBird0.80 client rollout, and
TS-668 owns private peering and the NATS leaf runtime.

Exit0 means **every requested host** passed; missing daemons, failed queries,
offline transport or an incomplete read cause a failure. This command checks
active routes/bridges; the separate management/container inventories are still
required to account for inactive definitions and offline clients. `--all`
cannot discover a server hidden by the operator's NetBird policy or audit
unlisted user devices; compare its printed hosts with this inventory.
The [live check evidence](../evidence/ts-675-coexistence-check-20261007.md)
retains the original nine-host result and the corrected ten-host run: four PCs
pass dual-mesh checks and all six regional servers pass NetBird checks, exit0.
The original server failures included incorrectly required client-only checks;
the corrected server checks do not require Tailscale or MagicDNS.

## Migration decision and outstanding acceptance

No audited active allocation overlaps another allocation; keep the serving
mesh, VCNs and subnets in place. No OCI CIDR addition/removal, server address
change, serving-cell re-found or NetBird account-range PUT is needed.

NetBird0.80 account-range PUT reallocates **all** account peer IPs in one
transaction and explicitly causes clients to restart/reconnect, including
ts-ops and user devices. It has no region-scoped dual-range migration. If a
future audit finds an actual conflicting client LAN, do not run a blind
`netbird sync --apply` to renumber the account: present the target, outage and
device-access options to the user first. The pinned upstream API/client code
references are in the management evidence.

For an actual OCI overlap, the orchestrator must add the reviewed new CIDR
first, prepare new disjoint subnets, routes and security rules, move one
drain-safe node at a time, verify health and replication after each move, then
remove old allocations only after the complete readback proves them unused.
Operate one region at a time; preserve private and NetBird fallback reachability.
Do not use direct provider mutation or re-found a serving cell. This ticket
does not introduce an untested live-subnet migration command when no CIDR move
is necessary.

At the initial audit, GRU was held by TS-632 with two of three serving members.
Both public readyz endpoints passed; GRU1↔SFO1 TCP9443 passed over OCI and
NetBird. These are availability and transport checks, **not** cross-region
replication proof. NATS7422 was not running, so replication acceptance remains
dependent on TS-668/TS-660. No regional mutation is safe while the hold remains.

Remaining client acceptance requires a check on the known enrolled but offline
`mariogk-laptop`; the inspected PCs are `delta`, `beta`, `mariogk-dev` and
`mariogk-desktop`. Tailnet membership alone does not put a device in TerraScale's
NetBird client inventory: `alpha` was inspected and is Tailscale-only. Future
enrolled clients must supply their address/route/DNS inventory. Unused bridge
definitions still need approved unique ranges before activation. No regional
Tailscale installation or enrollment credential is needed. User-device or LAN
changes remain separate decisions; this checker only reads their state.
