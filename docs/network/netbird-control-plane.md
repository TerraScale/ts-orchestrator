# NetBird control-plane path (TS-676)

Status, 2026-10-07: root cause verified; uniform policy and failover are not
implemented. The draft contains an operator audit, not a serving-cell rollout.
The [sanitized live readback](../evidence/ts-676-control-plane-baseline-20261007.json)
records every peer's observed sockets, OCI DNS answer, TLS probes and the
relevant OCI route/egress metadata.

## Why GRU is private and SFO is public

The control plane runs on the `ts-ops` OCI VM in `sa-saopaulo-1`, in
`ts-ops-vcn` (`10.250.0.0/16`), subnet `ts-ops-public`
(`10.250.10.0/24`). Its primary VNIC has private IP `10.250.10.155` and
public IP `163.176.73.79`. The repository's combined NetBird server supplies
management, signal and secure relay on the same TLS name,
`netbird.terrascale.tech:443`, behind Caddy. It also supplies STUN on UDP
3478. There is no separately advertised TURN service in the observed client
configuration. No changes or SSH sessions to ts-ops are needed for this audit.

The GRU image input sets `management_ip: 10.250.10.155`.
`ts-orch netbird-enroll` owns this exact `/etc/hosts` entry:

```text
10.250.10.155 netbird.terrascale.tech # terrascale-netbird-manager
```

SFO's input omits `management_ip`; `netbird image-input` explicitly generates
public enrollment for non-home regions. Both use
`https://netbird.terrascale.tech`. Direct OCI DNS queries return the public
address from both regions. The current difference is a host override, **not
OCI split-horizon DNS**. GRU's private traffic uses its same-region LPG to the
ts-ops VCN; SFO uses its NAT gateway. The dashboard's SFO source
`64.181.243.47` is the NAT public IP, not a controller's public VNIC address.

The live audit found six peers, including SFO-2 and SFO-3 beyond the ticket's
initial four. Every peer answered NetBird SSH and reported management,
signal, STUN and secure WebSocket relay available. Established daemon TCP
443 sockets went to `10.250.10.155` from all three GRU nodes and
`163.176.73.79` from all three SFO nodes. NetBird geolocates the connection's
source IP: private sources `10.251.0.11`–`.13` have no public location, so
Unknown/no country flag is expected. A flag is not a connectivity check.

## Proposed uniform policy and decision required

The COS default is private preferred for every server region: one FQDN with
private DNS answers over the independent OCI private network, plus automatic
public recovery when that path fails. User laptops continue to use public
DNS. Keep the FQDN and TLS verification identical on both paths. Public
fallback means servers may also use the public endpoint during an outage;
it cannot be strictly laptop-only then.

This requires three things that are currently absent:

1. **Manager transit and return path.** TS-668's DRG/RPC link routes the cell
   subnets `10.251.0.0/25` and `10.252.0.0/25`, admitting TCP 7422/9443. SFO
   has no private route to `10.250.10.155/32`. GRU's LPG is not proof that the
   DRG transits through it. A reviewed manager-VCN attachment/transit and
   return-path design is needed. Changing the manager's VCN would need an
   explicit exception to this ticket's ts-ops exclusion.
2. **Independent public egress.** Live GRU has an available NAT gateway
   (`163.176.30.185`) and a default route, despite the older foundation
   runbook. Its security list permits private manager TCP 443/UDP 3478 but
   omits the public manager `/32`. Verified public TLS attempts time out on
   all three GRU nodes; SFO's public TLS succeeds. Add narrow, owned egress
   rather than assuming a DNS change creates a working fallback.
3. **Health-based resolution and reconnect.** A private-only hosts entry
   has no public fallback. Two DNS answers do not enforce private preference
   or equal selection across gRPC, WebSocket and UDP clients. The resolver
   and reconnect mechanism must recover without depending on the NetBird
   mesh it is repairing, preserve established SSH/mesh sessions, and prove
   private failure, public recovery and restored-private recovery live.

The alternative is uniform public control-plane access through regional NAT.
It avoids private-link bootstrap dependencies and manager-VCN transit, but
still needs the GRU egress allowance and gives up the private preferred
default. This is a policy trade-off requiring a user decision. No path policy
has been applied by this draft.

All changes must enter through reviewed cell configuration and authenticated
ts-orchestrator operations; no manual hosts, DNS, firewall or OCI route edits.
The current signed cell spec has no NetBird path-policy section or reconciler.
Image configuration and the once-per-boot enrollment service alone do not
enforce live failover. Coordinate the implementation with TS-674's 0.80
client lifecycle and TS-675's address reservations and scoped DNS.

## Read-only path audit

Build the operator CLI at low CPU priority, then use the operator's existing
NetBird client. The server needs its existing `netbird`, `jq`, `getent`, `ss`
and `systemctl`; nothing is installed or restarted.

```bash
nice -n 19 make build
NB='sudo -n netbird-wt0' scripts/netbird-control-plane-audit.sh \
  --vault-id <automation-vault-ocid> --expected-ip 10.250.10.155 \
  --node ts-gru-1 --node ts-gru-2 --node ts-gru-3 \
  --node ts-sfo-1 --node ts-sfo-2 --node ts-sfo-3
```

Use current NetBird peer names if a rename is incomplete. Without `--node`,
the CLI discovers all server peers from the operator's NetBird status; an
empty selection fails. On hosts using `ts-netbird-ops`, set `NB` to the
existing `nsenter` client command described in
[the NetBird runbook](../../deploy/netbird/README.md#operator-automation-peer).
Do not use `podman exec` for NetBird SSH.

Exit 0 means every **selected** peer answered NetBird SSH, management and
signal are connected to the common HTTPS name, a secure WebSocket relay is available,
host resolution matches the reviewed IP, and every observed daemon TCP 443
socket uses that IP. Mixed, missing or unreadable observations fail. Run
explicitly against the complete cell inventory for acceptance coverage.
An available QUIC/unknown relay transport fails because this audit cannot
prove its UDP destination. The baseline full selection fails for either destination because the
regions currently differ. Separate regional audits can establish the
current private GRU and public SFO paths.

This audit does **not** prove STUN packet routing, mesh ICMP, TerraBase
replication or failover. It must not be used as the full TS-676 acceptance
gate. Those checks remain to be implemented with the chosen path policy.

## Rollout and acceptance prerequisites

TS-674's 20:27 UTC coordination records an active TS-632 GRU hold: a node
rename is stuck, one TerraBase member is fenced/down, and only two of three
serve. TS-632 owns GRU spec writes until it posts `gru-1 clear`. Before a
rollout, re-read that ticket and require no running node operation/fence and
an inactive rollout. Never re-found a serving cell or restart its NetBird
daemon through the only access session.

After the hold clears and the policy is approved, roll one region and one
node at a time through ts-orchestrator. Capture fresh checks before and
after each change:

1. Complete server inventory, manager-seen source IP, actual management,
   signal and relay destinations, and STUN path evidence.
2. NetBird SSH and literal mesh ping in both directions. Current desired
   policies admit SSH and TCP 7422/9443, not server ICMP; a narrowly scoped
   ICMP policy is a prerequisite, not a reason to call a TCP probe a ping.
3. In-region TerraBase replication and the GRU/SFO two-way write/read
   checks. Latest TS-668/TS-643 evidence says the interregion NATS leaf/WAN
   replication is not yet live. A green WAN baseline is required first.
   Do not route replication checks through ts-ops.
4. A bounded private-manager failure drill with an independent access path
   and automatic restoration. Prove public reconnection, continued SSH,
   mesh ping and replication, then restore the private path and repeat.

The eventual acceptance script must exit nonzero for missing prerequisites
or skipped checks. The diagnostic audit's success alone cannot close TS-676.
