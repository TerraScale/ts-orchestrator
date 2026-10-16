# TS-674 live NetBird evidence, 2026-10-07

This is a **before-upgrade** record. This inventory was read-only: it did
not drain, restart, upgrade, re-enroll or re-found a node, or change a
development-host configuration. There is no after-upgrade result
yet: the live prerequisites below must pass first.

## Current agents and target

Target: [NetBird v0.80.0](https://github.com/netbirdio/netbird/releases/tag/v0.80.0).
The repository's reviewed image input pins the release archive and extracted
binary checksums. Every inventoried node below is ARM64. CLI and daemon
versions were both `0.79.0`, with daemon status `Connected`, at
2026-10-07 20:54:09–20:54:11 UTC.

| NetBird peer | OCI display name | OS hostname | NetBird address | OCI private address | Before |
| --- | --- | --- | --- | --- | --- |
| ts-gru-1 | gru-1-ctl-1 | gru-1-ctl-1 | 10.200.87.215 | 10.251.0.11 | 0.79.0 |
| ts-gru-2 | ts-gru-2 | gru-1-ctl-2 | 10.200.38.135 | 10.251.0.12 | 0.79.0 |
| ts-gru-3 | gru-1-ctl-3 | gru-1-ctl-3 | 10.200.168.164 | 10.251.0.13 | 0.79.0 |
| ts-sfo-1 | ts-sfo-1 | ts-sfo-1 | 10.200.112.213 | 10.252.0.11 | 0.79.0 |
| ts-sfo-2 | ts-sfo-2 | ts-sfo-2 | 10.200.122.37 | 10.252.0.12 | 0.79.0 |
| ts-sfo-3 | ts-sfo-3 | ts-sfo-3 | 10.200.63.195 | 10.252.0.13 | 0.79.0 |

GRU peer names do not imply that OCI or host renaming has completed. Verify
the instance identity, private address and host grant again before acting.
The initial inventory found no public address on any of these six nodes.

## Rollout gates at 20:54–20:56 UTC

**DNS now passes.** Every controller resolved all six
`ts-{gru,sfo}-{1,2,3}.nb.ts.internal` names through native `getent ahostsv4`
to the addresses above. This changes the initial 20:33 inventory, when
controller DNS failed and same-cell peers were absent. Same-cell peers now
appear in status, often `Idle`; that status alone does not establish TCP
reachability. The three operator hosts also resolve the NetBird names while
retaining Tailscale MagicDNS.

**Service and recovery gates still fail.** Both representative same-cell
probes below used `nc -z -w 3` from the controller source, not from an
operator device. `Blocked` means that no TCP connection completed within
three seconds; it does not distinguish ACL rejection from timeout.

| Source → target | Target OCI SSH :22 | Target OCI NATS :4222 | Target NetBird :22/:4222/:8080/:9465 |
| --- | --- | --- | --- |
| ts-gru-2 → ts-gru-1, 20:55:32 UTC | Blocked | Open | All blocked |
| ts-sfo-2 → ts-sfo-1, 20:55:33 UTC | Open | Open | All blocked |

The target NetBird ts-auth `/readyz` and TerraBase `/readyz` requests returned
no HTTP response from both controller sources. NATS listens only on each
node's **OCI private address:4222**, using TLS-first/mTLS; it does not listen
on the NetBird address. The inspected GRU2 NATS certificate names
`controller-b` and `10.251.0.12`, not its NetBird IP. An open OCI NATS port is
not evidence that NATS works over the mesh.

All six local ts-auth `http://127.0.0.1:8080/readyz` probes returned HTTP 200.
Local TerraBase `https://127.0.0.1:9465/readyz` returned 200 on GRU1, GRU3
and all SFO nodes. **GRU2 has no TerraBase :9465 listener** and returned no
HTTP response. The TerraBase diagnostic used `curl --insecure` solely to
separate application readiness from certificate-name configuration; it is
not a verified TLS or mesh-health result. All six dashboard listeners were
still `127.0.0.1:9463`; operator requests to the GRU1/SFO1 NetBird dashboard
addresses failed to connect.

The initial inventory proved conventional `ubuntu@10.252.0.11` SSH from
mariogk-dev through untouched SFO2 as a TCP relay, using the existing owner
key. It returned `ts-sfo-1`, `ubuntu`, and `sudo -n netbird version` =
`0.79.0`. The target host key matched an independently observed NetBird SSH
host key. This target-VCN path does not depend on the target NetBird daemon,
but requires the relay to remain connected. Recheck it for each SFO target.
GRU still has no verified independent target SSH path. The initial OCI
Bastion lists were empty in both control compartments and the TerraScale
parent compartment; this refresh did not create a Bastion or alter ingress.

## Operator and development hosts

Existing root-owned operator configurations on mariogk-dev are
`/var/lib/terrascale-operator/operator.json` for GRU and
`/var/lib/terrascale-operator-sfo/operator.json` for SFO. Their NATS URLs name
the OCI private addresses. TLS, signing and credential files remain beside
the configurations; no credential or private-key contents were printed.
Use transient `--nats-forward` mappings when direct private access is
unavailable. The current node binary runs through
`/var/lib/terrascale-orchestrator/current/terrascale-orchestrator`; existing
artifact delivery uses the signed NATS artifact store and host-session
chunk downloads.

| Development host/client | Before | Observed state | Tailscale address |
| --- | --- | --- | --- |
| delta, NixOS netbird-wt0 | v0.71.4 | Connected, 10.200.87.10 | 100.77.52.68 |
| beta, NixOS netbird-wt0 | v0.71.4 | Connected, 10.200.186.149 | 100.115.156.95 |
| mariogk-dev, NixOS netbird-wt0 | v0.71.4 | NeedsLogin, no NetBird IP | 100.89.133.91 |
| mariogk-dev, ts-netbird-ops container | 0.79.0 | Connected, 10.200.35.107 | Same host |

Development-host observations were refreshed at 20:53–20:54 UTC. All three
Tailscale peers were online, SSH access worked, and `sudo -n` was available.
Native NetBird DNS and the beta Tailscale FQDN resolved on delta and
mariogk-dev. The NixOS client and operator container are distinct clients;
updating only the container leaves mariogk-dev's system client unchanged.

**NEEDS-USER — NixOS configuration scope.** The system closures identify
HomeLab configuration; the documented module is HomeLab
`fleet/nix/modules/common/netbird-vm.nix`. `/etc/nixos` is empty on
delta/beta, and mariogk-dev's configuration has an empty imports list.
This ticket forbids touching homelab, so its source was not opened or
changed. Either authorize the specific NixOS NetBird module/package change
there or provide an approved configuration repository. Sudo availability
is not the blocker. Apply eventual host changes one at a time with a live
Tailscale session; do not replace NixOS binaries imperatively.

## Coordination and remaining acceptance

Ku TS-632 was marked Done, but its 20:48 UTC
comment records an active GRU rename waiting at `check`: the GRU2 TerraBase
member remains down until [PR #312](https://github.com/TerraScale/ts-orchestrator/pulls/312)
reaches its host agent. GRU1 and GRU3 serve. Do not drain another GRU node
while that leaves only two serving members.

TS-672's 20:50 UTC update reports native operator DNS fixed and
[PR #313](https://github.com/TerraScale/ts-orchestrator/pulls/313)
open; its dashboard listener/deployment dependency on TS-670 remains.
This refresh independently confirmed controller DNS, but did not confirm
server-to-server service or NATS access. TS-676's 20:46 UTC coordination
also reports GRU's manager pinned to private `10.250.10.155` and public
manager egress blocked; do not assume a public fallback during upgrade.

Before live rollout, verify GRU2 recovery and its drain quorum, an
independent SSH path for every target, and authenticated peer/service/NATS
mesh health. The managed reconciler must retain its fail-closed preflight.
After an authorized rollout actually completes, append each node's observed
after version, checks and rollback outcome here and to Ku TS-674. No
`0.80.0` live-upgrade acceptance is claimed by this record.

## Read-only refresh, 22:08–22:09 UTC

GRU2 and SFO2 still reported NetBird `0.79.0`. Both inspected controllers
resolved all six peer names. The representative same-cell mesh probes above
still failed on ports 22/4222/8080/9465; GRU OCI SSH22 remained blocked,
while SFO OCI SSH22 was open. GRU2 still had no TerraBase :9465 listener.
No host, configuration or network was changed by this refresh.

TS-632's 22:16–22:18 UTC coordination still held GRU generation 5 frozen
and GRU2's TerraBase member down. Its recovery also awaits a qualified main
release; TS-670 owns the separate main-CI deadline fix in PR #320. Keep
the NetBird pin unapplied until the recovery and mesh health gates pass.

## Implementation update (2026-10-08)

PR #319 now supplies the authenticated mesh NATS client listener and
same-cell TCP health policies for ports 4222, 8080 and 9465. The listener
shares the OCI path's mTLS, JWT and authority-ticket gate; removing or
rebinding it closes its mesh sessions without closing OCI sessions. These
changes address the code gap observed above, but this implementation has
not yet been deployed to the six servers or their manager policies. The
historical before/current observations above remain unchanged; obtain fresh
OCI recovery, controller quorum, backend and mesh-health evidence before
activating the live pin. No serving node was drained or upgraded.
