# TS-675 live coexistence check, 2026-10-07

`ts-orch network check --all` ran from verified delta approximately
20:39–20:42 UTC, with the existing GRU automation Vault and
`--netbird 'sudo -n netbird-wt0'`. This used the TS-675 branch's working-tree
binary, before commit. It made read-only status, route, DNS and finite
reachability requests. No software, addresses, resolver settings or services
were changed by this command.

| Requested target | Verified OS hostname | Active route / DNS / reachability result | Outcome |
| --- | --- | --- | --- |
| delta | delta | Both IPv4/IPv6 meshes disjoint; suffix-scoped NetBird and MagicDNS; native names match peer IPs; NetBird TCP22 and Tailscale ping pass | OK |
| beta | beta | Same checks pass | OK |
| mariogk-dev | mariogk-dev | TerraScale automation-container identity selected; both meshes, resolver and live probes pass | OK |
| ts-gru-1 | gru-1-ctl-1 | NetBird cross-region TCP9443 and native DNS pass; Tailscale absent, no MagicDNS | FAIL |
| ts-gru-2 | gru-1-ctl-2 | NetBird cross-region TCP9443 passes; native NetBird DNS fails; Tailscale absent, no MagicDNS | FAIL |
| ts-gru-3 | gru-1-ctl-3 | Same regional checks as GRU2 | FAIL |
| ts-sfo-1 | ts-sfo-1 | NetBird cross-region TCP9443 passes; native NetBird DNS fails; Tailscale absent, no MagicDNS | FAIL |
| ts-sfo-2 | ts-sfo-2 | Same regional checks as SFO1 | FAIL |
| ts-sfo-3 | ts-sfo-3 | Same regional checks as SFO1 | FAIL |

The original command exited **1**. It incorrectly applied PC/client Tailscale,
MagicDNS and native NetBird-name requirements to regional servers. The user
subsequently clarified that Tailscale runs on clients/PCs, not TerraScale
servers. The server Tailscale absence in this historical table is therefore
intended, not an acceptance defect. The revised `--node` mode requires NetBird
reachability and disjoint routes, permits disabled server NetBird DNS, and
continues to reject DNS hijacking. PC/client checks still require both meshes.

TS-672's concurrent scoped-DNS work resolved the T3 failures recorded in the
[earlier host audit](ts-675-host-audit-20261007.md). The initial OCI audit had
DNS disabled on all regional nodes; GRU1's native DNS passed during this later
check. Changes in another ticket are time-sensitive; repeat the check after
its complete rollout. TS-674 owns the concurrent NetBird client update.

The checker does not prove application replication, idle container-network
uniqueness or the state of devices absent from its inventory. The independent
[OCI evidence](ts-675-oci-audit-20261007.md) established reciprocal PEERED
RPCs and GRU1↔SFO1 TCP9443 over both OCI and NetBird; no NATS7422 listener
existed. TS-668/TS-660 must supply cross-region replication proof. The offline
user laptop and other tailnet clients remain uninspected.

## Corrected fleet check, 21:41–21:44 UTC

After the client/server scope correction, the working-tree binary was rebuilt
and the thin shell wrapper ran read-only from verified delta:

```sh
scripts/check-network-coexistence.sh --all --host mariogk-desktop \
  --vault-id <existing GRU automation Vault OCID> \
  --netbird 'sudo -n netbird-wt0'
```

The command exited **0**, verifying all ten requested targets:

```text
OK mariogk-desktop (mariogk-desktop): disjoint routes; scoped NetBird DNS; MagicDNS; both meshes reachable
OK delta (delta): disjoint routes; scoped NetBird DNS; MagicDNS; both meshes reachable
OK beta (beta): disjoint routes; scoped NetBird DNS; MagicDNS; both meshes reachable
OK mariogk-dev (mariogk-dev): disjoint routes; scoped NetBird DNS; MagicDNS; both meshes reachable
OK ts-gru-1 (gru-1-ctl-1): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
OK ts-gru-2 (gru-1-ctl-2): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
OK ts-gru-3 (gru-1-ctl-3): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
OK ts-sfo-1 (ts-sfo-1): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
OK ts-sfo-2 (ts-sfo-2): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
OK ts-sfo-3 (ts-sfo-3): disjoint routes; NetBird DNS scoped or disabled; NetBird reachable
```

No Tailscale installation or enrollment credential is needed on the servers.
The [refreshed host audit](ts-675-host-audit-20261007.md) identifies the offline
`mariogk-laptop` as a known enrolled client still requiring its own check;
Tailscale-only devices are not required to enroll in TerraScale's mesh.
The [refreshed server audit](ts-675-oci-audit-20261007.md) also verified scoped
server DNS and TCP9443 over OCI private and NetBird paths. This result proves
the requested network checks, not application replication or serving health.
No host or network configuration was changed.
