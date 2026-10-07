# TS-675 NetBird and Fly address audit, 2026-10-07

Read-only observations collected between 20:20 and 20:35 UTC from
`mariogk-dev`. No manager settings, peers, policies, machines, WireGuard
connections, servers, or LAN configuration were changed. The NetBird PAT was
read from the current OCI Vault version into process memory; no secret value
or configuration file is included here.

## Ranges observed

| Network | Live range | Authority / source | Object ID |
| --- | --- | --- | --- |
| NetBird account IPv4 mesh | `10.200.0.0/16` | `GET https://netbird.terrascale.tech/api/accounts`, `settings.network_range` | Account `dau6o5ka0rgg00bijsig` |
| NetBird account IPv6 mesh | `fd9c:200:2182:65f2::/64` | Same response, `settings.network_range_v6`; IPv6 enabled for group `All` | Group `dau6o5ka0rgg00bijsjg` |
| NetBird advertised GRU subnet | `10.251.0.0/25` | `GET /api/networks/db1dl8ka0rgg00dt33mg/resources` | Network `db1dl8ka0rgg00dt33mg`; resource `db1dl8ka0rgg00dt33o0` |
| Fly organization private 6PN | `fdaa:2:ebb9::/48` | Machine and registered WireGuard peer addresses; [Fly 6PN address format](https://fly.io/docs/networking/private-networking/#6pn-addresses-in-detail), 16-bit `fdaa` plus 32-bit network identifier | Organization `personal`, ID `RVLZQkpYjPL7yTyD6ne82l5gq8TG4GOQO`, numeric ID `310161` |
| Fly current machine address aggregate | `fdaa:2:ebb9:a7b::/64` | `fly machine list --app <app> --json`, all nine apps; this is the observed aggregate, **not** the organization's allocation boundary | Individual machine IDs below |

The live manager reports version `0.80.0` in `GET /api/instance/version`:
`management_current_version: "0.80.0"`,
`management_available_version: "0.80.0"`,
`management_update_available: false`.

The account's two mesh ranges and Fly's organization range are pairwise
disjoint. They also do not overlap the supplied Tailscale IPv4
`100.64.0.0/10`, its standard IPv6 `fd7a:115c:a1e0::/48`, or the supplied
LAN `10.10.10.0/24`. OCI and host-side inventories determine whether another
actual route collides; this account audit alone cannot rule out arbitrary
client LANs in the rest of `10.0.0.0/8`.

## NetBird peers

`GET /api/peers` returned 12 peers. Eleven reported connected; the laptop
reported disconnected. Every IPv4 address was inside `10.200.0.0/16`, and
every reported IPv6 address was inside `fd9c:200:2182:65f2::/64`.

| Manager peer name | Peer ID | IPv4 address | Client version | Connected | DNS locally disabled |
| --- | --- | --- | --- | --- | --- |
| `beta` | `db0ls14a0rgg00dsufig` | `10.200.186.149` | `v0.71.4` | yes | yes |
| `delta` | `db0pi34a0rgg00dsvu40` | `10.200.87.10` | `v0.71.4` | yes | yes |
| `mariogk-desktop` | `db3ajcka0rgg00840u2g` | `10.200.89.33` | `0.80.0` | yes | no |
| `mariogk-dev-ops` | `db20sisa0rgg00dt6th0` | `10.200.35.107` | `0.79.0` | yes | no |
| `mariogk-laptop` | `dav01msa0rgg00binjc0` | `10.200.72.78` | `0.79.0` | no | no |
| `ts-gru-1` | `db2asvca0rgg00dtcmig` | `10.200.87.215` | `0.79.0` | yes | yes |
| `ts-gru-2` | `db2atica0rgg00dtcn30` | `10.200.38.135` | `0.79.0` | yes | yes |
| `ts-gru-3` | `db2au1ka0rgg00dtcnj0` | `10.200.168.164` | `0.79.0` | yes | yes |
| `ts-ops` | `dauk7uca0rgg00bik16g` | `10.200.106.253` | `0.79.0` | yes | yes |
| `ts-sfo-1` | `db33snca0rgg0083sl30` | `10.200.112.213` | `0.79.0` | yes | yes |
| `ts-sfo-2` | `db341cka0rgg0083sof0` | `10.200.122.37` | `0.79.0` | yes | yes |
| `ts-sfo-3` | `db341v4a0rgg0083sp7g` | `10.200.63.195` | `0.79.0` | yes | yes |

The manager associates `10.200.87.10` with `delta`, whereas the ticket's
host facts associate it with `mariogk-dev`. Do not use the manager peer name
alone to select a host for changes: compare the host's live interface,
hostname, and peer identity. `mariogk-dev-ops` is a separate operator
automation identity; see the [prior enrollment evidence](ts-547-netbird-operator-access-20261005.md).

## NetBird routing and DNS

`GET /api/routes` returned `[]`. `GET /api/networks` returned only `gru-cell`.
Its single subnet resource is enabled, address `10.251.0.0/25`. Its single
router `db1dl8ka0rgg00dt33pg` is enabled, metric `100`, masquerade `true`,
peer `dauk7uca0rgg00bik16g` (`ts-ops`), with no peer-group routers. There is
no SFO subnet resource or default route in these management objects.

| DNS object | Live configuration | Source / ID |
| --- | --- | --- |
| Peer DNS suffix | `nb.ts.internal` | `GET /api/accounts`, `settings.dns_domain` |
| Disabled DNS management groups | `gru-servers` and `sfo-servers` | `GET /api/dns/settings`: `db1dl8ka0rgg00dt33l0`, `db32uika0rgg0083s13g` |
| Nameserver groups | None (`[]`); no primary resolver configured through this API | `GET /api/dns/nameservers` |
| Custom zone | Enabled `gru.ts.internal`, search domain disabled, distributed only to `operators` | `GET /api/dns/zones`, zone `db1dl8ka0rgg00dt33ug`, distribution group `dau6qfsa0rgg00bijsrg` |

The zone's ten A records map controller names and `nats.gru.ts.internal`
to `.11`, `.12`, `.13` in `10.251.0.0/25`; member names and
`terrabase.gru.ts.internal` map to `.21`, `.22`. Record IDs are
`db1dl8ka0rgg00dt33vg`, `db1dl8ka0rgg00dt340g`, `db1dl8ka0rgg00dt341g`,
`db1dl8ka0rgg00dt342g`, `db1dl8ka0rgg00dt343g`, `db1dl8ka0rgg00dt344g`,
`db1dl8ka0rgg00dt345g`, `db1dl8ka0rgg00dt346g`, `db1dl8ka0rgg00dt347g`,
and `db1dl8sa0rgg00dt348g`, respectively.

These manager settings do **not** prove that an operating system resolves
MagicDNS correctly or uses suffix-scoped resolvers. Verify live resolver
state and lookups on each host/client. The laptop was offline, so its
coexistence could not be checked from these APIs.

## NetBird access policies

All eleven policies below are enabled. Their single rules are enabled,
action `accept`, unidirectional. There is no enabled default `All` policy.
The account's GRU and SFO server groups contain three controller peers each;
no TerraBase member peers appeared in this snapshot.

| Policy name | ID | Protocol / ports |
| --- | --- | --- |
| `operators-to-ts-ops-forgejo` | `dav0ij4a0rgg00bio38g` | TCP `22,443,2022` |
| `operators-to-ts-ops-ping` | `dav0jnsa0rgg00bio3vg` | ICMP |
| `operators-to-gru-cell-ops-ports` | `db1dl8ka0rgg00dt33r0` | TCP `22,4222,9465`, destination resource `db1dl8ka0rgg00dt33o0` |
| `operators-to-gru-servers-ssh` | `db1dl8ka0rgg00dt33sg` | `netbird-ssh` |
| `ops-automation-to-gru-servers-ssh` | `db20qtsa0rgg00dt6se0` | `netbird-ssh` |
| `operators-to-sfo-servers-ssh` | `db32uika0rgg0083s150` | `netbird-ssh` |
| `ops-automation-to-sfo-servers-ssh` | `db32uika0rgg0083s16g` | `netbird-ssh` |
| `gru-servers-to-sfo-servers-fabric` | `db38l44a0rgg0083vrog` | TCP `7422,9443` |
| `sfo-servers-to-gru-servers-fabric` | `db38l44a0rgg0083vrq0` | TCP `7422,9443` |
| `operators-to-gru-servers-dashboard` | `db3a0fca0rgg00840ig0` | TCP `9463`; sources `operators` and `ops-automation` |
| `operators-to-sfo-servers-dashboard` | `db3a0fca0rgg00840ihg` | TCP `9463`; sources `operators` and `ops-automation` |

These fabric policies demonstrate the intended fallback permissions, not
successful replication or NATS leafnode traffic. Those require application
and link checks on the live regions.

## Fly allocations

`fly auth whoami` returned `mariogk01@gmail.com`. `fly orgs list --json`
returned only `personal`. `fly apps list --json` returned nine apps, all in
that organization. The current WireGuard inventory contains 16 registrations
(five GRU, two IAD, nine CDG); every address belongs to `fdaa:2:ebb9::/48`.

Each machine has a provider-assigned `/112` subnet: mask the final 16 bits
of the current private address below. Fly documents that these private
addresses may change on reboot/migration, so use `.internal` DNS for durable
destinations and reserve the whole organization `/48` in the address plan.

| App | Machine ID | Region / state | Current private IPv6 address |
| --- | --- | --- | --- |
| `openbao-mariogk` | `48ed915ec32098` | GRU / started | `fdaa:2:ebb9:a7b:1f4:152c:ffb5:2` |
| `terra-scale-dashboard-pr-200` | `d8d137ec5d54d8` | GRU / stopped | `fdaa:2:ebb9:a7b:5c2:2a5b:b6e0:2` |
| `terra-scale-dashboard-pr-201` | `2863067f37e318` | GRU / stopped | `fdaa:2:ebb9:a7b:5c6:a232:1db4:2` |
| `terra-scale-dashboard-pr-202` | `8ed941ef7e1178` | GRU / stopped | `fdaa:2:ebb9:a7b:1c8:baee:6ec5:2` |
| `terra-scale-dashboard-pr-203` | `48e7455b5d1728` | GRU / stopped | `fdaa:2:ebb9:a7b:5c7:3a2a:8696:2` |
| `terra-scale-dashboard-pr-207` | `e82771db494528` | GRU / stopped | `fdaa:2:ebb9:a7b:5d3:5c5b:c3b9:2` |
| `terra-scale-dashboard-pr-208` | `6837932ce33218` | GRU / started | `fdaa:2:ebb9:a7b:5c5:bed1:fe83:2` |
| `ts-dashboard` | `d8d96000b74e78` | GRU / started | `fdaa:2:ebb9:a7b:1bf:eaac:d528:2` |
| `vw-mariogk` | `7817922cd12978` | GRU / started | `fdaa:2:ebb9:a7b:5d4:369f:9361:2` |

`fly status --app ts-dashboard --json` reported the machine's
`servicecheck-00-http-8080` check passing. This is dashboard health only.

| Registered Fly connection | Registration ID | Region | Private peer IPv6 |
| --- | --- | --- | --- |
| Latest `beta` interactive connection | `Lmnzb4xglD59QckQ9L84V8lzLYTYO72A3pN` | GRU | `fdaa:2:ebb9:a7b:81c:9b64:b644:b502` |
| Latest `mariogk-dev` interactive connection | `6q52MD6exQ091FVMoKL52LRbKAfk6gjN4KA` | GRU | `fdaa:2:ebb9:a7b:81c:ac72:1dcd:a702` |
| Latest `delta` interactive connection | `Lmnzb4xglD59QckQ9L84V8lzLYTQp79X67` | GRU | `fdaa:2:ebb9:a7b:81c:1bfc:95ce:e902` |
| Earlier `mariogk-dev` interactive connection | `K5VGln8yXqbYBcnYz435v3qb4Qs4J5XxXN` | GRU | `fdaa:2:ebb9:a7b:81c:cf4f:fbc:6f02` |
| `hermes-homelab-vm` interactive connection | `52jQz1oaxR0BkCVboG3xD3gYG4fv1N1kLAB` | GRU | `fdaa:2:ebb9:a7b:81c:8849:fde5:4102` |
| Desktop interactive connection | `9BDV0zGA7qXNxCKB7xG45GgpxZHRAxeqDvD` | IAD | `fdaa:2:ebb9:a7b:d0cd:0:a:102` |
| Desktop interactive connection | `52jQz1oaxR0BkCVboG3xD3gYG4fvvA82N5k` | IAD | `fdaa:2:ebb9:a7b:ce2:0:a:102` |
| Desktop interactive connection | `JZ5ebLqx9nDkVHJQ15XjPXYL54taRXRw1K` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:802` |
| Desktop static connection | `Lmnzb4xglD59QckQ9L84V8lzLYTyQoeYylk` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:702` |
| Desktop static connection | `kgyjV4xQqORGKI83eblRBl0QbxsGQkL4xbD` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:602` |
| Desktop static connection | `K5VGln8yXqbYBcnYz435v3qb4QswxJ2vaAV` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:502` |
| Desktop static connection | `b2aY3eVM1gj9wCBjznJlDJgOnRHzbpngxDm` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:402` |
| Desktop static connection | `g6JvgBwV18RojHl8VbqkQqejb0czAQ1vVNo` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:302` |
| Desktop static connection | `v8noyOejQ5wkBu4KnbMpjMeobJCOxpPXLb6` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:202` |
| Desktop static connection | `b2aY3eVM1gj9wCBjznJlDJgOnRHRvQq2jOl` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:102` |
| Desktop interactive connection | `7YbBPpaGK2zXwFw0a163V6Mo1JCz78y3wNy` | CDG | `fdaa:2:ebb9:a7b:1596:0:a:2` |

Registered connections do not prove a live host tunnel. Fly's WireGuard DNS
address for this network is `fdaa:2:ebb9::3`; the provider's in-machine DNS
service is `fdaa::3`. Keep any client resolver rule scoped to Fly's
`.internal` namespace rather than replacing the host's default resolver.
NetBird uses the more specific `nb.ts.internal` and `gru.ts.internal`
namespaces, so resolver rule precedence must be checked when all exist.

Machine API inventory does not expose guest IPv4 routes. Read-only
`fly machine exec` attempts to run `ip` and `cat` on `ts-dashboard` both
returned `No such file or directory`; those binaries are absent from its
image. Guest IPv4, DNS configuration, and any container-side bridge remain
unverified. No debugging package or tunnel was installed for this audit.

## Minimum safe path

Retain the already disjoint account IPv4/IPv6 ranges and Fly `/48` unless the
complete OCI/host inventory proves an actual collision. Document these as
dedicated reservations, validate future desired state against them, and
verify both meshes and DNS on every reachable host. This needs no manager
renumbering and preserves the existing ts-ops and user-client identities.

If a real collision requires a NetBird range change, the 0.80 API supports
`PUT /api/accounts/{accountId}` with `settings.network_range`; preserve all
other settings and onboarding from a fresh account read. The manager
transaction calls `reallocateAccountPeerIPs`, assigns new IPv4 addresses to
**all** account peers, stores them, and pushes account updates. The client
detects its own address change in `Engine.updateConfig`, cancels its client
context, and reconnects. There is no dual-range, region-scoped migration in
this account API; changing IPv6 likewise restarts affected clients.

Source evidence, pinned to the live manager version:

1. [0.80.0 accounts HTTP handler](https://github.com/netbirdio/netbird/blob/v0.80.0/management/server/http/handlers/accounts/accounts_handler.go#L337): parses both network settings.
2. [0.80.0 account update](https://github.com/netbirdio/netbird/blob/v0.80.0/management/server/account.go#L344): transaction-wide renumber, account peer update fan-out; [allocator](https://github.com/netbirdio/netbird/blob/v0.80.0/management/server/account.go#L2345) covers every peer.
3. [0.80.0 client](https://github.com/netbirdio/netbird/blob/v0.80.0/client/internal/engine.go#L1333): changed own IPv4/IPv6 address resets the client connection.

Consequently, an account renumber cannot satisfy an uninterrupted,
one-region-at-a-time migration by itself. It also changes ts-ops's overlay
address and user devices, so it requires an explicit interruption decision
before execution. A rollback renumbers again; it does not restore the old
per-peer addresses automatically. Do not use an account renumber as an
exploratory operation.
