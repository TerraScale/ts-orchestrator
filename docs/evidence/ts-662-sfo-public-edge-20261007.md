# TS-662: sfo-1 public edge, TerraBase and ts-auth, 2026-10-07

TS-640 founded sfo-1 (three controllers in `us-sanjose-1`) but left no load
balancer, no DNS, no host agents and no workloads. This records how the edge
and the services came up, all through ts-orchestrator, and every object ID.
Times are UTC. gru-1 was not touched; `gru.api` and `gru.auth` answered 200
throughout.

## Timeline

| Time | Step |
| --- | --- |
| 14:52–14:56 | Controllers ts-sfo-3, -2, -1 self-updated in place from the founding build `9debb9b7` to main `1afa18af` (release `b0136e12…`, SFO update delegation, watchdog-confirmed). |
| 14:57 | Host agents enrolled on all three nodes once `host-setup` ran the self-updated release (drop-in below). |
| 15:08 | Origin CA certificate for `sfo.api`, `sfo.auth`, `sfo.orch` into Vault `sfo-1-api-origin` (`public-api cert --apply`). |
| 15:09–15:11 | `public-api apply`: network, NSG, load balancer `sfo-1-api` with `terrabase`, `terrabase-primary`, `ts-auth`, `ts-orch` and the `terrabase_routes` routing policy. |
| 15:12–15:14 | Cloudflare: configuration rule `ts-orch-sfo-1-api-ssl-strict` and three proxied A records (`cf` CLI). |
| 15:15 | Vault secret `sfo-1-terrabase-management-credential` (48 random characters). |
| 15:17 | Cell spec generation 2 (root, `e992212c…`): management credential as a secret file, artifact store 2 GiB, `release_fence` with role-owned sets, `machines_api`. |
| 15:17–15:23 | TerraBase release `1cad934d` (`dd86bf84…`, the build gru-1 runs): `{"step":"ready","members":3}`. |
| 15:24 | `sfo.api/healthz` and `/readyz` 200 through Cloudflare; `terrabase` and `terrabase-primary` OK. |
| 15:25–15:34 | JetStream over-reservation found and repaired (incident 1): generations 3 (`6c1d5174…`), 4 (`5d2efc33…`) and 5 (`ad64cd44…`). All three controllers serve the Machines API. |
| 16:05 | One `atlas publish` of `atlas-gru-1.json` (gru-1 + sfo-1); it went stale within minutes. |
| 16:14–16:16 | ts-auth prerequisites: `ts-auth secrets`, `ouroboros bootstrap` on ts-sfo-1 (org `01a11722-22a9-7fe2-b02e-f27b1546f99b`, ts-auth project `01a11722-248e-7ed5-9bb7-c4e4bd9596b6`), the metadata firewall on ts-sfo-1..3. |
| 16:30 | gru-1 cell spec generation 8 (root, `bc597160…`): only `atlas` added, from `atlas-gru-1.json`. gru-1's spec had lost the section in the TS-578 lineage reset, so nothing published. gru-1's leader publishes again; gru.api and gru.auth 200 before and after. |
| 16:48 | Main release `ci-90ad5472…-run-14919` (with #294), from a dispatched `ci.yml` run after three runner flakes failed the push run. |
| 16:51–16:54 | Controllers ts-sfo-1..3 self-updated to `90ad5472` (release `095f9717…`). Each node's host agent, and so its TerraBase member, restarted with it. |
| 16:56 | sfo cell spec generation 6 (root, `70b138ed…`): ts-auth service (3 stateless replicas, one per fault domain), host grants `[terrabase, ts-auth]`. |
| 16:58–17:03 | Host registrations generation 2 (roles `[terrabase, ts-auth]`, capacity 2 CPU / 5 GiB / 22 GiB), `host.json` roles and `ts_auth_root`, rolling host-agent restart (incident 4). sfo.api 200 throughout. |
| 17:04–17:09 | `operator ts-auth-release` of ts-auth `31c6bead` (`86390805…`, the build gru-1 runs): replicas aborted (incident 5). |
| 17:11 | ts-auth's 20 collections created in sfo's `auth` database; all three replicas ready; `ts-auth` backends healthy. |
| 17:14 | `ts-orch region verify sfo`: api, auth, load balancer and atlas PASS (exit 0). |

## Incidents

1. **JetStream reservations past `store_max_bytes`.** Generation 2 raised the
   artifact store to 2 GiB. The same second, ts-sfo-2 created the Machines
   API buckets `TS_APPS` and `TS_MACHINE_STATUS` (256 MiB each). Every
   controller then reserved 4319 of its 4096 MiB, and embedded NATS refused
   every stream update, even a shrink: ts-sfo-1 and -3 could not open
   `TS_APPS`, and the leader could not lower the artifact store. A
   controller restart would have hung re-opening its streams. Repair: drop
   `machines_api` (gen 4); delete the two empty buckets (0 values) with a
   controller's NATS identity; the leader then set the artifact store to
   1 GiB (2783 MiB reserved); re-add `machines_api` (gen 5, 3295 MiB). Fix:
   a spec's artifact store now leaves 2 GiB for the other reserving streams,
   and 2.5 GiB with `machines_api`.
2. **Host setup ran the baked binary.** The founding image's
   `host-setup.service` runs `/usr/local/bin/terrascale-orchestrator`, which
   refused `ts-sfo-N` names (fixed in #279), so no host agent could enroll
   and a self-update could not fix it. The drop-in
   `deploy/systemd/selfupdate/terrascale-orchestrator-host-setup.service.d/60-selfupdate.conf`
   runs the current release. It was installed on ts-sfo-1..3 by hand at
   14:57; #283 (TS-632) ships the same drop-in in the image and has
   `selfupdate prepare` install it on older hosts.
3. **Cloudflare token scope.** `oci-region dns` stops with HTTP 403: Vault's
   `gru-1-cloudflare-dns-edit-token` cannot read the zone's configuration
   rules. The same steps were made with the logged-in `cf` CLI.
4. **A grant change does not reach an enrolled host.** `host-setup` keeps
   credentials with more than 24 h left, and a re-run without `host.json`
   replays the cached first enrollment (roles `[terrabase]`). Roles reached
   the nodes only through `operator host-register` (generation 2) and a
   `host.json` edit, then a host-agent restart per node. `node-drain` refused
   to fence first: no ts-auth backend served yet.
5. **ts-auth's collections did not exist.** Every replica aborted with
   `TerraBaseNotFoundException: the collection does not exist`: nothing runs
   ts-auth's `AuthStore.ProvisionAsync`. The 20 `RequiredCollections` were
   created with ts-auth's own key (`POST
   /v1/projects/{project}/databases/auth/collections`); the replicas served
   on their next relaunch.

## Objects

OCI, `us-sanjose-1`:

| Object | ID |
| --- | --- |
| Load balancer `sfo-1-api` (public IP `146.235.234.34`, 10 Mbps) | `ocid1.loadbalancer.oc1.us-sanjose-1.aaaaaaaaybsw57uhoyzbdblsqsxyv77fa6aogt5b55jlvic6c4ta3e35imma` |
| Internet gateway `sfo-1-api-igw` | `ocid1.internetgateway.oc1.us-sanjose-1.aaaaaaaa4ohgjpbbcdvbfw4m6skayjnzlghjynp7jkywfw62rinofewjfosq` |
| Route table `sfo-1-api-routes` | `ocid1.routetable.oc1.us-sanjose-1.aaaaaaaaelhcs23mcybvcgar37vtent3fh65zorhpnaigysvylsg3kxdcp2q` |
| Security list `sfo-1-api-security` | `ocid1.securitylist.oc1.us-sanjose-1.aaaaaaaawrszej4wjhbvgldiztxmat4j3itvgk2luz7jlt4dcmgpd3x6gkva` |
| Subnet `sfo-1-api-subnet` (`10.252.0.128/26`) | `ocid1.subnet.oc1.us-sanjose-1.aaaaaaaamieag53lxryhqfiegen76u2bms2fd7s6ciw7bv3nqqujz4avkwbq` |
| NSG `sfo-1-api-nsg` (Cloudflare ranges on 80/443) | `ocid1.networksecuritygroup.oc1.us-sanjose-1.aaaaaaaa556cdvsxvxmv2jys5frqsslq3bj744iz5x4k7oymospbc7ksd4bq` |
| Vault secret `sfo-1-api-origin` | `ocid1.vaultsecret.oc1.us-sanjose-1.amaaaaaappuhpdqavyq6is3olbz223cslib5gegd6dgg5dg3civlskbxznna` |
| Vault secret `sfo-1-terrabase-management-credential` | `ocid1.vaultsecret.oc1.us-sanjose-1.amaaaaaappuhpdqas7gypegmgs6wgnn4wgw6z6x4xmxjbm5lc764xytyduqa` |

Cloudflare, zone `terrascale.tech` (`4cc466e19478c116fae7dc445a6d0911`):

| Object | ID |
| --- | --- |
| Origin CA certificate (`sfo.api`, `sfo.auth`, `sfo.orch`, until 2041-10-03) | `26663437175060695821584150704905288908153500643` |
| Configuration rule `ts-orch-sfo-1-api-ssl-strict` (ruleset `ca1fd87761ab4266a19c23e1de815891`, version 3) | `7c284cdd01d9472fbb4acc1b75030da1` |
| A `sfo.api.terrascale.tech` → `146.235.234.34`, proxied | `c934655adff612bbca51d33bc3bf294b` |
| A `sfo.auth.terrascale.tech` → `146.235.234.34`, proxied | `0e65d4c01f1574cdd57300e6302c579a` |
| A `sfo.orch.terrascale.tech` → `146.235.234.34`, proxied | `b5f4887904af3781d7953ae18920300d` |

Unchanged: zone Authenticated Origin Pulls (enabled, one active zone
certificate `a68331f0-3491-4c68-8cb3-264953efcc89`); no hostname
associations on the sfo names (error 1553).

## Edge ownership

`release_fence` in the sfo-1 spec names role `terrabase` for `terrabase`
and `terrabase-primary` and role `ts-auth` for `ts-auth`, so the leader's
edge reconciler keeps those sets equal to the role's replicas. `ts-orch`
(8444, the Machines API) keeps the controllers `apply` seeded.

## ts-auth

ts-auth `31c6bead` serves on ts-sfo-1..3 at `https://sfo.auth.terrascale.tech`
(issuer `https://sfo.auth.terrascale.tech/terrascale`), from the reviewed
`deploy/oci-region/ts-auth-sfo-1-profile.json`. It stores in sfo's own
TerraBase (organization `01a11722-22a9-7fe2-b02e-f27b1546f99b`, project
`01a11722-248e-7ed5-9bb7-c4e4bd9596b6`, database `auth`), so its users and
keys are its own, not gru.auth's. sfo's TerraBase accepts gru.auth tokens
(`TERRABASE_AUTH_ISSUER`, set by TS-640). It has no SMTP relay: us-sanjose-1
has no approved sender and sfo cannot reach the sa-saopaulo-1 relay, so it
logs mail instead of sending it.

## Verification

`ts-orch region verify sfo --plan <bound plan>`, 17:14Z, exit 0:

| Check | Result | Evidence |
| --- | --- | --- |
| api | PASS | `https://sfo.api.terrascale.tech/healthz` 200; status "ok", region "sfo-1" |
| auth | PASS | `https://sfo.auth.terrascale.tech/terrascale/.well-known/openid-configuration` 200; issuer `https://sfo.auth.terrascale.tech/terrascale` |
| load balancer | PASS | terrabase 3/3, ts-auth 3/3, ts-orch 3/3 healthy; `terrabase-primary` OK |
| atlas | PASS | `https://atlas.terrascale.tech/v1/discovery` lists sfo-1, health ok |
