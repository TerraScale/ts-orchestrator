# TS-550 gru-1 re-found and live rollout, 2026-10-06

Executed under the user's blanket pre-approval relayed by COS. No secret,
token, key or passcode appears here; Vault secrets are named by name and OCID.

## Outcome on `ts-550-gru-refound-6` (verified 2026-10-06T08:34Z to 08:45Z)

| Check | Result |
|---|---|
| `https://gru.api.terrascale.tech/healthz`, `/readyz` | 200, `{"status":"ready","version":"0.1.0","region":"gru-1"}` |
| `/openapi/v1.json`, `/scalar/` | 200 |
| `/` | 302 to `/scalar/` |
| `https://gru.auth.terrascale.tech/readyz` | 200, `0.1.0+f8e359658198` |
| `…/terrascale/.well-known/openid-configuration` directly, and via `https://auth.terrascale.tech/terrascale/…` | 200, issuer `https://gru.auth.terrascale.tech/terrascale` |
| `https://dash.terrascale.tech/health/ready` | `{"status":"ok","version":"15826c9e…","backend":"terrabase"}` (Fly release 90) |
| `dash/login` | to `gru.auth/terrascale/oauth/authorize` (client `ts-dashboard`, PKCE S256, redirect `https://dash.terrascale.tech/login/callback`), then 302 to the ts-auth sign-in page (200, "Sign in · ts-auth") |
| ts-auth JWT smoke test, 08:41:57Z | `client_credentials` (`ops-smoke`, HTTP Basic) 200; claims `iss https://gru.auth.terrascale.tech/terrascale`, `aud https://gru.api.terrascale.tech`, `sub ops-smoke`; `GET gru.api/v1/management/organizations` with it 200, without a token 401 |
| KV snapshots | `gru-1-head/kv-snapshot/v1/gru/TS_HOST_ENROLLMENT.json` (08:31Z), `TS_SERVICE_SET.json` (08:39Z) |
| Release channel bridge | no `OCI region "GRU" is not in the region catalog` since boot (#220) |

## Re-found 6, 2026-10-06T07:37Z to 08:45Z

COS's audit decisions, applied in this re-found:

1. **Material cap.** #220 raises `bootstrapmaterial.MaxValidity` from 30 to
   365 days. The attempt ran with `validity_days` 364: the NATS CA, the
   controller, operator and host issuer certificates are valid to
   **2027-10-05T07:40:06Z**; the TerraBase member CA to 2036-10-03. TS-568
   adds in-place renewal and shorter leaf lifetimes later.
2. **Rollouts.** The signed controller configs keep `kv_snapshot` on and
   leave `controller.rollouts` unset. Unset is the production default
   (`rolloutSettings`): enabled, executor, `allow_scoped_auto_sign` and
   channel on, and an executor that cannot start only logs. An explicit
   `executor: true` would stop a production controller from starting
   (`rollout_control.go:80`). The operator grant keeps
   `can_roll_out_orchestrator`, and the new material carries the controller
   JWT grant for `rollout.proof.*` (`natscell.ControllerSubscriptions`).
   #220 also fixes the release channel bridge: it opened Object Storage
   with the fleet code `GRU` instead of `sa-saopaulo-1`, so no controller
   could read the CI channel.
3. **Fleet owner.** `oci-region.json` `owner` is now the cell prefix
   `gru-1`, not the deployment ID (#220). The db hosts' `terrascale-owner`
   tag still comes from the bound plan's `orchestrator_owner`
   (`ts-470-gru-rebuild-2`); that belongs with TS-569.

- Orchestrator `main` `8ea7e6ca` (CI run 1251); image `gru-1-arm64`
  `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaa7tc7yxcpwsthwxtb5blkxijbrlnskfjiuvr26ltmvady3wam4hya`,
  booted by all five servers.
- Cell spec generations, each root-signed: 1 TerraBase with the Management
  credential only; 2 ts-auth with its seven Vault refs (including
  `TS_AUTH_SERVICE_CLIENTS`) and 2 replicas; 3-5 host grants
  `gru-1-ctl-1..3`; 6 the TerraBase auth issuer and audience, once ts-auth
  served. The order avoids the readiness deadlock below; no outage.
- TerraBase `b9d16432` ready on 2 members; ts-auth `f8e35965` ready on 2
  replicas.

| Server | Instance (prefix `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc`) |
|---|---|
| gru-1-ctl-1 | `…gmt5zbqdtxativqkabodmmmghpd64ujne7kmyhzrzpda` |
| gru-1-ctl-2 | `…xkk6q5dov3tf7q2346htwvywd5o2tuavfg7oto22ll2a` |
| gru-1-ctl-3 | `…svkeuw5rp4ussdhfh4ydt4xye5p5ax7vzvhudabph24q` |
| gru-1-db-1 | `…55ubtmrgmbeg72idbmt6kpqcqtinhh75zhbawtixmcpq` |
| gru-1-db-2 | `…jm4es7cylnahqmgdiyjhwgiql7nnken6et4occblpepq` |

Downtime: `gru.api`, `gru.auth` and the dashboard from 07:37Z (terminate)
to 08:34Z (`gru.api`), 08:39Z (`gru.auth`) and 08:41Z (dashboard).

What a re-found still needs by hand (each a follow-up for TS-569 or the
plan code):

- **Egress.** The attempt's preview refuses any NAT gateway, its public IP
  and route or security-list rules outside the plan. `gru-1-nat`, its route
  and the 15 Cloudflare egress rules were removed before `material` and
  recreated after `members` (`restore-egress.sh`). New NAT gateway
  `ocid1.natgateway.oc1.sa-saopaulo-1.aaaaaaaafgmtdw5enzeez26p5rq44xbi3fe3kqouxhu43qfu5cmcaotq2rqa`.
- **Member CA on the load balancer.** The preview wants the `terrabase`
  backend set on the plan's `member-ca` bundle; it was pointed back there
  for the attempt, then at the new bundle `member-ca-refound-6`
  (SHA-256 `0F:5D:AD:55…`).
- **KV snapshots of the old cell.** The new cell would restore the old
  cell's spec and host enrollments. The two objects were deleted after the
  old controllers stopped (07:39Z); the bucket keeps their earlier versions.
- **Tenant secrets.** The re-found reset TerraBase, so `ouroboros bootstrap`
  stopped on the stale project IDs in Vault, as designed. New current
  versions (version 2) of `gru-1-ts-auth-terrascale-{project-id,api-key}`
  and `gru-1-ts-dashboard-terrabase-{project-id,api-key}` were written from
  the new tenant (an admin-listener key for each project), then
  `ouroboros bootstrap` passed with nothing to create. New organization
  `terrascale` `01a11059-a8df-7b4d-b9b9-ac5ba2d25c35`, projects `ts-auth`
  `01a11059-a955-…` and `ts-dashboard` `01a1105a-7350-…`.
- **Per host:** the ts-auth metadata firewall on `gru-1-ctl-1..3`, the
  Management credential file on both db hosts, and the ten ts-auth
  collections.

## Deployment `ts-550-gru-refound-5` (superseded by re-found 6)

- Orchestrator `main` `b545cea8` (CI run 1181), arm64 `117316bb…`; image `gru-1-arm64` `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaa7huraewddqokz55x4sgxwjeuu7iqldewan4xukqwxrciujdqqq`.
- Fresh material, anchor valid to 2026-11-05 (30 days, the maximum). Controller material has no in-place rotation yet.
- Signed controller config: `mariogk` grant `terrabase`, `ts-auth`, `can_register_hosts`, `can_roll_out_orchestrator`; base TerraBase profile; `kv_snapshot` on `gru-1-head` (#190).
- Cell spec generations, each root-signed (`release sign-spec --root`):
  1. TerraBase adds the Management credential, ts-auth issuer and audience.
  2. ts-auth: committed profile with six Vault secret refs, 2 stateless replicas.
  3-5. Host grants `gru-1-ctl-1..3` (`10.251.0.11-13`, `ts-auth`, `canary`).
  6. Auth issuer removed (see "TerraBase readiness needs ts-auth").
  7. Auth issuer restored once ts-auth served.

| Server | Instance |
|---|---|
| gru-1-ctl-1 | `…g3cpvew3d6ffo6vpnp5h2v2lksvci2xd2r3duadejpfa` |
| gru-1-ctl-2 | `…ubtlih7nvfrd3ve7w3mwkox2bxhrov2qxpymbanvvyoa` |
| gru-1-ctl-3 | `…hl4jn6gdwiovhzhbqhqilcs5r4ev4fiowm5fb6zpwnpa` |
| gru-1-db-1 | `…4lwtsyct6eoovo6xxiicgu7tt52ce4snaxx3mw4pqwda` |
| gru-1-db-2 | `…mhhuk77zcsg3towfbxpl5hu7lbcuj2foejstkdgnt26a` |

(prefix `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc`)

`operator hosts`: three controller hosts with role `ts-auth` (enrolled through
their host grants, #178) and two TerraBase hosts, all with current sessions.
TerraBase `b9d16432` (`7da6542c…`) generation 3 `ready` on 2 members; ts-auth
`f8e35965` (`e7f8a5ff…`) generation 2 `ready` on 2 replicas.

## Live changes outside the attempt

- Load balancer `gru-1-api`: certificate bundle `member-ca-refound-5` added (`CN=TerraBase member CA gru-1`, SHA-256 `46:29:E3:58…`); backend set `terrabase` points at it (TLS 1.2, peer verify on). The old `member-ca` bundle is kept, unused.
- Egress: NAT gateway `gru-1-nat` `ocid1.natgateway.oc1.sa-saopaulo-1.aaaaaaaadpthctgcrzhkfzyzccgehps4q7vmc3qgdhmq7wmzfwxfl43ahueq`; route `0.0.0.0/0` added to `gru-1-private-routes`; 15 security-list egress rules (TCP 443 to Cloudflare's IPv4 ranges) added to `gru-1-private-security`. Checked: `gru.api` and `gru.auth` reachable from the cell; Google, GitHub and Oracle time out.
- ts-auth metadata firewall on `gru-1-ctl-1..3` with the DNS exception (#210).
- Vault (names): `gru-1-ts-auth-{master,audit-signing,operator}-key`, `gru-1-ts-auth-dashboard-client-secret`, `gru-1-ts-auth-terrascale-{api-key,project-id}`, `gru-1-ts-dashboard-terrabase-{api-key,project-id}` (control compartment); `gru-1-terrabase-management-credential`, `gru-1-ts-dashboard-csrf-secret` (`TerraScale`).
- TerraBase tenant (phase A): organization `terrascale` `01a10fec-3981-7b7a-9128-c783f9bf62a1`, projects `ts-auth` (database `auth`) and `ts-dashboard` (database `dashboard`). The ten collections ts-auth requires were created in `auth` (ts-auth's `AuthStore.ProvisionAsync` is an operator step nothing ran).
- Fly `ts-dashboard`: `TERRABASE_URL`, `TERRABASE_API_KEY`, `TERRABASE_PROJECT_ID`, `TERRABASE_DATABASE`, `TS_AUTH_ISSUER`, `TS_AUTH_CLIENT_ID`, `TS_AUTH_CLIENT_SECRET`, `TS_AUTH_REDIRECT_URL`, `TS_DASHBOARD_CSRF_SECRET`; `import-org --org terrascale --owner-email mariogk@terrascale.tech` imported the organization with 2 projects.

## Removed

| Kind | Name | OCID |
|---|---|---|
| instance + boot volume | gru-1-ctl-1..3, gru-1-db-1..2 (`ts-470-gru-rebuild-2`) | see `terminate-targets`: `…6isx5cda`, `…by4umriz5faua`, `…rz6trb2cdnq`, `…mqfi7rvn5va`, `…l7pq`; boot `…scvvh5a`, `…k4asmba`, `…xrc32da`, `…ij46csq`, `…ci5mnaia` |
| instance + boot volume | gru-1-ctl-1 (`refound-3`) | `…sxxd6iowq6aa` |
| instance + boot volume | gru-1-ctl-1..3 (`refound-4`) | `…nz4ldyjsza`, `…hkg3ylnsy2a`, `…c44a2f45lk6a` |
| image | gru-1-arm64-555876d8 | `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaoickypqe57fklhk5s2qmmbxw3ensusrrs3edbkd3oq455rr5lhfa` |
| image | gru-1-arm64-e4f1de35 | `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaapqlmzaonvl6i2ml5gfnyp53uquym2vaaowmmpl6gqq2lwehtvkha` |
| image | gru-1-arm64-11c40cdc | `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaakefvjkzsbbfwbeptyjnwhhdryngtvfznxjrogmurpaxo7brmwhja` |
| instance + boot volume | gru-1-ctl-1..3, gru-1-db-1..2 (`refound-5`, re-found 6, 07:37Z) | `…2r3duadejpfa`, `…xpymbanvvyoa`, `…wm5fb6zpwnpa`, `…axx3mw4pqwda`, `…ejstkdgnt26a`; boot `…csckar3sxbcq`, `…y6czm3hosnwq`, `…42lauqu3zx3a`, `…qtoa2wajujbq`, `…4i6l652uvf6q` |
| image | gru-1-arm64-b545cea8 (`refound-5`) | `ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaaa7huraewddqokz55x4sgxwjeuu7iqldewan4xukqwxrciujdqqq` |
| NAT gateway (recreated) | gru-1-nat | `ocid1.natgateway.oc1.sa-saopaulo-1.aaaaaaaadpthctgcrzhkfzyzccgehps4q7vmc3qgdhmq7wmzfwxfl43ahueq` |
| LB certificate bundle | `member-ca-refound-5` on `gru-1-api` | unused since re-found 6 |
| objects (delete markers; versions kept) | `gru-1-head/kv-snapshot/v1/gru/TS_{HOST_ENROLLMENT,SERVICE_SET}.json` of `refound-5` | |

All terminations used `--preserve-boot-volume false`; the five boot volumes
left are attached to the re-found 6 servers. Retained, not deleted: the
ledger records of the earlier deployments (35-day retention) and their
Vault secrets.

## Production bugs found and fixed on the way

| PR | Bug |
|---|---|
| #192 | Preview admission allowed one public IP; the TS-486 LB's VIP stopped every attempt. |
| #194 | The config installer (CAP_CHOWN only) could not read TS-558's root chain in the controller's 0700 state directory: no controller could install its config. |
| #205 | TS-560 defaulted `controller.rollouts` before the signed config digest check: no controller could start. |
| #210 | The ts-auth metadata firewall dropped systemd-resolved's DNS to OCI's resolver (same address): controllers lost DNS and their instance principal. |

## TerraBase readiness needs ts-auth

With `TERRABASE_AUTH_ISSUER` set, TerraBase `/readyz` stays `unavailable`
until it has fetched ts-auth's signing keys, while ts-auth's own readiness
needs TerraBase through `gru.api`: a bootstrap deadlock. Generation 6 removed
the issuer to start the chain, generation 7 restored it after ts-auth served.
This needs a TerraBase change (readiness independent of the issuer, or a
bootstrap order the orchestrator drives).

## Self-update round trip, 2026-10-06T06:56Z to 06:59Z

No rebuild: each controller moved to `main` `dd5d6386` (CI run 1226,
arm64 `fc2932ae49d9c1423f1d9277e95f98a491a9dda46851607b052be7f58aee690a`)
in place. The update receipt was signed by the release leaf under a
root-signed binary update delegation (canary, GRU, arm64, lineage base
`b545cea8`, valid to 2026-11-05), then staged with
`selfupdate stage --allow-scoped-auto-sign` and activated with
`selfupdate activate --proof-window 10m --restart`, one controller at a
time with the seed last: gru-1-ctl-3, then ctl-2, then ctl-1. On each, the
restarted controller passed restart admission (TS-552) and signed its
version proof, and the watchdog confirmed: `activation.json` was removed,
`current` and `known-good` name `fc2932ae…`, and the controller is active.
The controllers' host agents were restarted onto the same release
(`/proc/<pid>/exe` = `fc2932ae…`).

## Spec generations 8 and 9: ts-auth outage, 07:01Z to 07:07Z

Generation 8 added a `TS_AUTH_SERVICE_CLIENTS` Vault ref
(`gru-1-ts-auth-service-clients`, one client `ops-smoke`) for the JWT smoke
test (#214 allows the ref in a profile). The host's own launch check still
required exactly six secrets, so every replica failed and `gru.auth` answered
502 for about six minutes. Generation 9 restored the previous profile, and
the re-release reached `ready` on 2 replicas; `gru.auth` answered 200 again at
07:07:52Z. #218 fixes the host check.

## Smoke test, 2026-10-06T07:18Z

After #218 the controllers moved in place to `main` `423a8b15` (arm64
`899f442b…`, CI run 1235): ctl-3, ctl-2, then ctl-1, each confirmed by its
watchdog, and each host agent restarted onto it. `gru.api` and `gru.auth`
stayed 200 throughout. Spec generation 10 (root-signed) added the
`TS_AUTH_SERVICE_CLIENTS` ref, and ts-auth reached `ready` on 2 replicas.

```text
dash/login                      -> 303 gru.auth/terrascale/oauth/authorize?client_id=ts-dashboard&...&redirect_uri=https://dash.terrascale.tech/login/callback
gru.auth authorize              -> 302 /ui/terrascale/sign-in (200, "Sign in · ts-auth")
POST gru.auth/terrascale/oauth/token  grant_type=client_credentials, client ops-smoke (HTTP Basic) -> 200, expires_in 3599
  JWT claims: iss https://gru.auth.terrascale.tech/terrascale, aud https://gru.api.terrascale.tech, sub ops-smoke
GET gru.api/v1/management/organizations  with that JWT -> 200 {"items":[],"next":null}
GET gru.api/v1/management/organizations  without a token -> 401 {"error":{"code":"invalid_key"}}
```

## Open

- **Human sign-in.** ts-auth has no SMTP relay, so it delivers no passcode and nobody can finish signing in on the dashboard. Since #214 and #218 a profile can carry `TS_AUTH_SMTP_PASSWORD` as a Vault ref; an SMTP relay (for example OCI Email Delivery credentials and an approved sender) is still needed.
- **Phase B** (owner `mariogk@terrascale.tech`) needs the ts-auth users API (`/v1/{slug}/users`), which ts-auth `f8e35965` does not serve, and a signed-in user.
- **CI releases to gru-1.** The bridge now reads the channel (#220), but CI publishes nothing yet: the repository has no `TS_AUTO_DEPLOY_CELLS`, and gru-1 is a `canary` cell while `TS_AUTO_DEPLOY_ENVIRONMENT` defaults to `production`. CI also needs `TS_RELEASE_UPDATE_DELEGATION`, a root-signed update delegation for `canary`, `GRU`, arm64, lineage base `8ea7e6ca` or earlier (at most 31 days) (TS-560).
- **Re-found by hand.** See "What a re-found still needs by hand" above: egress, the LB member CA, old KV snapshots, tenant secrets.
- **Vault:** the controller material secrets of `refound-3`, `-4` and `-5` remain.
- **`ops-smoke`** service client (`gru-1-ts-auth-service-clients`) is for smoke tests only; remove it when no longer needed.
