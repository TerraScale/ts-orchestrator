# TS-578: colocate TerraBase and ts-auth on gru-1's controllers, 2026-10-06

Done. gru-1 moved its TerraBase members from `gru-1-db-1`/`-db-2` onto
`gru-1-ctl-1..3`, beside the controllers and ts-auth, all in place: every
node now runs a controller, a TerraBase member (ctl-1 the catalog primary)
and ts-auth, and db-1/db-2 are terminated.
Times are UTC. Probe: `gru.api` `/readyz`, `gru.auth` `/readyz` and an
unauthenticated Management request (401 expected), once a second.

## Code

| PR | Change |
| --- | --- |
| #251 | A cell spec host grant may list `terrabase` for the node `TERRABASE_PEERS` lists at its address; host restart hold (`terrabase-restart-hold`). |
| #253 | The hold covers any role (`<role>-restart-hold`): a ts-auth release writes every replica at once. |
| #254 | `host.role_memory_max_bytes`: a role's cgroup `memory.max` from host.json. |
| #259 | `tsauth.Replicas` 3: one ts-auth replica per node. |

## Live steps

| Time | Step |
| --- | --- |
| 15:14 | NSG adds: controllers 9443 from the 5 members, 9465 from the LB subnet, .18, .155, ctl-1..3; databases 9443 from ctl-1..3. |
| 15:23–15:31 | Self-update to `6aeb8a0f` (ctl-3, ctl-2, ctl-1, then db-2's host agent), each drained and watchdog-confirmed. |
| 15:34 | Cell spec gen 11 (root, `c22da808…`): peers += ctl-1..3, ctl grants `[terrabase ts-auth]`. |
| 15:35–15:47 | ctl-1..3 registrations gen 2 (`operator host-register`), host.json roles and `terrabase_root`. |
| 15:53–16:02 | TerraBase release R1, same build `c8c3aad8`, gen 6, db-2 held: `{"step":"ready","members":5}`. |
| 16:05–16:16 | ctl-1..3 added to `terrabase` and `terrabase-primary`. |
| 16:21–16:24 | db-1/db-2 drained and offlined in both sets. |
| 16:56–17:16 | Self-update to `d4c22641` (ctl-1..3). |
| 17:18 | Cell spec gen 12 (root, `1c1b5f64…`): peers ctl-1..3, catalog primary ctl-1, ts-auth endpoints ctl-1..3. Not yet released for TerraBase. |
| 17:18 | ts-auth release of `919316bd` with the gen 12 profile; ctl-2 and ctl-3 held. |
| 19:53–20:24 | ctl-2, then ctl-3 back in `terrabase` (full diff 0 before each). |
| 20:54 | db-1 drained and offline in `terrabase`; `terrabase` = ctl-1..3. |
| 21:57–22:06 | A false-positive auto re-add returned db-1 to `terrabase` (incident 5); drained and offline again. |
| 22:10–22:13 | Catalog primary to ctl-1: TerraBase release R2 (same build `c8c3aad8`, gen 7, gen 12 profile). See [Catalog primary move](#catalog-primary-move). |
| 22:20–22:28 | ctl-1, ctl-2, ctl-3 back in `terrabase` and `terrabase-primary`, each a follower of ctl-1 (ctl-1 the primary). |
| 22:59–23:03 | db-1/db-2 retired: LB backends removed, FULL boot-volume backups, instances and boot volumes terminated. |
| 23:17 | ts-orch auto-deploy to GRU paused (incident 6). |
| 23:19–23:40 | Self-update to `6b63e4c2` (#259), ctl-3, ctl-2, ctl-1, each behind LB fences. |
| 23:44 | Cell spec generation 1 (root, `a4153d68…`): gen 12 plus ts-auth replicas 3 (incident 8). |
| 23:44–23:47 | ts-auth on ctl-1: placed by the reconciler, checked, `10.251.0.11:8080` active in `ts-auth`. |

## Incidents

1. **15:27:03–15:27:26, gru.auth 502 (18 samples). Cause: TS-578.** ctl-1's
   ts-auth backend was drained 27 s after ctl-2's was undrained, before
   the load balancer served ctl-2 again. Fix: every drain now requires
   another backend whose every LB node's last check is OK.
2. **15:54:21–15:56:54, gru.auth 503/502 (80 samples); gru.api 200. Cause:
   TS-578.** R1 gave db-1 three empty peers. With write-wait (TS-575) db-1
   sent them its 47,626-group journal and every write waited 2 s for
   their acknowledgements. ts-auth's private endpoints (TS-577) prefer
   db-1, and its readiness probe timed out. Fix: db-1's 9465 rejected the
   controllers until its sender lag was 0; db-2 was restarted fenced the
   same way.
3. **16:06–16:26 and 17:00–17:20, dashboard sign-in broken (Fly logs:
   `404 unknown_collection`). Cause: TS-578.** ctl-1..3 lacked 11 empty
   collections that db-1/db-2 hold: `verification_tokens` (ts-auth `auth`),
   `access_tokens`, `api_keys`, `audit_events`, `checkout_sessions`,
   `device_grants`, `invitations`, `login_throttle`, `notifications`,
   `stripe_customers`, `stripe_organizations` (dashboard). They predate
   TerraBase #37, which replicates collection creates; TS-574 had created
   db-2's by hand. The pre-switch check compared document rows only.
   - **Rollback (COS, 16:26:41–16:29:13; resolved 16:30):** `terrabase` set
     to db-1 active; ctl-1..3 and db-2 drained and offline. Sign-out and
     sign-in worked again end to end.
   - **Re-broken by TS-578 at 16:58–17:14:** the controller self-update
     script fenced each controller's backends and then returned them to
     rotation without checking that they had been in rotation before, so
     it undid the rollback (ctl-1 16:58:51/17:00:38, ctl-2 17:04:53/17:06:43,
     ctl-3 17:12:18/17:13:59). COS rolled back again at 17:20:05–17:21:12.
     The script now restores only backends that were in rotation.
4. **17:26:34–17:26:52, gru.auth 503 (6 samples). Cause: TS-578.** The
   ts-auth unhold script returned ctl-2's new replica (storage on the
   controllers, failing on the missing collections) to the `ts-auth` set
   while it answered 503. Offline since 17:48:51; the script no longer
   returns a backend.

Not TS-578: 15:17:56–59 (TS-575's TerraBase release restarted both
members at once) and 15:33:20–21 (TS-577's ts-auth release restarted both
replicas at once). Single 5 s client timeouts, several per hour, also occur
without any change.

## Repair and checks before switching traffic again (17:49–18:05)

- The 11 collections were created on ctl-1 through its client listener with
  each project's key, rendered from the Vault on ctl-1 and shredded. #37
  replicated them to ctl-2/ctl-3.
- The catalog registers 3 databases (`auth`, `dashboard`, `atlas`); every
  member holds all 3.
- Collections and indexes: identical on all 5 members.
- Document counts per collection, 34 collections: identical on all 5
  members. Document rows except ts-auth's `storage_health` probes:
  byte-identical (sha256 `74a873aa…`, `5e27e141…`, `abe38738…`).
- Catalog `_system.db`, every document except usage counters: 41, sha256
  `6ecf12dd…` on every member.
- Dashboard: its `resolve session` query (`{"filter":{"eq":["/kind","record"]},"limit":1000}`)
  on all 19 collections, against every member: 95 × 200, identical results.
- ts-auth: its storage probe (create, read, conditional delete) with its own
  key, against every member: 201/200/200. ctl-2's replica with storage on
  ctl-1..3 is ready, 0 failed checks.

ctl-1..3 then went back one at a time while Fly logs were watched (above).

## Later incidents

5. **21:57:38–22:06:06, db-1 back in `terrabase`; no errors. Cause: TS-578.**
   The auto re-add watcher armed at db-1's removal fired on a dashboard
   `WARN resolve session … context canceled` (the client cancelled the
   request), a false positive. db-1 was drained and offlined again after a
   full diff (DIFF=0). The watchers ignore `context canceled` since.
6. **23:17:01, an automatic fleet deploy started; cancelled at 23:17:31,
   nothing signed or published. Cause: TS-578.** A `workflow_dispatch` re-run
   of `ci.yml` on main (main was red on flaky e2e tests) was green and
   dispatched `deploy.yml`, since `TS_AUTO_DEPLOY_CELLS` was `GRU`. The CI
   rollout restarts controllers and host agents without fencing LB backends,
   and a controller self-update restarts the node's TerraBase member and
   ts-auth. The variable was removed for the TS-578/TS-609 live work.
7. **23:37:21–23:37:23, gru.auth 503 (2 samples). Cause: TS-578.** While
   ctl-1's TerraBase member (the catalog primary) restarted for its
   self-update, ts-auth's readiness on ctl-2/ctl-3 failed instead of failing
   over to another member.
8. **23:21–23:44, controllers without the cell spec; no traffic impact.
   Cause: TS-578.** #259 made a controller require exactly 3 ts-auth
   replicas also when it loads the stored spec. Each updated controller
   rejected the stored gen 12 (2 replicas) and fell back to the signed
   config's generation 0 (no services, no host grants). Running workloads
   kept their persisted desired state. The only repair the registry accepts
   is the leader's next amendment, current+1: generation 1, gen 12's content
   plus ts-auth replicas 3. The cell's spec lineage restarts there.

Single 5 s client timeouts (22:16:49 mgmt, 22:18:43 api, 22:44:43 mgmt,
23:19:25 api) occurred with no change running.

## Catalog primary move

Decision 0009 failover, planned. No TerraBase test covers promoting a
follower, so it was first dry-run on a copy of db-2's data with the real
binary on loopback ports: ready in 2 s, a catalog write (an API key, in the
copy only) answered 201.

1. `terrabase-primary` routed to ctl-1 only; ctl-1 drained and offline in
   `terrabase`; ctl-2/ctl-3 held. Full diff 0 on all 5 members; ctl-1 at
   catalog sequence 3265, lag 0.
2. R2 landed at 22:12:53. It withdrew db-1/db-2 (a hold does not cover a
   withdrawal), and their members stopped; ctl-1 restarted as primary and
   was ready at 22:13:00. db-1's final journal head was 3265, the sequence
   ctl-1 had applied: no catalog group was lost. One mgmt 502 sample
   (22:12:53) while ctl-1 restarted.
3. ctl-1 back in `terrabase` (22:20). ctl-2 (22:23) and ctl-3 (22:26)
   unheld one at a time: each restarted as a follower of ctl-1, connected
   with lag 0, full diff 0, back in both sets.

## db-1/db-2 retirement

After 30 clean minutes (22:28–22:58: 1,248 probe samples, one timeout,
0 Fly store errors): backends removed from `terrabase` and
`terrabase-primary`; FULL boot-volume backups, tagged `ts-issue=TS-578`,
`delete-after=2026-10-13` (deletion: TS-628):

- `gru-1-db-1-retired-20261006`: `ocid1.bootvolumebackup.oc1.sa-saopaulo-1.abtxeljrzxpt6bsmmf3ieustujo6ioudb5e52e4kczzefxgx3c7kligkfikq`
- `gru-1-db-2-retired-20261006`: `ocid1.bootvolumebackup.oc1.sa-saopaulo-1.abtxeljrpqltvovmjxcyfxz7wqmrpt22oyhquzvc7iocoxed3urcv5i6rdsa`

Then both instances were terminated with their boot volumes (no block
volumes were attached). No reconciler relaunches them: the controllers'
build has no pool launch, and `cellscale` is a dry-run CLI.

## ts-auth on ctl-1

The controllers allowed exactly 2 ts-auth replicas; #259 makes it 3. After
the controllers' self-update and cell spec generation 1, the reconciler
placed release 6 (`ffb81859`) on ctl-1 while ctl-2/ctl-3 were held. Before
activation, ctl-1 matched ctl-2 on `/readyz`, OIDC discovery and JWKS
(byte-identical) and rendered the same sign-in form.

## State at 23:48

| Set | Backends |
| --- | --- |
| `terrabase` | ctl-1, ctl-2, ctl-3 (`:9465`) |
| `terrabase-primary` | ctl-1, ctl-2, ctl-3 (`:9465`) |
| `ts-auth` | ctl-1, ctl-2, ctl-3 (`:8080`) |

TerraBase `c8c3aad8` gen 7 (peers ctl-1..3, catalog primary ctl-1); ts-auth
`ffb81859` release 6 on all three; controllers and host agents `6b63e4c2`;
cell spec generation 1. No restart holds remain.

Open: the NetBird peers `gru-1-db-1`/`-2`, NSG rules for `10.251.0.21`/`.22`
and private DNS records of the retired hosts; re-enabling ts-orch
auto-deploy once its rollout fences LB backends; a load-time cell spec
check must not discard a stored, root-verified spec (incident 8); ts-auth
failover on a restarting member (incident 7).
