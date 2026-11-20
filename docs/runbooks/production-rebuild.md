# Production cell rebuild

This records the November 19–20, 2026 production reset (C45). The reset
discarded TerraBase customer data, auth users, and dashboard data. GRU
restored public service first. Confirm the destructive scope and the release
and access prerequisites before using this sequence for another reset.

## Preserve operator access

- Keep the external GRU host `ts-gru-1`, its NetBird management store, and its
  monitoring services. Preserve its boot-volume backups and the existing
  Vault credentials, VCNs, NLBs, and reserved public addresses.
- Mount the dedicated OCI block volume at `/var/lib/ts-data` and bind
  `/var/lib/ts-data/ts-orch` to `/var/lib/ts-orch`. Check the mounts before
  starting the cell. The root disk still holds monitoring and the OS.
- Stop the old cell, NetBird service, and release-recovery timer on
  `ts-gru-1` within one logged systemd transaction. Keep the NetBird data
  and edge certificates when replacing the old orchestrator state. Verify
  an independent operator access path before stopping NetBird.

## Rebuild in order

1. Retire the old pool nodes and their old data volumes. Once all old
   writers stop, empty the approved R2 buckets
   `terrascale-{gru,sjc,fra}-files`, `terrascale-gru-terrabase`, and
   `ts-terrabase-shapes-prod`. The C45 approval also covered the contents of
   `terrascale-gru-terrabase-backups-b12` in Tigris and the specified
   retired-node OCI backups. Keep the buckets. Confirm the object sweeps
   finished before starting TerraBase.
2. Use the newest verified stable orchestrator release that carries the
   approved fleet definition. Publish the GRU founder entry for
   `ts-gru-1` to `ts-orch-join-gru` and start the founder. Check the
   Vault version quota before writing the join entry.
3. Run `ts-orch region apply sjc compute` and
   `ts-orch region apply fra compute` to bring up the remote founders.
   Check the three regions with `ts-orch mesh ping` so the replicated
   JetStream state can form. Reapply the preserved NetBird service.
4. Use `ts-orch region apply gru compute` for the two GRU pool workers.
   SJC and FRA each have three pool hosts. Confirm fresh volume bindings
   before counting a host as ready. Reconcile each region's NLB with
   `ts-orch region apply <region> nlb` and confirm production DNS points
   to the reserved NLB addresses before checking ACME and public TLS.
5. Verify signed app images and current deployment generations. Establish
   a serving TerraBase writer in GRU, then start auth in GRU, then verify
   dashboard readiness. Resume the other regions only after the GRU
   baseline passes. Preserve signed deployment floors when a concurrent
   workflow supersedes an operator apply.
6. Verify auth and dashboard readiness, the auth issuer and revision,
   the API, PG TLS, the multi-region mesh check, the deployment lag guard,
   and the production journey. Check the active managers per region
   separately from the number of running hosts.

## GRU ingress recovery observed in C45

Two GRU workers returned 502 for auth while the manager returned 200.
The worker-to-manager TCP 443 SYNs reached the manager's NetBird interface,
where the active regional server ACL omitted port 443. Both worker
`tcp-443` backends were drained individually using OCI's conditional
backend update. Their entries and previous flags were retained for rollback.
Public auth, OIDC, API, and dashboard passed fresh connection probes after
the drain. Keep the drain scoped to the failing listener and restore each
worker only after direct SNI readiness and the NLB health check pass.

After approval, a one-way NetBird grant allowed TCP 443 from the two live
GRU worker peer identities to the manager. Direct auth, OIDC, dashboard,
API, NetBird, and NLB checker probes then passed on both workers. Each
backend returned to rotation separately. Six fresh public connections
per HTTPS check succeeded after each change, and public PG TLS verified.

The GRU bootstrap used TerraBase revision `6014cb370` and auth and
dashboard revision `8f7ce8bf62`. The TerraBase apply took 52 seconds
and the auth apply took 38 seconds. Public auth stabilized 13 minutes
17 seconds after the GRU TerraBase apply started. Six public auth readiness
probes took 75–110 milliseconds and six dashboard probes took 83–93
milliseconds.

After bootstrap, the signed main release moved live auth to `cd89fecd8`.
Six fresh public readiness and OIDC requests each returned HTTP 200. The
readiness revision matched main at rollout and OIDC returned the issuer
`https://auth.terrascale.tech/terrascale`. The next main commit had an
empty diff under the release gate's auth input paths.

## Dashboard recovery when an all-region bake fails

Dashboard needs the regional TerraBase writer on its loopback service
endpoint. Confirm the dependencies in each target region before a
dashboard rollout. In C45, dashboard tasks in SJC and FRA returned 503
while TerraBase ran only in GRU.

If a terminal failed bake blocks placement changes and the approved
recovery requires a dashboard restart, verify that remote regions have no
serving dashboard. Confirm the exact signed floor on every receiver,
verify the cached baseline image and its mount-free service spec, and
check that GRU readiness reports both dependencies healthy. Check for
active dashboard release or placement writers. Stage a copy of the exact
baseline spec with only `regions: ["gru"]` changed before removing the
service. The remove and apply interrupt dashboard, MCP, and platform.

Run `ts-orch service rm ts-dashboard` and verify all three regions
accepted the removal with the signed floor retained. Immediately run
`ts-orch service apply -f <staged-gru-dashboard-spec>`. Verify the bake
completes in GRU, SJC and FRA are skipped, and the signed floor and exact
GRU-only spec agree on all receivers. Repeat public readiness and OIDC
probes. The C45 recreation took 24.865 seconds including a 16.031-second
bake with nine samples.

Use a newer eligible signed release for the qualified source. Check its
placement and bake separately from the full-fleet wait. Record the
executed production journey job and the current deploy-lag guard before
closing the rebuild.

In C45, a normal rerun of the originally qualified Images workflow signed
attempt 2 for `cd89fecd8`. It inherited the GRU-only placement, passed its
bake on `ts-gru-1`, and passed the release waiter. SJC and FRA reported
zero dashboard replicas. Public auth and dashboard served the qualified
source. The current main commit `ce4081b` changed only AI-review files,
leaving both applications' release inputs unchanged.
[Signed dashboard release](https://github.com/TerraScale/terrascale/actions/runs/44764950036/attempts/2)

The current-source production journey was dispatched after the signed
release. The latest executed deploy-lag check was red, and host revision
convergence remains open.
[Production journey](https://github.com/TerraScale/terrascale/actions/runs/44773500958)
[Deploy-lag check](https://github.com/TerraScale/ts-orchestrator/actions/runs/44739092294)
