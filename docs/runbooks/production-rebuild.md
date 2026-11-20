# Production cell rebuild

This records the November 19–20, 2026 production reset (C45). The reset
discarded TerraBase customer data, auth users, and dashboard data. GRU
restored public service first. Confirm the destructive scope and the release
and access prerequisites before using this sequence for another reset.

## Verify releases and join material

- Resolve the newest qualified, attested release on `stable` for the
  approved fleet. The resolver accepts qualified `ci-<sha>-run-<id>`
  tags even when GitHub labels them prereleases. Verify the artifact
  attestation and compare the architecture-specific binary checksum with
  `qualification.json` before installing it. Record the founder and
  operator releases separately when they differ.
- In C45, the founder release was
  `ci-05ff0b2036b8d60a4f833ec69892de27e0c67f6d-run-44582545260`.
  Its attestation verified and the live ARM64 binary checksum matched
  `qualification.json` (prefix `1fa779d5a0e2`).
  [Founder release](https://github.com/TerraScale/ts-orchestrator/releases/tag/ci-05ff0b2036b8d60a4f833ec69892de27e0c67f6d-run-44582545260)
- The CLI for GRU pool creation was built from the verified release revision
  `ci-d1e665dab07ecef27fc3c76385e39982359aca17-run-44613725374`.
  Before applying compute, the operator matched `ts-gru-1`'s IMDS
  identity to its OCI instance and confirmed the manager was `READY`.
  [Operator release for #512](https://github.com/TerraScale/ts-orchestrator/releases/tag/ci-d1e665dab07ecef27fc3c76385e39982359aca17-run-44613725374)
- Before retiring hosts, record the current Vault version and creation
  time for `ts-orch-join-{gru,sjc,fra}` using metadata only. Check version
  capacity for every secret. Leave room for the founder marker and the
  subsequent publication of usable manager and route addresses. FRA had
  no free version slot during C45. The operator scheduled deletion of
  approved deprecated versions before continuing. Confirm capacity is
  available before relying on a new publication.
- In SJC and FRA, check the regional compartment as well as the fleet
  pool. Reclaim requires the previous manager to be unreachable and
  every nonterminated instance to have a creation time later than the
  current join material. Confirm that approved retired hand-made hosts
  have reached OCI `TERMINATED`. The oldest eligible fleet node then
  publishes the founder marker. C45 kept the external `ts-gru-1`, so the
  operator verified the old GRU manager had stopped and explicitly
  published the GRU founder marker.

## Preserve operator access

- Keep the external GRU host `ts-gru-1`, its NetBird management store, and its
  monitoring services. Preserve its boot-volume backups and the existing
  Vault credentials, VCNs, NLBs, and reserved public addresses.
- Mount the dedicated OCI block volume at `/var/lib/ts-data` and bind
  `/var/lib/ts-data/ts-orch` to `/var/lib/ts-orch`. Check the mounts before
  starting the cell. The root disk still holds monitoring and the OS.
- Verify independent operator access to `ts-gru-1` before stopping
  NetBird. Stop the old cell, NetBird host services, and release-recovery
  timer within one logged systemd transaction. Keep the NetBird data and
  edge certificates when replacing the old orchestrator state.

## Rebuild in order

1. Retire the old pool nodes and their old data volumes. Once all old
   writers stop, empty the approved R2 buckets
   `terrascale-{gru,sjc,fra}-files`, `terrascale-gru-terrabase`, and
   `ts-terrabase-shapes-prod`. The C45 approval also covered the contents of
   `terrascale-gru-terrabase-backups-b12` in Tigris and the specified
   retired-node OCI backups. Keep the buckets. Confirm the object sweeps
   finished before starting TerraBase.
2. Publish the GRU founder entry for `ts-gru-1` to `ts-orch-join-gru` and
   start the verified founder binary. Confirm GRU publishes a fresh join
   version with the new manager and route addresses.
3. Run `ts-orch region apply sjc compute` and
   `ts-orch region apply fra compute` to bring up the remote founders.
   Confirm each region publishes fresh join material with the expected
   manager and routes. Verify those addresses through the admitted hosts
   without printing the worker token. Run `ts-orch mesh ping` to check
   regional reachability. Before any workload apply, confirm the fresh
   metadata group has a leader and that authenticated JetStream account
   requests (`$JS.API.INFO`) through each region succeed without an API
   error. Use an existing approved JetStream account identity. Stop if
   join material is stale or JetStream readiness cannot be verified.
4. On `ts-gru-1`, reapply `deploy/m1/services/netbird-server.json` with
   `ts-orch service apply -f` using the preserved NetBird store. Verify
   `ts-orch service ls` shows the SwarmKit `netbird-server` workload at
   `1/1` and the public endpoint responds. Restore `netbird.service`, the
   `netbird-server.service` companion, and `ts-orch-release-recovery.timer`.
   Run `systemctl is-active <unit>` for each and confirm the next run in
   `systemctl list-timers ts-orch-release-recovery.timer`. Prove operator
   access through NetBird from a separate session before removing temporary
   access. In C45, NetBird returned HTTP 200 before its companion and timer
   were restored.
5. Use `ts-orch region apply gru compute` for the two GRU pool workers.
   SJC and FRA each have three pool hosts. Confirm fresh volume bindings
   before counting a host as ready. Reconcile each region's NLB with
   `ts-orch region apply <region> nlb` and confirm production DNS points
   to the reserved NLB addresses before checking ACME and public TLS.
6. Verify signed app images and current deployment generations. Establish
   a serving TerraBase writer in GRU, then start auth in GRU, then verify
   dashboard readiness. Resume the other regions only after the GRU
   baseline passes. Preserve signed deployment floors when a concurrent
   workflow supersedes an operator apply.
7. Verify auth and dashboard readiness, the auth issuer and revision,
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

## Verification status at handoff

- The production journey job started at 16:27 UTC on November 20 for
  `ce4081b`. Its `Journey against production` step started at 16:29 UTC
  and was still running at 16:50 UTC.
  [Production journey job](https://github.com/TerraScale/terrascale/actions/runs/44773500958/job/136417102558)
- The last executed deploy-lag check failed at 12:50 UTC before the GRU
  app recovery. Run `44744094060` skipped its check. The latest qualified
  orchestrator revision was
  `fb83f90df`; only `sjc-node-2` and `sjc-node-3` ran it. The release
  controller reported SJC waiting on `sjc-node-1` with `raft group
  _meta_: membership is changing`. GRU and FRA waited at the SJC canary
  gate. The refusal confirms a leader replied at a term at least as high
  as the local term at the time of the check. The exact failing membership
  predicate and current voter and replica state were unverified.
  [Deploy-lag check job](https://github.com/TerraScale/ts-orchestrator/actions/runs/44739092294/job/136297846552)
- All three receivers agreed on GRU-only placement for TerraBase, auth,
  and dashboard. SJC and FRA reported zero declared replicas for those
  services. Fleet-wide app and orchestrator convergence remain open.
