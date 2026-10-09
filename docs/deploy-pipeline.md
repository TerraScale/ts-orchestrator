# ts-orchestrator deployment pipeline

Part of [TS-768](https://ku.mariogk.com/terrascale/issue/TS-768).

## Green main to every server

`ci.yml` validates the exact main revision, builds static amd64/arm64 binaries,
and retains their qualification manifest. Its final step dispatches `deploy.yml`;
a dispatch failure fails CI. Documentation-only changes do not create a build.
The deploy job checks main ancestry before using credentials, waits up to five
minutes for the producing CI run, and rejects failed or cancelled runs. A queued
revision overtaken by a newer qualified main revision is skipped. An active
deployment always finishes; workflows never cancel it to deploy a newer build.

`scripts/ci/deploy-fleet.sh` verifies the retained bytes and CI provenance, reads
the delegated release leaf from OCI Vault, and signs every configured cell and
architecture before publishing anything. A delegation outside any required
cell, architecture, environment or source lineage rejects the whole deployment.
GRU and SFO upload and publish independently, then roll concurrently. A failure
in one region does not interrupt another region's healthy rollout; the command
waits for all started regions and returns failure if any failed.

Within a cell, the existing leader executor updates controllers one at a time,
with the founder last. Quorum, load-balancer draining and readiness gates remain
in force. Managed hosts follow after controllers; hosts sharing a TerraBase
partition never restart together. The default canary soak is five minutes,
later waves soak two minutes, and three healthy reports are required. Failed
target proofs cause automatic rollback and mark the target known bad. CI allows
30 minutes per region, with both regions sharing that window.

A region is complete only when every current controller and participating host
freshly proves the target binary. An unjoined host, a changed registration key,
a stale proof or conflicting predecessor releases keeps deployment pending.
A completed historical rollout is insufficient proof that every current server
still runs its target. Diagnose the reported reason; update an existing host
in place when it needs initial self-update enrollment. Never re-found a serving
cell to complete a deployment.

## Repository configuration

Required variables:

- `TS_AUTO_DEPLOY_CELLS=GRU SFO`, `TS_AUTO_DEPLOY_ENVIRONMENT=production`, and
  `TS_AUTO_DEPLOY_ARCHES=arm64` for the verified 2026-10-09 inventory. Both cells
  have three running A1 controllers and no workload compute instances. Add an
  architecture when actual server inventory requires it.
- `TS_OBJECT_NAMESPACE`, `TS_RELEASE_VAULT_ID`, `TS_RELEASE_LEAF_SECRET`, and
  canonical `TS_RELEASE_UPDATE_DELEGATION` covering every configured target.
- `TS_DEPLOY_OCI_USER`, `TS_DEPLOY_OCI_TENANCY`, and `TS_DEPLOY_OCI_FINGERPRINT`.

Required secrets are `TS_DEPLOY_OCI_KEY` and `TS_DEPLOY_READ_TOKEN`. The OCI key
may read only the release leaf and manage the regional release objects.
The offline root key stays outside Actions. Delegations last at most 31 days;
renew them before expiry. Never print credential files, tokens or private keys.
The signed node environment and delegation must agree with the repository
environment before its value changes.

## Live verification and timing

`deploy-lag.yml` runs every five minutes. Each service records a
`deployment/qualified` commit status after verification and before delivery.
The guard reads main ancestry and those markers rather than treating a failed
deployment as a failed build. Continuous green builds cannot reset the clock
of the oldest pending build. The latest 50 main commits bound API work; absent
markers or unreadable observations fail visibly.
If the deployed revision is outside the checked ancestry, incomplete history
also fails visibly instead of restarting the 30-minute clock.

Native services must report the expected source revision, complete, and a
heartbeat within two minutes. Atlas, Status and Dashboard are observed through
Status's fixed GRU/SFO vantage bindings at `/api/v1/deployments`; both Status
vantage Workers also prove their own revision. The guard opens or updates one
assigned Forgejo alert, mentions `@mariogk`, and fails its scheduled job when
a qualified build is overdue after 30 minutes or telemetry is unreadable.
It closes the alert only when the full matrix has valid fresh proofs and no
overdue builds; missing or stale proofs keep the incident open even when all
visible qualifications are younger than 30 minutes. Alert lookup paginates
open issues so an existing incident is updated or closed instead of duplicated.
Its read token and OCI credentials are
the existing scoped deployment secrets; its Actions token can write the
orchestrator alert. Alert delivery failure also fails the job.

Read each region with `ts-orch release fleet-status --namespace NS --cell GRU
--cell SFO`. Require the expected full source revision, run number, `complete`,
and fresh reports. Check the binary revision and services on every inventoried
server as well; publishing a channel is not evidence of deployment.

Merge a no-op Go source change to exercise the complete pipeline. Record the
merge time, producing CI completion, regional publication and each server's
first healthy target proof. Report merge-to-last-server and green-to-last-server
for each region and the fleet; CI prints per-region and fleet deployment elapsed
times. Keep the resulting run links and server observations with the ticket.

The 2026-10-09 initial audit found live `releases/v1/...` reports, while main uses
`releases/...`. TS-746 owns GRU recovery, the region-wide delegation and initial
in-place rollout of #330. Verify its handoff and regional IAM before publishing
through the current pipeline. Initial audit evidence is not a successful live
deployment measurement.
