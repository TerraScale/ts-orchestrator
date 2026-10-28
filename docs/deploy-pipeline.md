# ts-orchestrator deployment pipeline

This is the legacy signed cell-channel pipeline inventory. The former
`deploy.yml` and `image.yml` are not active GitHub workflows. For current
GitHub-hosted CI, the merge queue, retained binaries and the OIDC-authenticated
`ci.yml` release-push job, use [delivery pipeline](delivery-pipeline.md).

Deployment provenance is retained in the repository and signed release artifacts;
no external issue tracker is required. See [release boundaries](releases.md).

## Green main to every server

`ci.yml` checks every revision. It builds static amd64/arm64 binaries only when
executable or baked image inputs differ from retained qualification, and retains
their exact source manifest before dispatching `deploy.yml`. A dispatch failure
fails CI. Documentation-only changes run checks without publishing binaries,
recording a runtime qualification status or dispatching image/fleet delivery.
The comparison uses a complete retained successful main-ancestor release, never
the push parent: a cancelled runtime change still builds on the next docs push.
Missing or unreadable provenance builds current source. Weekly image refreshes
always build a candidate from the current source and run; older bytes keep their
original source identity. Image and deployment tools use the retained amd64
binary after both artifact digests, VCS metadata and CI manifest/job provenance
have been verified; those jobs do not compile another orchestrator.
The deploy job checks main ancestry before using credentials, waits up to five
minutes for the producing CI run, and rejects failed or cancelled runs. A queued
revision overtaken by a newer qualified main revision is skipped. An active
deployment always finishes; workflows never cancel it to deploy a newer build.

`scripts/ci/deploy-fleet.sh` verifies the retained bytes and CI provenance, reads
the delegated release leaf from OCI Vault, and signs each region within its
independent worker. A delegation outside a required cell, architecture or
environment fails that region visibly. Source qualification and lineage remain
required for every signature. GRU and SJC sign, upload, publish and roll
concurrently. A signing, storage, publication or rollout failure
in one region does not interrupt another region's healthy rollout; the command
waits for all started regions and returns failure if any failed.

Serving membership comes from the orchestrator's signed cell-spec topology,
published at Atlas `/v1/discovery`. Region creation admits its Atlas entry;
future supported regions join delivery without edits to service repositories.
Routing health never removes an admitted region from deployment. The CLI
rejects empty, unreadable, duplicate, unsupported or stale membership, rather
than treating the entire supported-region catalog as a serving fleet.
`release deploy`, `release service-deploy` and `release fleet-status` omit
`--cell` to discover every serving cell. Native deploy commands omit
`--environment` to use each region's admitted environment; orchestrator deploy
also omits `--arch` to select each region's architectures. Scope reads and
binary inspection happen inside independent region workers. An unreadable
SJC inventory does not prevent GRU from deploying.

The regional leader now includes `environment` and sorted `architectures` in
`releases/orchestrator/status.json`. These come from its admitted trust
environment, the executable architecture of the controller image shared by
all controller slots, and the signed managed-host shape. Release progress
and a malformed desired channel cannot change this scope. Existing status
readers ignore the additional fields; health-proof formats are unchanged.
For the initial scope-schema activation, deploy a qualified main containing
the scope reporter to both cells with the supported operator scope flags.
Verify fresh scope fields before testing the automatic workflow with omitted
scope flags. Subsequent main builds discover scope without operator input.
The shared consumer rejects missing scope or a heartbeat older than two
minutes for that region, even if an older report says the rollout completed.

Within a cell, the existing leader executor updates controllers one at a time,
with the founder last. Quorum, load-balancer draining and readiness gates remain
in force. Managed hosts follow after controllers; hosts sharing a TerraBase
partition never restart together. The default canary soak is five minutes,
later waves soak two minutes, and three healthy reports are required. Failed
target proofs cause automatic rollback and mark the target known bad. CI allows
a fixed 20-minute observation budget per release, shared by controller and
host rollouts and preserved across leader changes. Qualification has a fixed
10-minute budget, so qualification plus observation is at most 30 minutes.
There is no timing variable, per-region CLI override or cell-spec policy.
The controller automatically rolls back a release that reaches its observation
deadline without complete fresh serving proofs; recovery has its own deadline.
The [TS-783 timer inventory](rollout-policy.md) records before/after values,
the paths covered by this policy change and the remaining ticket work.

A region is complete only when every current controller and participating host
freshly proves the target binary. An unjoined host, a changed registration key,
a stale proof or conflicting predecessor releases keeps deployment pending.
A completed historical rollout is insufficient proof that every current server
still runs its target. Durably retired registrations remain visible for
diagnosis but do not participate; a lost session never excludes a current host.
Diagnose the reported reason; update an existing host
in place when it needs initial self-update enrollment. Never re-found a serving
cell to complete a deployment.

## Repository configuration

Required variables:

- `TS_OBJECT_NAMESPACE`, `TS_RELEASE_VAULT_ID`, `TS_RELEASE_LEAF_SECRET`, and
  the Vault secret `release-delegation`, a root-signed update delegation covering every serving region of the environment.
- `TS_DEPLOY_OCI_USER`, `TS_DEPLOY_OCI_TENANCY`, and `TS_DEPLOY_OCI_FINGERPRINT`.

There is no deployment switch or repository-maintained region list. The script
downloads the qualification manifest's binary assets and delegates serving-cell,
environment and architecture discovery to ts-orch. The verified initial fleet
is GRU and SJC, with three ARM64 controllers in each cell and admitted `canary`
environments. Future cells use their own reported scope and signing authority.

Required secrets are `TS_DEPLOY_OCI_KEY` and `TS_DEPLOY_READ_TOKEN`. The OCI key
may read only the release leaf and manage the regional release objects.
The offline root key stays outside Actions. Delegations last at most 31 days;
renew them before expiry. Never print credential files, tokens or private keys.
The signed node environment and delegation must agree. The root's offline key
and scoped signing checks remain mandatory for each region.

## Live verification and timing

`deploy-lag.yml` runs every five minutes (`scripts/ci/deploylag`) and fails,
opening or updating one assigned GitHub alert (`TS-768`, mentions `@mariogk`),
when a main build was published but not released within 30 minutes:

- ts-orchestrator: a main commit is released when its `deploy/release-push`
  succeeded, or a newer one did; a skipped release-push with a green `test`
  check had nothing to publish. A red main that skips release-push counts.
- terrabase, ts-auth (terrascale `ci.yml` jobs `main (terrabase)`, `main (auth)`)
  and ts-dashboard (`images-ghcr.yml` job `test`): the oldest image published
  since the last successful `Release to every region` step starts the clock;
  newer builds never reset it.
- Services in the code map `held` (today terrabase, until the batch-2 wipe)
  are logged, not alerted. Unreadable history is a finding.

The alert closes on the first run with no findings.

Read every serving region with `ts-orch release fleet-status --namespace NS`.
Require the expected full source revision, run number, `complete`,
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
