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

Serving membership comes from the orchestrator's own controller membership:
each founded cell's regional authority leader refreshes its head bucket's
`releases/orchestrator/status.json`, and discovery reads that document with
the same per-cell operator credentials the deploy path uses. A cell whose
status object is authoritatively absent has not deployed a release; routing
health never removes a serving region from deployment. The CLI rejects
empty, unreadable, duplicate, unsupported or stale membership, rather
than treating the entire supported-region catalog as a serving fleet.

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

`deploy-lag.yml` runs after each main CI push and every five minutes.
`scripts/ci/deploylag` reads every region over HTTPS using its main-workflow
GitHub OIDC identity. Only GET `/orchestrator/observation` is authorized;
`?view=deployments` returns regional task revisions, hosts, task errors and
rollout failures only to the main deploy-lag workflow. Existing observation
callers retain the original view and cannot read the new deployment details.
No release or mutation authority is granted to deploy-lag. Its report has a
fifteen-second server deadline within the twenty-second client deadline.
The verifier and regional report must be released to the hosts before the new
guard can observe them.

Every artifact (ts-orchestrator, terrabase, ts-auth, ts-dashboard) has a row in
every production region: main commit, selected release, running revisions by host,
lag in minutes, budget and verdict. Each region reports the placement it holds
for an application: its desired spec's generation and `regions`. A missing
deployment is expected only where that placement leaves the region out (ts-auth
runs only in gru). Every configured region must report the identical placement
(generation, rollback ancestry and `regions`), so the guard never ranks one
generation over another, and the region must have no service, task or failure
for the application. Its row
then reads `running=none (not declared in <region> by placement generation N)`.
The publisher checks still apply to that row. In every other case a missing
deployment stays pending and turns red after the fifteen-minute budget. That
includes a region with no desired spec (reason `this region holds no desired
spec for the service`), a region on a ts-orch release that reports no
placement, and any disagreement between regions, such as an older apply or a
rollback held in some regions and a later apply in others. Each artifact's budget lives in the guard's
artifact table and is fifteen minutes. The newest signed selection observed in
any region is the target everywhere. An unserved target's age starts at channel
publication (or the selected application's OCIR publication step), rather than
the commit timestamp. An unchanged artifact remains current when unrelated main
changes produce no release. A running descendant of the sampled selection is current.
A reported release failure is red immediately, including an erroring or down
host with no readable revision. For ts-auth and ts-dashboard, the guard reads
the exact publishing run and attempt recorded in the signed selection, including
push runs before the main journey finishes. It reads `main-auth` or
`Publish and release`, the successful OCIR publication step, `Select the signed
release`, and `Wait for rollout`. A failed select or rollout wait is a failure
of that selected release; pending steps consume its publication budget. Workflow
or journey completion is not required to observe the publishing job.
Unreadable regions and revision comparisons
explicitly report `cannot observe`; they never set an artifact's deployment
verdict to red. Observation gaps fail the CI run and open/update one assigned
`Deploy observation unavailable` issue without paging. Existing artifact lag
issues remain open while their recovery cannot be observed.

This guard observes signed selected releases. A main commit whose publication
fails before selection moves is outside its coverage. Orchestrator publication
failures are caught by CI's `release-publish` or
`release-publish-after-lanes` jobs and fail the required `all-green` check;
handle those as red main. Application publication failures are caught by their
producing terrascale CI or Images (GHCR) workflow. They do not generate a deploy-lag
page while the previously selected release still serves.

A red main run opens or updates one assigned `Deploy lag: <artifact>` issue
per affected artifact and pages through the existing `TS_ALERTS_NTFY_TOPIC`.
Each issue stores a page reservation before delivery, limiting an artifact to
one page per thirty minutes across scheduled runs. Failed or ambiguous delivery
still consumes the reservation. A page is withheld when its reservation cannot
be persisted. An artifact's issue closes only when all its regional rows are
observed green. Delivery errors fail CI without manufacturing artifact lag.
The final output line is `DEPLOY red` followed by confirmed red artifacts, or
`DEPLOY ok` followed by fully observed green artifacts. `DEPLOY ok -` means no
artifact has a confirmed red verdict and none is fully observed green; the
observation failure still makes the process exit unsuccessfully. An absent
artifact in an ok list must not be treated as healthy.

Check the binary revision and services on every inventoried server;
publishing a release is not evidence of deployment.

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
