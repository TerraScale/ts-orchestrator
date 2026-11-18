# Delivery pipeline

## Current GitHub workflow

Use the public [GitHub repository](https://github.com/TerraScale/ts-orchestrator)
and the [contribution workflow](../AGENTS.md#shipping-code): ready-for-review
PRs, CI as the gate, a rebase on current main and green checks on the latest
head. Local checks are optional before push. Fix and answer review findings;
no review approval or named reviewer request is required. Use the T3 PR
watcher while checks run.

All CI runs on GitHub-hosted runners in one workflow,
[`ci.yml`](../.github/workflows/ci.yml) (`CI`). A pull request runs two jobs in
parallel: `lint` (`make lint`, `make release-check` for both release binaries
and the dependency audit of the source graphs and of both binaries) and
`e2e-m1`, the node E2E
(`test/e2e/m1/run.sh`) on a disposable GitHub-hosted ARM64 runner. The last
job, `all-green`, is the one required check; it fails when any job failed or
was cancelled. `gh pr merge --auto --squash` merges once it passes; the branch
need not be up to date with main. New PR pushes cancel older PR runs. On main,
a newer push cancels an older run's `verify/go + artifact/linux-amd64-arm64`
and `e2e-m1` jobs while they run or wait, so that run skips
`deploy/release-publish` and fails `all-green`; the newer run's commit carries
both changes. `deploy/release-publish` jobs share the `production-ts-orch` lock
and never cancel a running rollout.

Every main push runs `e2e-m1` again on the merged tree, beside the
`verify/go + artifact/linux-amd64-arm64` job. `lint` runs in `ci.yml` only on
pull requests and restores the `lint-v2` build cache; every main push runs the same
commands in [`lint-cache.yml`](../.github/workflows/lint-cache.yml)
(`Lint cache`), which saves that cache. Nothing reads its result: a red run
means main does not lint, and it holds back no merge and no release.

The Go action returns the exact cache key and paths for main-push saves.
Caller-key change detection restores only module sources under its own cache
name; the caller-key builder has a separate build/module cache. Neither restores
the lint audit cache. Lint uses a fresh namespace to exclude oversized historical
entries. Cache keys include the pinned Go version, go.sum and UTC date, with a
restore prefix restricted to the same dependency hash. A job saves at most once
per day for those inputs instead of once per commit. Before saving, compiled
build caches are trimmed oldest-first to 1 GiB; module sources are retained.
Go rebuilds evicted outputs it needs. ARM64 journey and release producers retain
their cache names and save the paths returned by the action. Job time limits
are unchanged.

The `verify/go + artifact/linux-amd64-arm64` job compares the push's
executable inputs with the newest retained `ci-*` release in its history:
different inputs publish, and the same inputs skip publication and
`deploy/release-publish` when that release's run succeeded; a release whose run
did not succeed is passed over for the next older one. Publishing builds static
amd64/arm64 binaries, verifies their source metadata and publishes the binaries
plus `qualification.json` on the GitHub release `ci-<sha>-run-<id>`. Use
`gh run view` for individual run details and `gh release view` or
`gh release download` for retained artifacts.

The main-only `deploy/release-publish` job waits for the required checks,
attests the retained binaries with Sigstore and uploads provenance.sigstore.json
to their GitHub release. It does not deliver a binary to a host or send a nudge.
The publication identity remains the qualified main CI workflow.

## Host pull and regional order

Managers poll the GitHub releases API every five minutes. One owner per region
holds a renewable lease in TS_ORCH_PULL_ROLLOUT. The regional record persists
the target, each host's progress, failures and a stable completion timestamp.
A successor resumes the same record. Lease failure relinquishes ownership;
it does not stop the serving node.

The fixed binary order is sjc, fra, gru. Staging precedes sjc once C16 founds
that catalog cell. Before taking a tag, the leader reads its predecessor's
record from the same fabric store: that exact tag must be complete and have
passed its regional gate. Missing, unreadable or failed predecessor evidence
blocks admission.

The gate compares with the region before the release. When a region takes a
tag its leader records a baseline: each host's health conditions and the
services below desired replicas. A host installs while every other host is no
worse than its baseline, so a region that was already degraded still takes a
release that may fix it. After the last host the gate samples every 2 s: every
host runs the release and is no worse than its baseline, no service is below
desired replicas unless it was before, no task of a steady service is replaced
and no host's orchestrator restarts. It passes after 20 s of such samples
(two swarm readiness probe intervals); three failed samples over 15 s, a
restart, or no passing window within 55 s roll the release back and block
subsequent regions. Each stage's time is in the record:
`ts-orch observe releases` prints published, discovered, installed and ready
per host, gate start, gate end and complete for every region.

Inside one region the updater admits one host at a time through the private
PullInstall subject. Each host verifies the main workflow's Sigstore identity,
source ancestry, transparency evidence and exact binary digest, then runs the
candidate preflight before swapping. The existing probation and recovery
units confirm a serving binary or restore its previous bytes. The next host
waits for the full health gate. No public NATS receiver, CI push claim or
nudge path remains.

## Application release selection

The producer reuses an already-built, attested native Linux digest of the
existing GHCR package. Its release job signs a separate in-toto selection
with predicate type https://terrascale.tech/attestations/release-selection/v1
and service and revision fields, then moves that package's release tag to
the selected digest. The tag is a discovery pointer and carries no authority.

Hosts require both build provenance and the selection, verified with the
existing Sigstore trust root, certificate identity, timestamps and transparency
log. The certificate must name the target workflow on refs/heads/main.
PR triggers are refused. TerraBase selection requires workflow_dispatch;
auth and dashboard allow push or workflow_dispatch; the canary requires
workflow_run. The selection run and attempt, rather than the build run,
identify the durable deployment and retained floor. A newer authorized
selection can release the same built digest after a held attempt.

The producer signs keylessly with its existing OIDC permission and pushes
only an attestation referrer and tag under the existing package using its
existing or explicitly approved packages permission. It adds no PAT, host
secret, package or GitHub attestations permission. Main build-only publication
creates no selection. TerraBase release-only remains a user decision.

## Read-only release proof

CI reads GET /orchestrator/observation through the existing authenticated edge
on HTTPS 443. The response contains host revisions, regional health, a mesh
ping matrix and desired/running images. It has no mutation operation.

- release hosts REVISION waits for every registered host to run that revision with its release confirmed and no rollback.
- release wait --service NAME --image IMAGE waits for the selected image to serve.
- release digests --out FILE records complete, agreeing running digests.
- release mesh-check verifies mesh and HTTPS evidence without NATS access.

The app-release wait and mesh check compare validated SHA-256 manifest digests. Legacy GHCR,
package-only and regional OCIR references to the same digest satisfy the same
gate. Missing, mutable, malformed and different digests fail the comparison.
The mesh check includes both observed and desired references in a mismatch.

`release hosts` and `release wait` log a `Region release observation` record on
stderr whenever a region's readiness, host inventory or app images change.
Each record includes its region, UTC `observed_at`, HTTP status, health,
registered host versions, desired/running images and readiness. A down host
cannot confirm a host release. The first `ready:true` record for a region is
its first observed healthy target proof. Subtract the PR's `mergedAt` from that
timestamp for merge-to-region time; retain the workflow run and target revision
with the measurement. Pending records expose the blocking state before a
workflow deadline. Observation budgets and release gates are unchanged.

Transport failures and undecodable responses during host restart remain pending
until the existing observation deadline; authentication failure is terminal.
The canary waits for the revision encoded in the downloaded release tag, so a
main commit that does not publish another binary cannot stall its observation.

Receiver deployment precedes the companion producer change. The production
4222 rule removal follows only after all six hosts run this release and the
retired callers are absent over a recorded observation interval. FRA is
changed and verified first, then SJC, then GRU. See [network.md](network.md)
for before evidence, the exposure table and the exact undo procedure.
