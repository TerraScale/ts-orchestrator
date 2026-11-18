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
restore prefix restricted to the same dependency hash. Most jobs save at most once
per day for those inputs. The main release builder saves once per run and
restores the newest matching dependency cache without trimming compiled
outputs: both architectures must remain warm across releases. Other compiled
build caches are trimmed oldest-first to 1 GiB; module sources are retained.
Go rebuilds evicted outputs it needs. ARM64 journey and release producers retain
their cache names and save the paths returned by the action. Job time limits
are unchanged.

The `verify/go + artifact/linux-amd64-arm64` job always compares the push's
executable inputs with the newest retained `ci-*` release in its history:
different inputs publish, and the same inputs skip publication and
`deploy/release-publish` when that release's run succeeded; a release whose run
did not succeed is passed over for the next older one. Publishing builds static
amd64/arm64 binaries, verifies their source metadata and publishes the binaries
plus `qualification.json` on a draft GitHub release `ci-<sha>-run-<id>`. Use
`gh run view` for individual run details and `gh release view` or
`gh release download` for retained artifacts.

Before building, main checks GitHub's merged-PR association for its exact
commit, the PR head's tree against main's Git tree and the successful
`all-green` job in a completed PR run of `ci.yml`. That same attempt must
have successful `lint`, `e2e-m1`, certificate detector/lane, caller-key
detector and all eight caller-key shards. A skipped lane does not qualify.
Only same-repository PRs qualify. The search considers the latest 100 successful PR runs; no match
uses main's lanes. API errors, timeouts and incomplete job lists select main's
lanes and record the reason without failing the build. The proof, including
run, attempt, head, tree and each gate URL, is written to the build summary.

For a proven tree, the main-only `deploy/release-publish` job needs only
the fresh main build when executable inputs changed. The legacy scan runs
on both paths; source dependency audits already passed on that exact PR tree.
Main still builds both architectures in parallel and checks and audits the
actual release binaries. It attests them with Sigstore, uploads
`provenance.sigstore.json`, makes the draft public and publishes the signed
regional channels. Without that proof, `release-publish-after-lanes` waits
for the same main lane gates as before and runs the identical publisher.
Only the selected job has the check name `deploy/release-publish`.

All main lanes still run independently. `all-green` waits for them and both
publication paths, rejects failed or cancelled jobs and requires publication
when a build is required. `revert-red-main.yml` still observes the completed
CI run. Neither path delivers a binary to a host or sends a nudge. The
publication identity remains this push's main CI workflow, source and run;
no PR binary or attestation is reused.

Both upgrade lanes pin the newest signed published strict ancestor of
`SOURCE_SHA`, matching the binary's embedded revision. They exclude this
commit's own release even when publication finishes first, and record the
selected tag in their logs and job summaries.

Release pruning also considers CI drafts older than its existing age cutoff,
using creation time when publication time is absent. Drafts do not consume
the newest-published-release allowance. Existing revision, tag and manifest
digest pins still protect releases from deletion.

## Host pull and regional order

Managers poll the GitHub releases API every five minutes. One owner per region
holds a renewable lease in TS_ORCH_PULL_ROLLOUT. The regional record persists
the target, each host's progress, failures and a stable completion timestamp.
A successor resumes the same record. Lease failure relinquishes ownership;
it does not stop the serving node.

The fixed binary order is sjc, fra, gru. Staging precedes sjc once C16 founds
that catalog cell. Before taking a tag, the leader reads its predecessor's
record from the same fabric store: that exact tag must be complete and its
five-minute bake elapsed. Missing, unreadable or failed predecessor evidence
blocks admission. During the bake the predecessor checks host and region
health and rolls back on failure, which blocks subsequent regions.

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
