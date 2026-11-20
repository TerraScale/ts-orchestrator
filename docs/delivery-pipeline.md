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
need not be up to date with main. New PR pushes cancel older PR runs. Each
main run owns its M1 groups, automatic reruns and aggregate gate, so a newer
push does not cancel those jobs in an older run. The artifact build still
shares the `fast-build-refs/heads/main` key: a newer push can cancel an older
run's `verify/go + artifact/linux-amd64-arm64` job while it runs or waits,
preventing that run from publishing and leaving its `all-green` red.
Both `deploy/release-publish` paths share the `production-ts-orch` lock with
`cancel-in-progress: false` and `queue: max`. A late older publisher cannot
evict a newer pending publisher, and neither cancels a running rollout.

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

The `prune-releases.yml` workflow runs hourly and invokes
`scripts/ci/prune-drafts.sh` to remove CI and image drafts created more than
one day ago. Cleanup shares the `production-ts-orch` concurrency group with
both publication paths, so it cannot delete a draft while it becomes public.
It rereads each candidate and keeps any release that has become public.
Drafts do not consume the newest-published-release allowance or inherit
production pin retention because hosts cannot select them.

Published-release pruning remains in `scripts/ci/prune-releases.sh`, which
requires an explicit file of live pins. Its default retention keeps the
newest 20 published releases and those published within seven days. Revision,
tag and manifest digest pins protect public releases from deletion; an
unreadable manifest also preserves its release. The hourly draft cleanup
does not delete public releases.

## Host pull and regional order

Managers poll the GitHub releases API every five minutes. One owner per region
holds a renewable lease in TS_ORCH_PULL_ROLLOUT. The regional record persists
the target, each host's progress, failures and a stable completion timestamp.
A successor resumes the same record. Lease failure relinquishes ownership;
it does not stop the serving node.

sjc is the canary region; fra and gru follow it together. Before taking a tag,
the leader reads the other production regions' records from the same fabric store: the canary must
have completed that exact tag and passed its regional gate, and no region may
have rolled it back. Missing, unreadable or failed evidence blocks admission.
Once admitted, a region keeps rolling even if another region later rolls the
tag back; the failing region restores only itself. Every host downloads and
verifies the release when its region first sees it, so the install that
follows the previous host's gate starts from the fetched binary. A region's
gate end is written once, when its gate passes.

A region with no release record adopts the release it discovers when every
host runs it and reports `provenance: booted`: the host's install receipt, the
run fence `nats/release-run-id` that every install writes before it swaps, is
absent, so no rollout ever installed it. Such a region just formed from the
image. A host whose receipt is unreadable reports its history as unknown, and
the region refuses the adoption with that reason until it reads; a host with
a receipt sends the region through the normal rollout. Each host records the
release's channel seq through the pull op `adopt`, which checks the running
binary and never installs, and the record carries `adopted` instead of a gate
end. An adopted record is not gate evidence: it never admits another region,
and the region never installs that release afterwards. While a region stays
adopted, its sweep saves a newer signed seq of the same tag and records it on
every host that runs that release, including workers that join later; a host
on another release takes the next one. In any rollout, a host that already
runs the target before the rollout installed it is recorded done without a
gate, and a rollout that installed no host is recorded adopted rather than
passed. A failed regional gate rolls back the failing host when this rollout
installed it, otherwise the host this rollout installed last; the record
names the failing host or service.

The gate compares with the region before the release. When a region takes a
tag its leader records a baseline: each host's health conditions, the
services below desired replicas, and each service's mesh generation and
running replicas. A host installs while every other host is no worse than its
baseline, so a region that was already degraded still takes a release that
may fix it. A service is worse when fewer replicas run than before the
release, so a scale-up that keeps the mesh generation is no regression. The
gate judges only what the ts-orch release changed: a service whose mesh
generation differs from the baseline, or whose swarm update to a new
generation is still running, is in its own release, and the gate names it as
`excluded: own release` in the record's `excluded`. It settles only on
affirmative evidence, swarm's update state `completed`; from then on its new
generation and running replicas are its baseline and it is judged like any
other service. An update that is paused or rolled back (`failed`), or with no
update state, keeps the service named and unsettled. A baseline without
per-service evidence exempts nothing. After the last host the gate samples
every 2 s: every host runs the release and is no worse than its baseline, no
other service runs fewer replicas than before, no task of a steady service is
replaced and no host's orchestrator restarts. It passes after 20 s of such
samples (two swarm readiness probe intervals); while a service is unsettled
the bake waits. Three failed samples over 15 s, a restart, or no passing
window within 55 s of the gate start roll the release back and block
subsequent regions. When the 55 s pass with no failure but an app still
unsettled, the region records `withheld: app <name> unsettled`: the release
stays installed, later regions do not take it, and the region takes the next
release. Each stage's time is in the record:
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
- release wait --service NAME --image IMAGE observes the aggregate serving digest.
- release wait-signed --service NAME --image IMAGE proves the exact signed app generation and its authorized regional placement.
- release digests --out FILE records complete, agreeing running digests.
- release mesh-check verifies mesh and HTTPS evidence without NATS access.

The app-release wait and mesh check compare validated SHA-256 manifest digests. Legacy GHCR,
package-only and regional OCIR references to the same digest satisfy the same
gate. Missing, mutable, malformed and different digests fail the comparison.
The mesh check includes both observed and desired references in a mismatch.

The aggregate serving digest reflects the placement in the desired spec.
Querying all regional endpoints with `release wait` can therefore report the
same serving digest from every endpoint when the service only runs in GRU.
The hosts still select and apply releases through their signed pull workflow.

`release wait-signed` uses the same app workflow OIDC authorization with
`view=app-release`. Before switching CI, complete the GRU-first runtime
cutover and verify that each required HTTPS endpoint returns a fresh,
service-scoped response from its regional manager under the existing
workflow identity. Keep using `release wait` until that capability is live.

The signed waiter takes the selection revision, run ID and attempt from
the GitHub Actions environment or from `--revision`, `--run-id` and
`--run-attempt`. It checks the selected digest, runtime and durable bake
against the same signed desired generation on every required target. The
regions file describes the configured fleet. An unscoped wait requires that
whole fleet and reports any required target explicitly excluded by the
signed generation. An approved recovery may pass `--scope gru` when the
signed generation's placement is exactly GRU. The command prints
`gru_ready` when GRU has matching evidence. After all regions report ready,
it probes them again and emits `done` only when every region returns newer
live readiness evidence for that same generation within the freshness
window. Both events include the signed identity, target regions, bake pass
times and live check times. A held failed bake or rollback for the selected
release ends the wait with the region, signed run and attempt, and the
affected generation.

`release hosts` and `release wait` log a `Region release observation` record on
stderr whenever a region's readiness, host inventory or app images change.
Each record includes its region, UTC `observed_at`, HTTP status, health,
registered host versions, desired/running images and readiness. A down host
cannot confirm a host release. For `release hosts`, the first `ready:true`
record marks the first observation of a confirmed host release in that region.
For a signed app, use that region's `passed_at` for the exact generation in
`release wait-signed`. Subtract the PR's `mergedAt` from the corresponding
timestamp and retain the signed run and revision with the measurement.

Transport failures and undecodable responses during host restart remain pending
until the existing observation deadline; authentication failure is terminal.
The canary waits for the revision encoded in the downloaded release tag, so a
main commit that does not publish another binary cannot stall its observation.

Receiver deployment precedes the companion producer change. The production
4222 rule removal follows only after all six hosts run this release and the
retired callers are absent over a recorded observation interval. FRA is
changed and verified first, then SJC, then GRU. See [network.md](network.md)
for before evidence, the exposure table and the exact undo procedure.
