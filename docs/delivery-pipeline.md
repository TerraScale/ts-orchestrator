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
`e2e-m1`, the single-host E2E
(`test/e2e/m1/run.sh`) on a disposable GitHub-hosted ARM64 runner. The last
job, `all-green`, is the one required check; it fails when any job failed or
was cancelled. `gh pr merge --auto --squash` merges once it passes; the branch
need not be up to date with main. New PR pushes cancel older PR runs. On main,
a newer push cancels an older run's `verify/go + artifact/linux-amd64-arm64`
and `e2e-m1` jobs while they run or wait, so that run skips
`deploy/release-push` and fails `all-green`; the newer run's commit carries
both changes. `deploy/release-push` jobs share the `production-ts-orch` lock
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
`deploy/release-push` when that release's run succeeded; a release whose run
did not succeed is passed over for the next older one. Publishing builds static
amd64/arm64 binaries, verifies their source metadata and publishes the binaries
plus `qualification.json` on the GitHub release `ci-<sha>-run-<id>`. Use
`gh run view` for individual run details and `gh release view` or
`gh release download` for retained artifacts.

The main-only `deploy/release-push` job runs only after both jobs passed. It
downloads that run's retained binaries
and calls `ts-orch release push` for the regions in
[`deploy/m1/regions.json`](../deploy/m1/regions.json). GitHub OIDC is the push
credential; workflow identity and permissions authorize the release listener.
Regions roll one at a time in catalog order with the first founded region
last: sjc, fra, gru today. G0 requires every target's version reply within
10 seconds and health `ok` where the release-health subject is available,
before installing anything. No responders or `no health check` accepts the
version probe alone for the first push. G0 accepts any running version; an
install in progress or a pending restart fails health. G1 waits up to three
minutes for the requested SHA. G2 polls each region's release-health subject
every two seconds with an eight-second request timeout around the handler's
five-second total budget, requiring the requested SHA and 15 uninterrupted
seconds of healthy JetStream leaders and replicas, a READY SwarmKit node and
services at their desired replicas, within three minutes. Already-current
regions still pass G1 and the full G2 health gate. G2 completes before the
next install, keeping at most one JetStream peer down.

Any failed gate stops the push; unreached regions are marked skipped with
the blocking region's name. The job has a 30-minute limit and retains JSONL
results with `started_at`, `observed_at`, `healthy_ms` and the last health
reason. For a transient failure, run `gh run rerun <id> --failed`; for a bad
build, open a revert PR. The mixed-version window can now last minutes.
An already-unhealthy production stream intentionally stops the first release
at sjc's G2. During the first push, regions still running the old binary
provide only G0's version check if health is unavailable; G2 always checks
the requested binary, including on reruns where it is already current.
Runtime credentials remain managed by OCI Vault.

If `e2e-m1` fails or is cancelled after the build published, the run leaves its
public `ci-<sha>-run-<id>` prerelease behind, skips `deploy/release-push` and
fails `all-green`, so nothing reaches the regions. The comparison above passes
over that release, so the next push to main publishes and rolls out again
whatever it changes, documentation included, unless a successful run already
published the same executable inputs.

App image workflows in the public
[TerraScale monorepo](https://github.com/TerraScale/terrascale) release through
`ts-orch release app`. This repository's
[`app-canary.yml`](../.github/workflows/app-canary.yml) checks app releases and
[`app-digests.yml`](../.github/workflows/app-digests.yml) records the mesh's
desired image digests on the `app-digests` branch.

## Signed bundle boundary

An independently prepared signed bundle remains a supported deployment input:

```sh
ts-orch release apply --dir BUNDLE --root-key TRUSTED_ROOT --namespace NS
```

`BUNDLE/GRU/channel.json` and other region documents carry root-delegated
release proofs; `BUNDLE/binaries/<sha256>` supplies the exact bytes.
Application verifies trust, scope, digests and channel ordering, then publishes
to existing OCI channels. Region consumers verify locally and poll for updates.
Application needs no GitHub repository, `gh`, Git checkout or signing secret.
A webhook can hint that data exists; it cannot authorize a release.

The signed channel sequence remains the `run_number` wire field, currently a
CI counter. Changing producers must preserve monotonic ordering. See
[release application](releases.md#apply-a-signed-release-bundle).

## Legacy standalone image and service adapters

The former `image.yml` and `deploy.yml` are absent from the active workflows.
Do not dispatch them or configure private runner containers, a builder registry,
runner cache volumes or runner instance principals. CI uses GitHub-hosted
runners only.

Standalone `TerraScale/terrabase`, `TerraScale/ts-auth`, `TerraScale/ts-libs`
and `TerraScale/ts-builder` have no GitHub copies. Fresh qualification for the
legacy image/E2E adapters still requires reviewed source, pinned commits and
release assets; monorepo outputs cannot silently replace their signed contracts.
The retained `ts-orch image promote` and image-input tools are explicit legacy
operator paths, not evidence of automatic image publication or serving readiness.

`scripts/ci/pin-terrabase.sh` can open a data-only GitHub PR for an existing
qualified standalone release. It uses `gh`, the GitHub Actions commit identity
and auto-merge (`gh pr merge --auto --squash`). It needs scoped cross-repository write
authority when invoked from another repository; `GITHUB_TOKEN` only grants
its own repository's permissions. Public source and release reads need no
operator-managed source-host token. Production credentials are created and
delivered through OCI Vault rather than copied by hand.

Dated measurements below retain their original provider identities. They do
not describe current GitHub-hosted runner performance or the active workflow.

## Historical measurements (Forgejo runs, 2026-09-29)

| Stage | Before | After |
| --- | --- | --- |
| Orchestrator `ci.yml` | 7m56s warm (run 705), 13–17 min cold | 1m55s–4m32s (runs 717, 719, 725, 727, 729) |
| CI → image handoff | 5 values copied into a manual dispatch | none: `ci.yml` dispatches `image.yml` as it ends |
| Image job | 27–40 min (runs 698, 702) | 6m22s (run 728), 8m30s with a cold base cache (run 726) |
| Image tool setup | about 16 min (fj build, then nixpkgs tools with libguestfs built from source) | 31 s from pinned store paths in `/cache/nix` (10m31s once, to fill the cache) |
| Appliance launches per image | 7 under TCG, about 70 s each | 2 |
| Push → retained image | 45–60 min with hand-copied inputs | about 8½ min, plus any wait for the previous image build |
| TerraBase `main` → published release | about 17 min, published bytes rebuilt (run 1018) | 7m14s, the tested bytes (run 1020) |
| Local image build (KVM) | not available | 1m48s (`make image`) |
| Promotion dry run | about 25 hand-run commands | 1m11s, one command |
