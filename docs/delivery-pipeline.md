# Delivery pipeline

## Current GitHub workflow

Use the public [GitHub repository](https://github.com/TerraScale/ts-orchestrator)
and the [contribution workflow](../CONTRIBUTING.md#github-workflow): ready-for-review
PRs, CI as the gate, a rebase on current main and green checks on the latest
head. Local tests are optional before push. Fix and answer review findings;
no review approval or named reviewer request is required. Use the T3 PR
watcher while checks run.

All CI runs on GitHub-hosted runners. The active
[`ci.yml`](../.github/workflows/ci.yml) checks affected packages for PRs,
then the repository's required merge queue verifies full coverage against
current main. Queue entries also run
[`e2e-m1.yml`](../.github/workflows/e2e-m1.yml) on GitHub-hosted ARM64.
`gh pr merge --auto --squash` enters that queue; it cannot bypass its checks.
New PR pushes cancel older PR runs. A main run finishes so publication and
delivery retain their provenance.

After merge, `ci.yml` compares executable inputs with the last retained
qualification. Changed inputs build static amd64/arm64 binaries, verify their
source metadata and publish the binaries plus `qualification.json` on the
GitHub release `ci-<sha>-run-<id>`. Documentation-only changes do not publish
binaries or deploy. Scheduled/manual verification and develop pushes run the
full test tier. Use `gh run view` for individual run details and
`gh release view` or `gh release download` for retained artifacts.

The main-only `deploy/release-push` job downloads that run's retained binaries
and calls `ts-orch release push` for the regions in
[`deploy/m1/regions.json`](../deploy/m1/regions.json). GitHub OIDC is the push
credential; workflow identity and permissions authorize the release listener.
The job fails if any target region does not report the release serving and
retains its JSONL result and timings. Runtime credentials remain managed by
OCI Vault. This documentation change performs no live rollout.

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
and the repository's merge queue. It needs scoped cross-repository write
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
