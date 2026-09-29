# Delivery pipeline

How a merged change reaches the servers: merge → CI → retained artifacts →
image → OCI import → rollout. Every stage finds its input from the previous
stage's retained record by source revision; nothing is copied by hand except
the signing and authorization decisions policy requires.

```text
ts-orchestrator main push ──► ci.yml (one job) ──► ci-<sha>-run-<id> release ──dispatch──► image.yml
                                                    binaries + qualification.json           │
TerraBase main push ──► fast.yml: fast ∥ release ──► publish ──pin bump──► image-inputs.json │
                                     (retained bytes)  (promotes, no rebuild)                ▼
                                                            image-<sha>-run-<id>-attempt-<n> release
                                                                                             │
                                  deploy/image/promote-image.py (operator, one command) ◄────┘
                                  verify ─► OCI import ─► sign-image ─► verify-image ─► receipt
                                                                                             │
                                  launch / rollout through signed desired state ◄────────────┘
```

## Stages

### 1. Orchestrator CI (`.forgejo/workflows/ci.yml`)

Runs on every push to `main` or `develop` except documentation-only changes
(`docs/**`, `**/*.md`). A newer push cancels a running check of the same
branch; on `main` the newest revision contains every older one and is the
candidate. The run stays one job because `ts-release` admission requires
exactly one job in the qualifying run, so parallelism is inside it:
`make ci-verify` runs gofmt, every Python suite, `go vet`, the sharded race
tests (`scripts/ci/race-test.sh`) and the static release build at once. The
job then retains both binaries and `qualification.json` (the completion
marker) on `ci-<sha>-run-<id>` and, on `main`, dispatches `image.yml` for the
same revision.

### 2. TerraBase CI (`terrabase/.forgejo/workflows/fast.yml`)

`fast` (format, Clippy, Fast suite) and `release` (static x86_64 and ARM64
build, smoke run under qemu) run in parallel. On `main`, `release` retains
the exact bytes it tested on `ci-<sha>-run-<id>`; `publish` reads them back
once Fast passes, checks them against the release job's manifest, uploads
`qualification.json` and never rebuilds. It then pins the release in this
repository's `deploy/image/image-inputs.json` through
`scripts/ci/pin-terrabase.sh`, a data-only commit to `main` that runs
stage 1 and images the new pin.

### 3. Image (`.forgejo/workflows/image.yml`, `deploy/image/`)

`build-image.sh` checks out the named revision and reads every other input
from `deploy/image/image-inputs.json`: the base QCOW2 retained once on
`image-base-noble-arm64-20260926` and verified against Ubuntu's signed
checksums, the trust root and timesyncd config under `deploy/image/inputs`,
the priority profile, and the TerraBase pin (re-derived from its release to
prove it). It finds the orchestrator binary from the successful `ci.yml` run
for the revision, verifies the manifest, run detail and log marker, and
builds a deployment-neutral image with `build-offline.sh` (trust roots only;
identity, anchor and enrollment arrive in launch metadata). The release
`image-<sha>-run-<id>-attempt-<n>` holds the QCOW2, guest kernel,
`SHA256SUMS` and `image-qualification.json`. `make image SOURCE=<sha>` runs
the same build on a developer machine from the same retained release.

### 4. Promotion (`deploy/image/promote-image.py`)

One operator command per image: it verifies the image release (digests,
successful image run and job attempt, log marker), the candidate binary and
base image, and the signed binary receipt; imports the QCOW2 with
`deploy/oci-region/import-image.py`; creates, signs and verifies the image
receipt with `ts-release`; and writes `promotion-receipt.json`. `--dry-run`
runs every read-only gate without importing or signing.

### 5. Rollout

A signed image OCID is what the bootstrap runbook
([region-bootstrap.md](region-bootstrap.md)) launches: the image receipt
travels in the root-signed manifest and each instance verifies it before its
controller starts. TerraBase binary updates do not need a new image: they
roll out through the managed update path and signed desired state.

## What is automated

| Step | Trigger | Manual input |
| --- | --- | --- |
| Orchestrator checks, binaries, qualification | push to `main` | none |
| Image build and retention | end of `ci.yml` on `main` | none (optional dispatch of a named revision) |
| TerraBase checks, tested-bytes publication | push to TerraBase `main` | none |
| TerraBase pin bump into the image inputs | end of TerraBase `publish` | `TS_PIN_BUMP_TOKEN` secret (decision 2) |
| Local image build | `make image SOURCE=<sha>` | revision |
| Verification, OCI import, image signing, receipt | `promote-image.py` | leaf signing key, root-signed delegation, OCI target |

## Measured (Forgejo runs, 2026-09-29)

| Stage | Before | After |
| --- | --- | --- |
| Orchestrator `ci.yml` | 7m56s warm (run 705), 13–17 min cold | 4m15s (run 717) |
| CI → image handoff | 5 values copied into a dispatch | 0; image job starts when CI ends (run 718 started 3 s after run 717) |
| Image tool setup | about 16 min (fj build + nixpkgs tools, run 702) | fj cache hit 4 s; tools from `/cache/nix` after the first build |
| Image appliance launches | 7 under TCG, about 70 s each | 2 |
| Local image build (KVM) | not available | 1m37s end to end |

## Open decisions

1. **OCI credentials for automatic import.** Import still needs a person
   with OCI access. Least privilege: a dedicated IAM user (or, better, a
   runner instance principal if the runner moves to OCI) in a group whose
   policy allows only `manage objects` in the image bucket, `manage
   instance-images` and `read compartments` in the image compartment — no
   instance, network or IAM rights — with its API key stored as a
   `main`-only Actions secret. Image *signing* stays manual until OD-1 is
   decided; import without signing yields an image nothing will launch.
2. **Cross-repository pin bump token.** The Actions token cannot write to
   another repository. A `TS_PIN_BUMP_TOKEN` for `terrascale-bot` scoped to
   `write:repository` on ts-orchestrator, stored as a TerraBase secret,
   enables stage 2's pin bump; until then the step skips itself.
3. **KVM for image jobs.** The runner container has no `/dev/kvm`, so each
   libguestfs appliance boots under TCG (about 70 s instead of 4 s measured
   locally). Passing `/dev/kvm` to the runner's job containers would cut the
   image build to about a minute.
4. **Builder image tools.** The image tools come from the pinned nixpkgs
   revision through `/cache/nix`. Baking them into ts-builder removes the
   first-run build but needs the runner to re-pull the builder image, which
   is a manual step today.
