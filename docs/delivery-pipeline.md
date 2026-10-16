# Delivery pipeline

The primary deployment input is an already signed bundle:

```sh
ts-orch release apply --dir BUNDLE --root-key TRUSTED_ROOT --namespace NS
```

`BUNDLE/GRU/channel.json` and other region documents carry the existing
root-delegated release proofs; `BUNDLE/binaries/<sha256>` supplies the bytes.
Application verifies trust, scope, digests and channel ordering, then publishes
to existing OCI channels. Region consumers verify locally and poll for updates.
Application needs no GitHub repository, `gh`, Git checkout or signing secret.
A webhook may hint that new data exists; no hint authorizes a release. No new
webhook endpoint or provider storage adapter is implemented.

The signed channel sequence remains the `run_number` wire field, currently a
CI counter. Provider-independent allocation is unresolved: changing producers
must preserve its monotonic ordering. See [release application](releases.md#apply-a-signed-release-bundle).

The stages below describe the current GitHub producer and image adapter.
Missing `TerraScale/terrabase`, `TerraScale/ts-auth` and `TerraScale/ts-libs`
repositories (404 to the current account) block its fresh qualified image/E2E
inputs, not application of an independently prepared signed bundle. Historical
Forgejo evidence and signed records retain their original identities.

The existing GitHub producer/image route: merge → CI → retained artifacts →
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
                                  ts-orch image promote (operator, one command) ◄────┘
                                  verify ─► OCI import ─► sign-image ─► verify-image ─► receipt
                                                                                             │
                                  launch / rollout through signed desired state ◄────────────┘
```

## Stages

### 1. Orchestrator CI (`.github/workflows/ci.yml`)

Runs on every push to `main` or `develop`, including documentation-only
changes. A newer push cancels a running check of the same
branch; on `main` the newest revision contains every older one and is the
candidate. The run stays one job because `ts-orch release` admission requires
exactly one job in the qualifying run, so parallelism is inside it:
`make ci-verify` runs gofmt, `go vet`, all native Go driver contracts, the sharded race
tests (`scripts/ci/racetest/race-test.sh`) and the static release build at once. The
job then retains both binaries and `qualification.json` (the completion
marker) on `ci-<sha>-run-<id>`. On `main` its last step dispatches
`image.yml` for the same revision, so the image job never holds a builder
slot while the checks run. It dispatches only when an image input changed
since the newest image release's source (`scripts/ci/image-inputs-changed.sh`:
`deploy/image`, `deploy/systemd`, `deploy/udev`, `internal/image`,
`internal/netbird/client`, `image.yml`), and from a weekly scheduled run,
which deploys nothing. Running nodes take new binaries through self-update,
so a code-only merge needs no image. Pull requests run the fast test tier (`-short`)
and skip the admission client; pushes run every tier (CONTRIBUTING.md).

### 2. TerraBase CI (`terrabase/.github/workflows/fast.yml`)

`fast` (format, Clippy, Fast suite) and `release` (static x86_64 and ARM64
build, smoke run under qemu) run in parallel. On `main`, `release` retains
the exact bytes it tested on `ci-<sha>-run-<id>`; `publish` reads them back
once Fast passes, checks them against the release job's manifest, uploads
`qualification.json` and never rebuilds. It then pins the release in this
repository's `deploy/image/image-inputs.json` through
`scripts/ci/pin-terrabase.sh`, a data-only commit to `main` that runs
stage 1 and images the new pin.

### 3. Image (`.github/workflows/image.yml`, `deploy/image/`)

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
`SHA256SUMS` and `image-qualification.json`. Automatic builds queue rather
than cancel each other, so a running build always finishes. After preparing
its tools, an automatic build waits for its revision's `ci.yml` run and skips
itself if that run fails or is cancelled, or once a newer main revision has
passed `ci.yml` (`scripts/ci/image-superseded.sh`). `make image SOURCE=<sha>` runs the same
build on a developer machine from the same retained release.

### 4. Promotion (`ts-orch image promote`)

One operator command per image: it verifies the image release (digests,
successful image run and job attempt, log marker), the candidate binary and
base image, and the signed binary receipt; verifies independent production
qualification and retained evidence for the exact final disk; imports the QCOW2
through the in-binary OCI SDK; creates, signs and verifies the image
receipt with `ts-orch release`; and writes `promotion-receipt.json`. `--dry-run`
runs every read-only gate without importing or signing.

### 5. Rollout

A signed image OCID is what the bootstrap runbook
([region-bootstrap.md](region-bootstrap.md)) launches: the image receipt
travels in the root-signed manifest and each instance verifies it before its
controller starts. TerraBase binary updates do not need a new image: they
roll out through the managed update path and signed desired state.

### 6. Legacy combined signing and deployment (`.github/workflows/deploy.yml`)

Every successful push to `main`, including documentation changes, dispatches
deployment automatically. `ci.yml` dispatches it after the image dispatch; it waits for the
same `ci.yml` run, signs the binary update receipts with the update leaf
from OCI Vault and publishes the release to each region's head bucket, the
canary first, waiting for each region to report the rollout complete. A
region that rolls back fails the run and stops the fleet. See
[automatic fleet deployment](continuous-delivery.md#automatic-fleet-deployment-ts-557-part-1).

## Operator commands

```sh
# Build the image for a CI-qualified main revision on this machine.
make image SOURCE=<full sha> [IMAGE_OUT=/tmp/ts-image-<sha>]

# Every read-only promotion gate, no OCI writes and no signing.
ts-orch image promote --image-release image-<sha>-run-<id>-attempt-<n> \
  --out /tmp/promote-<sha> --delegation delegation.json --root-key root.pub --dry-run

# Import (idempotent); stops and prints the sign-delegation command for the OCID.
ts-orch image promote --image-release ... --out /tmp/promote-<sha>-import \
  --delegation delegation.json --root-key root.pub \
  --compartment-id <ocid> --namespace <ns> --bucket <bucket>

# Same command again with the image-scoped delegation and the leaf key signs it.
ts-orch image promote ... --out /tmp/promote-<sha>-sign \
  --image-delegation image-delegation.json --signing-key leaf.pem

# Pin a TerraBase release by hand (standard gh on PATH).
scripts/ci/pin-terrabase.sh ci-<terrabase sha>-run-<run id>
```

To rebuild a named revision in CI, run the "Qualified GRU ARM64 image"
workflow on `main` from the GitHub Actions page with `source_revision` set;
it needs no other input. `--sign-binary --signing-key leaf.pem` also signs the
binary receipt when the candidate's CI release has none. Local builds are
promoted with `--image-dir`.

## What is automated

| Step | Trigger | Manual input |
| --- | --- | --- |
| Orchestrator checks, binaries, qualification | push to `main` | none |
| Image build and retention | start of `ci.yml` on `main`, built once it passes | none (optional dispatch of a named revision) |
| TerraBase checks, tested-bytes publication | push to TerraBase `main` | none |
| TerraBase pin bump into the image inputs | end of TerraBase `publish` | `TS_PIN_BUMP_TOKEN` secret (decision 2) |
| Local image build | `make image SOURCE=<sha>` | revision |
| Verification, OCI import, image signing, receipt | `ts-orch image promote` | leaf signing key, root-signed delegation, OCI target |
| Binary update signing and region-by-region rollout | every green push to `main` | monthly root-signed update delegation |
| TerraBase and ts-auth rollout to every region | their `main` CI `deploy` job ([automatic service releases](continuous-delivery.md#automatic-service-releases-ts-610)) | none |

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
