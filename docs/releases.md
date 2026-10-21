# Build and release boundaries

## Apply a signed release bundle

```sh
ts-orch release apply --dir BUNDLE --root-key TRUSTED_ROOT --namespace NS
```

Deployment consumes signed release channels and exact binary bytes. It does
not require a GitHub repository, `gh`, Git, a source checkout or a signing
secret. The publisher prepares the root-delegated release proofs; application
verifies them against the trusted root before publishing to each region's
existing OCI channel. OCI access authorization is still required.

```text
BUNDLE/
  GRU/channel.json
  SJC/channel.json
  FRA/channel.json
  binaries/<sha256>
```

Each region directory contains its `releasechannel.Channel` document. Binary
file names are their exact SHA-256 digests. Existing region consumers verify
the delegated scope, signed receipts and binary digests locally, and enforce
channel ordering and rollback rules.

Application takes regional targets from the signed bundle directories; applying
an existing release needs no live Atlas or CI discovery. It verifies local trust
and shared binary metadata before any remote write, inspecting each digest once.
Regional scope preflight, transfer, channel admission and observation then run
independently with at most four regions active. An unreachable or invalid region
reports its own error while healthy regions finish. Each active region receives
its own bounded rollout deadline. Reapplying the same bundle reuses immutable
bytes and preserves channel ordering.

Each target still requires its fresh regional deployment scope. This updates
existing regions; initial infrastructure, identity and regional bootstrap remain
separate work. Local signatures, mixed release identities or tampered bytes fail
the shared bundle check before any region is changed.

A webhook may notify consumers that new data is available. The notification
carries no release authority: consumers must fetch and verify the signed
channel and bytes. Polling recovers missed notifications. No new webhook
endpoint or provider storage adapter is implemented by this change; the
application path still publishes to existing OCI storage.

The existing `run_number` wire field supplies the monotonically increasing
channel sequence and currently holds a CI run number. Independent providers'
counters are not interchangeable. A provider-independent sequence allocator
or counter migration remains unresolved; switching producers must preserve
the established ordering.

GitHub Actions remains a source/build producer adapter. Its run/job checks and
signing can prepare a bundle, but GitHub metadata is not an application-time
authority. The combined `release deploy` signing workflow remains a legacy
producer/application path, rather than the primary deployment contract.

## GitHub producer verification

The GitHub verification workflow checks out the event's exact Git revision and
requires a clean tree. Its producing job runs `make ci-verify`: Go formatting
checks, `go vet`, and the complete Go test suite with race detection, including
deployment and qualification driver contracts. The workflow uses Go 1.27.1;
the `terrascale-builder` image supplies that exact version and `.mise.toml`
pins the same version for local development.

Release admission requires the exact successful run and one uniquely named
producing job from its qualification manifest. Independent workflow checks,
including the configuration policy check, may run alongside it. Admission reads
that producing job's logs by job ID and requires its exact retained-manifest
digest marker; another job's success or log cannot qualify the release.

The same job then cross-compiles one static executable for Linux amd64 and one
for Linux arm64 with cgo disabled. It checks the ELF machine type, absence of a
dynamic interpreter and linked libraries, the embedded Git revision, and
SHA-256 digests. It prints a `SHA256SUMS` receipt in the job log.
After those checks, the job retains both exact binaries with a qualification
manifest that records the source revision and tree, Go version, module-file
digests, successful workflow/job run identity, and each artifact's size and
SHA-256.

## External canary binary signing

`ci.yml` is the producer for release inputs; CI retains the exact static
amd64 and arm64 binaries and `qualification.json` on the prerelease tag
`ci-${SOURCE_SHA}-run-${RUN_ID}`. The manifest binds each artifact's name,
architecture, byte size, and SHA-256 to the full source revision and tree,
Go version, module-file digests, CI run ID and number, workflow, job, and
successful conclusion. The manifest is uploaded after the binaries and is the
CI release's completion marker. CI does not sign those artifacts.

The same CI job also publishes the source-matched D15 diagnostic
ARM64 executable `terrascale-d15-qualify` and its separate
`terrascale-d15-probe.json` descriptor on that tag. CI downloads both back
and compares their exact bytes before uploading `qualification.json`. The
binary qualification manifest retains its strict two-binary schema; the
D15 probe is not a signed release binary or an image input. For D15, an
operator downloads the probe, descriptor, and completed binary qualification
manifest with `gh release download`, saves
`ts-orch release run-detail --repository TerraScale/ts-orchestrator --run-id "$RUN_ID"`, then
fetches that readback's one producing job log with
`gh api "repos/TerraScale/ts-orchestrator/actions/jobs/$JOB_ID/logs"`. The
`ts-orch runtime-priority probe-admission` check requires exact timestamped
probe and binary qualification digest markers in that job log and binds their
exact hashes, source/tree, successful run, producing job ID, attempt, and job
log hash in a pinned receipt.
See [D15 guest staging](../tests/runtime_priority/README.md#verify-each-target-guest)
for the readback commands, temporary root-owned path, and manifest fields.
This source route permits qualifying the unchanged cc9a ARM image. It does
not establish that the image's runtime or any live guest passed D15 pressure.

The former Forgejo backend had no protected-environment reviewer gate or
scoped Actions secrets. That historical limitation led to retiring the old
`release.yml` signing job. GitHub migration does not replace the independent
review or locally authorized signing process. Retain the actual review
decision and operator log separately; a public JSON `reviewer` field alone
does not authenticate approval.

Before signing, confirm through `gh` that the live `refs/heads/main` still
matches the exact qualified source commit and tree. Independently record the
source and tree, CI run ID and number, workflow, successful job name and exact
attempt, binary size and digest, qualification-manifest digest, delegation
digest and scope, and trust-key digests. The expected root public-key PEM SHA-256 is
`548426817b9ab219720d4a934703b7dfbd5b63633533a9340ec4e19c2fb65e5e`; the
expected delegated canary leaf public-key PEM SHA-256 is
`afb5b4e956b1d42f50679afea44dcd5774ed43348d9077a51baabe32f82d4486`. An
authorized root-key owner locally issues a new current delegation for that
exact source and the arm64 canary binary capability. Do not reuse a delegation
bound to an older source revision. Keep both root and delegated private keys
in owner-only local files; do not put private-key bytes or file paths in
release assets or shared review/operator records.

The root and canary leaf were replaced on 2026-10-05 for the gru-1 rebuild
(TS-470): the previous root's private key was not available, and no cell
trusts it after the GRU wipe. The image pins the new root as
`internal/trust/bootstrap-root-002.pem`. The private keys are kept
owner-only by the operator, who signs from those files. The gru-1 OCI Vault
(compartment `TerraScale`, operator-only) holds durable copies of all four
PEMs as secrets `gru-1-trust-root-private-key`,
`gru-1-trust-root-public-key`, `gru-1-trust-release-leaf-private-key` and
`gru-1-trust-release-leaf-public-key` (TS-534). They are not in OpenBao.

Build the local signing helper from the same clean source checkout with Go
1.27.1, low priority, and embedded VCS metadata. Check `go version -m` for the
exact `vcs.revision` and `vcs.modified=false` before using it. This helper is
not the deployed orchestrator binary; deployments use the CI-retained bytes.
For the signer's live GitHub check, install and authenticate the standard
`gh` CLI on the operator host. `ts-orch release run-detail --repository
TerraScale/ts-orchestrator --run-id "$RUN_ID"` reads GitHub's native run and
paginated job APIs and emits the normalized admission record. Keep root-key and delegated-key operations with their
respective local key owners; pass only the public root PEM, leaf PEM, and
delegation between those steps. Do not transfer either private key.

Choose `SOURCE_SHA`, `RUN_ID`, and `RUN_NUMBER` from the successful `ci.yml`
run under review, then download its two retained inputs with `gh release
download`. Clone the live repository with `gh` and confirm the checked-out
`main` commit and tree equal the qualification manifest before signing. Build
the local helper from that same clean checkout and require the embedded
revision and clean-tree metadata to match:

```bash
set -euo pipefail
umask 077
# Export these from the selected successful CI run and use a new private work directory.
: "${SOURCE_SHA:?set the selected full CI source SHA}"
: "${RUN_ID:?set the selected GitHub run ID}"
: "${RUN_NUMBER:?set the selected GitHub run number}"
: "${ISSUED_AT_UTC:?set a canonical UTC delegation start time}"
: "${EXPIRES_AT_UTC:?set a canonical UTC delegation expiry}"
[[ $SOURCE_SHA =~ ^[0-9a-f]{40}$ && $RUN_ID =~ ^[1-9][0-9]*$ &&
   $RUN_NUMBER =~ ^[1-9][0-9]*$ ]]
WORK=$(mktemp -d)
TAG="ci-${SOURCE_SHA}-run-${RUN_ID}"
gh release download "$TAG" --repo TerraScale/ts-orchestrator \
  --pattern qualification.json --output "$WORK/qualification.json"
gh release download "$TAG" --repo TerraScale/ts-orchestrator \
  --pattern terrascale-orchestrator-linux-arm64 --output "$WORK/terrascale-orchestrator-linux-arm64"
test "$(jq -r .source_revision "$WORK/qualification.json")" = "$SOURCE_SHA"
test "$(jq -r .verification.run_id "$WORK/qualification.json")" = "$RUN_ID"
test "$(jq -r .verification.run_number "$WORK/qualification.json")" = "$RUN_NUMBER"

gh repo clone TerraScale/ts-orchestrator "$WORK/source-main"
test "$(git -C "$WORK/source-main" branch --show-current)" = main
test "$(git -C "$WORK/source-main" rev-parse HEAD)" = "$SOURCE_SHA"
SOURCE_TREE=$(jq -r .source_tree "$WORK/qualification.json")
test "$(git -C "$WORK/source-main" rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE"
cd "$WORK/source-main"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test "$(go env GOVERSION)" = go1.27.1
nice -n 19 go build -trimpath -buildvcs=true \
  -o "$WORK/ts-orch" ./cmd/terrascale-orchestrator
build_info=$(go version -m "$WORK/ts-orch")
grep -Fq "vcs.revision=$SOURCE_SHA" <<< "$build_info"
grep -Fq 'vcs.modified=false' <<< "$build_info"

# The authorized root-key owner supplies the pinned public PEMs locally.
cp -- /LOCAL/PINNED/canary-release-root.pub "$WORK/canary-release-root.pub"
test "$(sha256sum "$WORK/canary-release-root.pub" | awk '{print $1}')" = \
  548426817b9ab219720d4a934703b7dfbd5b63633533a9340ec4e19c2fb65e5e
test "$(sha256sum /LOCAL/PINNED/canary-release-leaf.pub | awk '{print $1}')" = \
  afb5b4e956b1d42f50679afea44dcd5774ed43348d9077a51baabe32f82d4486
"$WORK/ts-orch" release sign-delegation \
  --subject-public-key /LOCAL/PINNED/canary-release-leaf.pub \
  --root-key "$WORK/canary-release-root.pub" \
  --signing-key /ABSOLUTE/OWNER-ONLY/offline-root-key.pem \
  --source-revision "$SOURCE_SHA" --arch arm64 --environment canary \
  --issued-at "$ISSUED_AT_UTC" --expires-at "$EXPIRES_AT_UTC" \
  --out "$WORK/canary-release-delegation.json"
"$WORK/ts-orch" release run-detail --repository TerraScale/ts-orchestrator --run-id "$RUN_ID" \
  > "$WORK/ci-run-detail.json"

"$WORK/ts-orch" release binary-candidate \
  --binary "$WORK/terrascale-orchestrator-linux-arm64" \
  --source-revision "$SOURCE_SHA" \
  --qualification "$WORK/qualification.json" \
  --out "$WORK/canary-linux-arm64.candidate.json"
"$WORK/ts-orch" release sign-binary \
  --candidate "$WORK/canary-linux-arm64.candidate.json" \
  --binary "$WORK/terrascale-orchestrator-linux-arm64" \
  --qualification "$WORK/qualification.json" \
  --delegation "$WORK/canary-release-delegation.json" \
  --root-key "$WORK/canary-release-root.pub" \
  --signing-key /ABSOLUTE/OWNER-ONLY/canary-release-key.pem \
  --environment canary \
  --out "$WORK/canary-linux-arm64.receipt.json"
"$WORK/ts-orch" release verify-binary \
  --receipt "$WORK/canary-linux-arm64.receipt.json" \
  --delegation "$WORK/canary-release-delegation.json" \
  --root-key "$WORK/canary-release-root.pub" \
  --binary "$WORK/terrascale-orchestrator-linux-arm64" \
  --qualification "$WORK/qualification.json" \
  --environment canary
```

`ISSUED_AT_UTC` and `EXPIRES_AT_UTC` must be current canonical RFC3339 UTC
instants ending in `Z`; a delegation can last no more than 365 days. The root
key owner runs `sign-delegation` locally and provides only the resulting public
delegation to the delegated-key owner, who runs `sign-binary`. Record the
successful job attempt from the `ts-orch release run-detail` output as part of the
independent review evidence.

`sign-binary` checks that the candidate, retained binary, and exact
qualification bytes agree, then uses the standard `gh` CLI to confirm the
CI run's ID, number, full source revision, workflow, successful job, and one
exact manifest-digest marker in its log. It also requires a current
root-signed delegation with the matching canary scope. `verify-binary` checks
the current delegation and receipt and re-inspects the exact binary bytes and
build metadata. These checks do not replace the independent review of the live
main ref and pinned key identities.

The signed receipt, delegation and root key may be published on the same CI
tag (`canary-linux-arm64.receipt.json`, `canary-release-delegation.json`,
`canary-release-root.pub`) with `gh release upload`, reading each back
with `gh release download` and `cmp`; `ts-orch image promote`
uses a receipt found there. It can also sign the binary itself
(`--sign-binary --signing-key`), after the same `binary-candidate` and
GitHub run checks. Any optional JSON copy of the review record is audit-only
and must not be represented as authenticated approval.

### Image CI provenance

A `ci.yml` run on `main` ends by dispatching `image.yml` for its exact
revision once the release is retained (`scripts/ci/dispatch-image.sh`),
so the image job never holds a
builder slot while the checks run. It does so only when an image input
changed since the source of the newest `image-*` release, or the comparison
cannot be made, and on the weekly scheduled run (TS-562). The image job confirms that run succeeded
and builds only if it did; where the runner supplies real-infrastructure
fixtures it first runs the qualification tier (`scripts/ci/qualify-image.sh`,
see CONTRIBUTING.md). These automatic builds queue; one that a newer
qualified revision has overtaken skips itself. An operator can dispatch `image.yml` with
`source_revision` for any other CI-qualified `main` revision; no run IDs,
tags or digests are copied by hand. The image job
(`deploy/image/build-image.sh`, the same script `make image SOURCE=<sha>`
runs locally) finds its candidate by source revision:

- it looks up the successful `ci.yml` run on `main` for that revision through
  the Actions API, downloads `qualification.json` and the arm64 binary from
  `ci-${SOURCE_SHA}-run-${RUN_ID}`, and requires the manifest's source, tree,
  module digests, run identity and binary digest to match, the `ts-orch release run-detail` readback to show the successful job, and the job log to
  carry the exact `TS_RELEASE_QUALIFICATION_V1` marker for the manifest bytes;
- every other input is data in `deploy/image/image-inputs.json`: the base
  QCOW2 and Ubuntu checksum files retained once on the
  `image-base-noble-arm64-20260926` release (pinned by size and SHA-256, the
  checksum signature verified against the pinned signer, the QCOW2 against
  the signed checksum), the base OCID and kernel release, the trust root and
  timesyncd config checked in under `deploy/image/inputs`, the priority
  profile, and the TerraBase artifact pin. `ts-orch image inputs`
  validates the file; its `pin-terrabase` command rewrites only the TerraBase
  pin from a published, Fast-qualified release, and the build re-derives that
  pin from the release to prove it. When its original release/run is gone,
  `terrabase.archive` selects a retained copy in ts-orchestrator: the build
  verifies the pinned image qualification and exact binary SHA-256, and
  requires that image's original TerraBase pin to match all source, run and
  qualification fields. Archive tags start `native-verifier-alpha-` and
  are outside the CI release-pruning pattern. The verifier remains mandatory
  for production managed-material preparation, including C# workload cells.

The build checks the binary with `ts-orch release binary-candidate` (static ARM64
ELF, Go toolchain, clean embedded revision, size and digest against the
qualification). The signed binary receipt is not an image input any more: it
is verified when the image is promoted. The tools (qemu, libguestfs with its
appliance, guestfs-tools, systemd, gnupg) come from one pinned nixpkgs
revision through `deploy/image/tools.sh`, which keeps their closure in the
runner's `/cache/nix` binary cache.

The job retains the image under
`image-${SOURCE_SHA}-run-${GITHUB_RUN_ID}-attempt-${run_attempt}`
(`deploy/image/publish-image.sh`). The retained `image-qualification.json`
(schema v2) records the source revision and tree, the image run, job ID and
attempt, the inline input manifest and its digest, the orchestrator
candidate's release, run and digests, the TerraBase release, the tool
versions, and the image and kernel digests. The QCOW2, `guest-kernel` and
`SHA256SUMS` are uploaded and read back first and the manifest last; the job
then logs one `TS_IMAGE_QUALIFICATION_V1` marker with the source SHA, run ID
and number, job ID, attempt, image, kernel and manifest digests, and tag. The
marker is written before the job finishes, so it does not prove the run
passed.

### Image promotion

`ts-orch image promote` turns a retained image release (or a local
`make image` directory) into a signed OCI image in one command and writes
one `promotion-receipt.json`. It stops at the first failed gate:

1. it downloads the four image assets, checks `SHA256SUMS`, and for a CI
   image requires the completed `image.yml` run and job attempt to have
   succeeded and the job log to carry the exact marker for these bytes;
2. it downloads the candidate binary, `qualification.json` and the pinned
   base QCOW2 and checks them against the image manifest;
3. it builds `ts-orch` from the image's clean source revision and runs
   `release verify-binary` on the signed binary receipt;
4. it verifies independent production qualification and retained evidence for
   the exact final QCOW2, then imports it through the in-binary OCI SDK (UEFI
   and paravirtualized capability schema, A1-only shapes; idempotent);
5. it runs `image-candidate` for the imported OCID, then, given the
   root-signed delegation extended to that OCID (`--image-delegation`),
   `sign-image` (which again checks the `ci.yml` run and qualification marker
   through the standard `gh` CLI and compares the binary extracted from the QCOW2
   with `virt-cat`) and `verify-image`.

The root owner can extend a delegation to an image only once its OCID exists
(`ts-orch release sign-delegation --previous-delegation ... --image-cell GRU
--image-ocid ...`). A first run without `--image-delegation` therefore stops
after the import and prints that command for the imported OCID; the rerun
with the extended delegation repeats every gate, finds the same image, and
signs it. `--sign-binary` signs the binary receipt with the leaf key when the
candidate's CI release has none.

`--dry-run` runs every read-only gate and builds the image candidate against
a placeholder OCID without importing or signing. The command re-executes
itself under `deploy/image/tools.sh` for `virt-cat`, and requires standard
`gh` on PATH; the receipt records the GitHub CLI binary hash and tool provenance.
`sign-image` does not itself
consume `image-qualification.json`; the image-run and marker checks are the
promotion command's and are recorded in its receipt.

`internal/release` owns the v2 binary and image receipt wire types, scope rules,
and current and historical verification. Each receipt requires the SHA-256 of
the exact qualification manifest. Binary receipts bind that manifest to the
source revision and retained static executable. Image receipts bind it to the
same qualified binary, the candidate QCOW2, its base image and kernel, and the
asserted custom-image OCID and region. Current verification requires a live
root-signed release delegation with a maximum 365-day lifetime and a receipt
with its separately defined 365-day maximum. Signing applies the same limits
and caps receipt expiry at the remaining delegation lifetime. Historical
verification returns a distinct audit-only proof and cannot serve as current
authorization. The verified image proof exposes SHA-256 of the exact canonical
envelope wire; this is the digest pinned by
`Manifest.ReleaseReceiptSHA256`, not a payload-only digest.
The accepted bootstrap wire direction carries the public image-receipt
envelope and release-delegation envelope in the root-signed manifest after OCI
image import; the runtime checks the envelope digest against this pin and
checks the receipt's environment, region, image OCID, and architecture against
the signed manifest before trusting the receipt. Neither image-candidate nor
sign-image reads image bytes back from OCI: they inspect the supplied local
QCOW2 and accept the imported image OCID and region as inputs. OCI read-back and
deployed-image execution therefore remain separate evidence.

`internal/release/cli` checks static ELF and embedded Go build metadata and consumes
the shared verifier for binary and image promotion receipts. OCI object upload
is bounded to 512 MiB, streams from disk, uses conditional create, and accepts
an existing object only after a matching streamed SHA-256/size read-back. Image
receipts bind the base and custom image OCID to the logical region and compare
the signed binary with bytes extracted from the final QCOW2 by `virt-cat`.
The controller's bootstrap oneshot now verifies the baked identity and anchor,
current image receipt, instance receipt, and current regional grant before the
controller service starts. The host service still starts independently from
its role config and does not run this image admission path; host startup
admission remains open.

`deploy/image/build-offline.sh` qualifies the binary with `ts-orch release
binary-candidate`, requires a standalone QCOW2 base, and completes the
candidate through filesystem-only guestfish operations in one appliance
session. Before any write it audits the base kernel (exactly one
`/boot/vmlinuz-RELEASE` AArch64 Image with its `/lib/modules/RELEASE`
directory, extracted to `--kernel-out`) and the guest's Noble systemd 255
unit metadata. It stages account creation with host `systemd-sysusers
--root` and unit enablement with host `systemctl --root`; the resulting files
and symlinks are written and read back offline, and a second, read-only
appliance reads the orchestrator binary, native verifier and kernel back from
the finished QCOW2. A scoped container runner can be supplied as
`TS_OFFLINE_GUESTFS_RUNNER` when guestfish is unavailable on the build host.
The image is deployment-neutral: the only deployment-related inputs are one
or more public bootstrap root PEMs (1 through 16 files, each bounded to 16
KiB and 64 KiB total). The deployment identity, signed anchor and host
enrollment bundle arrive in OCI launch metadata and are verified against
these roots on the instance; the builder rejects flags for them and fails if
the base image already contains any of them.

The same image build now requires the exact qualified ARM64 TerraBase
`tb-server-linux-arm64` artifact as `--native-verifier-binary` and its
independent lowercase SHA-256 as `--native-verifier-sha256`. Select the digest
from that artifact's passing TerraBase Fast `qualification.json` record and
verify the downloaded bytes before invoking the builder. The builder copies
the input once, checks its 1–128 MiB size, ELF64 little-endian AArch64
executable header and exact digest, then installs it root-owned at
`/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server`
with mode `0755` and a nonwritable directory chain. It reads the installed
bytes back from the candidate QCOW2 with `virt-cat` and requires the same
digest before publishing the candidate. Pass that digest as the separately
root-signed `ManagedMaterialDomain.NativeVerifierSHA256` field; never use the
orchestrator receipt's `BinarySHA256` for the TerraBase binary. The normal
image receipt signs the final QCOW2 containing both executables. A booted
ARM64 guest still must prove the installed TerraBase command
`validate-managed-material-v1` and its request/verdict contract before the
managed-material path is qualified; offline ELF and digest checks alone do
not prove that command is present or functional.

The candidate contains the verified root set as sequential
`/etc/terrascale-orchestrator/bootstrap/trust-roots/NNN.pem` files starting at
`001.pem`, matching the runtime loader's accepted names. Those files are
root-owned and mode `0444`; their directories are root-owned and mode `0755`.
The image also has the root-owned `0755` bootstrap marker directory and the
empty `terrascale-orchestrator`-owned `0700` secret-material directory. The
runtime bootstrap unit creates its `0700` `/run` staging directory for each
start. No private signing keys, release tools, deployment material, or
runtime secret bytes are copied into the guest.

The builder also requires an explicit `--timesyncd-config` file with a
nonempty `[Time] NTP=` list. It bounds the input to 16 KiB and interprets
repeated `NTP=` and `FallbackNTP=` assignments as systemd lists: nonempty
assignments append servers, while an empty assignment resets the accumulated
list. It rejects unsupported continuations, quoting, escapes, and inline
comments on those server assignments. The builder removes the input's server
assignments, preserves its other settings and comments, then writes normalized
`NTP=` and `FallbackNTP=` settings with an empty reset before each effective
list. This removes reset-away lab entries and explicitly clears distribution
fallback defaults unless a fallback list was supplied. The effective lists
must not contain the Firecracker qualification range. The normalized file is
installed at
`/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf`; the builder
also pins `PollIntervalMinSec=32` and `PollIntervalMaxSec=64`, replacing any
poll interval values in the input. The bounded polling limits unchecked growth
of the kernel NTP maximum error between samples; admission still requires a
fresh measured error no greater than 250 ms.
The builder prints the installed config's SHA-256 for review. The deployment
must provide reachable NTP endpoints for its network, and the builder does not
bake the lab endpoint. The
resulting config is part of the image signed by the normal release flow.

Before installation, the builder fails closed if it finds an active static
`NTP=`, `FallbackNTP=`, `PollIntervalMinSec=`, or `PollIntervalMaxSec=` assignment
in the base image's timesyncd config. It
checks the systemd v255 main-file paths `/etc/systemd/timesyncd.conf` and
`/usr/lib/systemd/timesyncd.conf`, with `/etc` taking precedence, and the
drop-in paths `/etc/systemd/timesyncd.conf.d`,
`/run/systemd/timesyncd.conf.d`, `/usr/local/lib/systemd/timesyncd.conf.d`,
and `/usr/lib/systemd/timesyncd.conf.d`. For drop-ins, a same-name file in a
higher-priority directory shadows the lower-priority file; `/dev/null` masks
are honored. Dangling symlinks and config inspection errors fail the build.
This scan covers static files only. systemd-timesyncd may also receive NTP
servers from DHCP or per-link network configuration, which the offline builder
does not inspect or suppress. Production qualification must establish that
the image's network policy supplies only approved reachable servers.

The image installs the single orchestrator executable, sysusers definition,
and bootstrap, controller, host, and host-volume-initializer systemd units. It
requires the base image to provide both `systemd-timesyncd.service` and
`systemd-time-wait-sync.service`; offline enablement fails the build if either
unit is unavailable, and the builder does not install packages. The inspected
upstream systemd v255 wait unit sets an unbounded start timeout, so the image
adds a root-owned `0644` drop-in setting `TimeoutStartSec=300s`. The bootstrap
unit requires and starts after timesyncd and the wait unit before doing admission;
the controller's existing `Requires=`/`After=` relationship carries that
ordering forward. A wait timeout or time-service failure prevents bootstrap
and controller startup, while the controller still applies the runtime
kernel-clock check before broker effects. The builder enables the time
services, controller, and host units. Each orchestrator service has a
`ConditionPathExists` for its role config, so an unprovisioned image leaves the
controller and host inactive. The builder makes no OCI calls. A future image
receipt can only be made after a custom image has been imported and its OCI
image OCID is known. This workflow has not been run because the pinned base
image, signer, and image-import authorization are not yet approved.

Every image can run the managed host, so the offline builder also checks that the base guest
already contains `e2fsprogs` `1.47.0-2.4~exp1ubuntu4.1` and `util-linux`
`2.39.3-9ubuntu6.6`, and that `/usr/sbin/mkfs.ext4`, `/usr/sbin/blkid`, `/usr/sbin/wipefs`, and
`/usr/bin/mount` resolve to executable guest files. It follows tool symlinks
within the guest root and fails on missing packages, version mismatches, or
missing/nonexecutable tools; it does not install packages. The image stages
the separate root service and root-owned mode-`0600` socket, and enables the
socket. The service's capability bounding set is `CAP_SYS_ADMIN CAP_CHOWN`. It
also provisions `/var/lib/terrascale-orchestrator-volume-init` as root-owned
mode `0700` for the helper's local format-attempt record. The helper has no
private filesystem namespace, so its verified mount is visible in the host
service's mount namespace. [`guestfs`](../internal/image/guest.go), [image-builder tests](../tests/deploy/build_offline_test.go), [initializer service](../deploy/systemd/terrascale-orchestrator-host-volume-init.service), [initializer socket](../deploy/systemd/terrascale-orchestrator-host-volume-init.socket).

The controller unit runs as the pre-created `terrascale-orchestrator` user,
reads `/etc/terrascale-orchestrator/controller.json`, and persists embedded
JetStream below `/var/lib/terrascale-orchestrator-controller`. Its config must
set `nats.embedded.store_dir` to a directory under that state root. The host
unit runs the one binary as root with `Delegate=yes`, `NoNewPrivileges=yes`,
and only `CAP_CHOWN`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, and
`CAP_DAC_READ_SEARCH`; its root-only config is
`/etc/terrascale-orchestrator/host.json`. `host.state_root` must be a private
child of `/var/lib/terrascale-orchestrator-host`, while `host.install_root` is
a separate child for tenant-group executable files. The unit's only extra
writable path is the canonical managed runtime root `/srv/ts-managed`, used
when `host.managed_runtime_root` selects it. Every image fixes workload
UID/GID to `2000:2000` and provisions `/srv/ts-managed` as `root:2000` mode
`0750`. The public enrollment bundle, delivered in launch metadata, fixes
`host.install_root` and `host.state_root` to separate children under
`/var/lib/terrascale-orchestrator-host`.
The strict systemd guest security run
passed all eight tests with no skips, including cross-UID child death after
the host supervisor receives `SIGKILL`; a later four-VM caller run against the
clock-gated harness is still pending.

Every production image must establish a synchronized kernel realtime clock
before opening its NATS broker or issuing/accepting JWT-backed sessions. Gate
service startup on `adjtimex` reporting `TIME_OK`, with `STA_UNSYNC` and
`STA_CLOCKERR` clear and `maxerror` at most 250 ms. This image path selects
systemd-timesyncd and its systemd time-wait unit, with deployment-supplied NTP
endpoints reachable on the guest network. The systemd wait is an initial
startup dependency; the Go kernel-clock predicate remains authoritative. A
manually set wall clock is not evidence of synchronization, and there is no
startup bypass for the time check.

## Local static build receipt

On 2026-09-24, `make release-linux` with Go 1.27.1 built source revision
`df09ee5692b4a5dc60230f019d1265efccb2f972`. Both outputs have the expected
ELF machine, no dynamic interpreter or linked libraries, and embedded
`vcs.modified=false` metadata for that revision. The local checksum receipt
is `dist/SHA256SUMS`.

| Artifact | Size | SHA-256 | Execution evidence |
| --- | ---: | --- | --- |
| `dist/terrascale-orchestrator-linux-amd64` | 21,008,544 bytes | `c577a52bbcd0e8dfbfbe6c3910141b42e9eae9444d0e5c92a97dbe29512c93da` | ELF-verified; Firecracker used its separately hashed harness build |
| `dist/terrascale-orchestrator-linux-arm64` | 19,267,744 bytes | `609d662e38bfe4fdf02b9670809865c9621df185f697e67c3b12f6d8144500f6` | Cross-compiled and ELF-verified; not executed |

These local outputs are not published or signed release assets. The distinct
amd64 binary used in the guest qualification is recorded in [local
development](local-development.md#prior-local-qualification-2026-09-24).

## Production qualification is separate from build provenance

`release deploy` requires retained production qualification for each inspected
regional candidate before retrieving the online release signer or publishing
objects. `qualification.json` remains build provenance; a green CI run alone
does not establish SwarmKit RUNTIME/HA or workload safety.

The retained release contains:

```text
production/
  GRU/amd64/production.json
  GRU/amd64/delegation.json  # only for a delegated qualification signer
  objects/<sha256>          # exact retained gate evidence bytes
```

Each `production.json` is a canonical `trust.Envelope` in the
`terrascale.release.production-qualification` domain. Its scope binds the build
identity, region, environment, workload role and `swarmkit-containerd/linux-ARCH`
slot. Its `terrascale.release.production-qualification.v1` payload binds the
exact source, binary digest and qualification-manifest digest, with ordered
`runtime-ha` and `workload-safety` evidence references. Every reference includes
its SHA-256, byte count and completion time. Admission verifies the referenced
bytes, requires both passing-gate attestations and refuses proofs completed
after signing. Signature/delegation validity must cover the rollout deadline;
accepted lifetimes remain bounded to 31 days.

The trusted root may sign qualification directly. A delegated signer needs an
explicit `sign` capability for this distinct domain and exact scope. The
ordinary release leaf's binary-signing authority does not grant qualification
authority. This repository supplies the consumer; it does not manufacture live
qualification evidence or install a signing credential.

Inspect retained admission independently:

```sh
ts-orch release verify-production --dir RELEASE --root-key TRUSTED_ROOT \
  --cell GRU --arch amd64
```

The default evidence directory is `RELEASE/production`. Versioned JSON reports
qualified/refused results for each requested region; another region's refusal
does not erase successful checks. This read-only command also inspects actual
candidate binary metadata and matches the retained build manifest.
