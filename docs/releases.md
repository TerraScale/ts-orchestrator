# Build and release boundaries

The Forgejo verification workflow checks out the event's exact Git revision and
requires a clean tree. Its single job runs `make verify`: Go formatting
checks, the Python Firecracker harness contract tests, `go vet`, and
race-enabled Go tests using Go 1.27.1. The `terrascale-builder` image supplies
that exact Go version; `.mise.toml` pins the same version for local development.

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

The deployed Forgejo 16.0.4 backend has no protected-environment reviewer gate
or environment-scoped Actions secrets; the reviewed 16.0.5 source has the same
limitation. The former `release.yml` signing and publishing job is retired.
Canary signing therefore runs in a locally authorized operator process, with
an independent reviewer using the existing review/evidence channel. A public
JSON `reviewer` field is an audit assertion only; it does not authenticate a
review or provide a Forgejo approval. Retain the actual review decision and
operator log separately. Do not claim that Forgejo approved a release.

Before signing, confirm through `fj` that the live `refs/heads/main` still
matches the exact qualified source commit and tree. Independently record the
source and tree, CI run ID and number, workflow, successful job name and exact
attempt, binary size and digest, qualification-manifest digest, delegation
digest and scope, and trust-key digests. The expected root public-key PEM SHA-256 is
`bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc`; the
expected delegated canary leaf public-key PEM SHA-256 is
`ddd81158ef6f5ad7e42e3a87ec16665ed42d480a48ab69441cc12df0d4b629f3`. An
authorized root-key owner locally issues a new current delegation for that
exact source and the arm64 canary binary capability. Do not reuse a delegation
bound to an older source revision. Keep both root and delegated private keys
in owner-only local files; do not put private-key bytes or file paths in
release assets or shared review/operator records.

Build the local signing helper from the same clean source checkout with Go
1.27.1, low priority, and embedded VCS metadata. Check `go version -m` for the
exact `vcs.revision` and `vcs.modified=false` before using it. This helper is
not the deployed orchestrator binary; deployments use the CI-retained bytes.
For the signer's live Forgejo check, prepare the pinned `fj` extension locally
with `nice -n 19 bash scripts/ci/prepare-fj-admission.sh
/ABSOLUTE/PRIVATE/fj-admission` and use that directory in `PATH`; stock `fj`
does not provide the `actions run-detail` and `actions logs` commands required
by `ts-release`. Keep root-key and delegated-key operations with their
respective local key owners; pass only the public root PEM, leaf PEM, and
delegation between those steps. Do not transfer either private key.

Choose `SOURCE_SHA`, `RUN_ID`, and `RUN_NUMBER` from the successful `ci.yml`
run under review, then download its two retained inputs with `fj release asset
download`. Clone the live repository with `fj` and confirm the checked-out
`main` commit and tree equal the qualification manifest before signing. Build
the local helper from that same clean checkout and require the embedded
revision and clean-tree metadata to match:

```bash
set -euo pipefail
umask 077
# Export these from the selected successful CI run and use a new private work directory.
: "${SOURCE_SHA:?set the selected full CI source SHA}"
: "${RUN_ID:?set the selected Forgejo run ID}"
: "${RUN_NUMBER:?set the selected Forgejo run number}"
: "${ISSUED_AT_UTC:?set a canonical UTC delegation start time}"
: "${EXPIRES_AT_UTC:?set a canonical UTC delegation expiry}"
[[ $SOURCE_SHA =~ ^[0-9a-f]{40}$ && $RUN_ID =~ ^[1-9][0-9]*$ &&
   $RUN_NUMBER =~ ^[1-9][0-9]*$ ]]
WORK=$(mktemp -d)
export PATH="/ABSOLUTE/PRIVATE/fj-admission:$PATH"
TAG="ci-${SOURCE_SHA}-run-${RUN_ID}"
fj release asset download "$TAG" qualification.json \
  -r TerraScale/ts-orchestrator -o "$WORK/qualification.json"
fj release asset download "$TAG" terrascale-orchestrator-linux-arm64 \
  -r TerraScale/ts-orchestrator -o "$WORK/terrascale-orchestrator-linux-arm64"
test "$(jq -r .source_revision "$WORK/qualification.json")" = "$SOURCE_SHA"
test "$(jq -r .verification.run_id "$WORK/qualification.json")" = "$RUN_ID"
test "$(jq -r .verification.run_number "$WORK/qualification.json")" = "$RUN_NUMBER"

fj repo clone -H https://git.terrascale.tech \
  TerraScale/ts-orchestrator "$WORK/source-main"
test "$(git -C "$WORK/source-main" branch --show-current)" = main
test "$(git -C "$WORK/source-main" rev-parse HEAD)" = "$SOURCE_SHA"
SOURCE_TREE=$(jq -r .source_tree "$WORK/qualification.json")
test "$(git -C "$WORK/source-main" rev-parse 'HEAD^{tree}')" = "$SOURCE_TREE"
cd "$WORK/source-main"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
test "$(go env GOVERSION)" = go1.27.1
nice -n 19 go build -trimpath -buildvcs=true \
  -o "$WORK/ts-release" ./cmd/ts-release
build_info=$(go version -m "$WORK/ts-release")
grep -Fq "vcs.revision=$SOURCE_SHA" <<< "$build_info"
grep -Fq 'vcs.modified=false' <<< "$build_info"

# The authorized root-key owner supplies the pinned public PEMs locally.
cp -- /LOCAL/PINNED/canary-release-root.pub "$WORK/canary-release-root.pub"
test "$(sha256sum "$WORK/canary-release-root.pub" | awk '{print $1}')" = \
  bbdab8425dac0382d641cdf9de7c5a6685f0355a63f6b1131c64241873d418bc
test "$(sha256sum /LOCAL/PINNED/canary-release-leaf.pub | awk '{print $1}')" = \
  ddd81158ef6f5ad7e42e3a87ec16665ed42d480a48ab69441cc12df0d4b629f3
"$WORK/ts-release" sign-delegation \
  --subject-public-key /LOCAL/PINNED/canary-release-leaf.pub \
  --root-key "$WORK/canary-release-root.pub" \
  --signing-key /ABSOLUTE/OWNER-ONLY/offline-root-key.pem \
  --source-revision "$SOURCE_SHA" --arch arm64 --environment canary \
  --issued-at "$ISSUED_AT_UTC" --expires-at "$EXPIRES_AT_UTC" \
  --out "$WORK/canary-release-delegation.json"
fj actions run-detail "$RUN_NUMBER" -r TerraScale/ts-orchestrator \
  > "$WORK/ci-run-detail.json"

"$WORK/ts-release" binary-candidate \
  --binary "$WORK/terrascale-orchestrator-linux-arm64" \
  --source-revision "$SOURCE_SHA" \
  --qualification "$WORK/qualification.json" \
  --out "$WORK/canary-linux-arm64.candidate.json"
"$WORK/ts-release" sign-binary \
  --candidate "$WORK/canary-linux-arm64.candidate.json" \
  --binary "$WORK/terrascale-orchestrator-linux-arm64" \
  --qualification "$WORK/qualification.json" \
  --delegation "$WORK/canary-release-delegation.json" \
  --root-key "$WORK/canary-release-root.pub" \
  --signing-key /ABSOLUTE/OWNER-ONLY/canary-release-key.pem \
  --environment canary \
  --out "$WORK/canary-linux-arm64.receipt.json"
"$WORK/ts-release" verify-binary \
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
successful job attempt from the `fj actions run-detail` output as part of the
independent review evidence.

`sign-binary` checks that the candidate, retained binary, and exact
qualification bytes agree, then uses the pinned `fj` extension to confirm the
CI run's ID, number, full source revision, workflow, successful job, and one
exact manifest-digest marker in its log. It also requires a current
root-signed delegation with the matching canary scope. `verify-binary` checks
the current delegation and receipt and re-inspects the exact binary bytes and
build metadata. These checks do not replace the independent review of the live
main ref and pinned key identities.

Publish only the three public inputs consumed by the image workflow to the
same CI tag: `canary-release-root.pub`, `canary-release-delegation.json`, and
`canary-linux-arm64.receipt.json`. Use `fj release asset create`, upload the
root and delegation first, read each asset back with `fj release asset
download` and compare its bytes, then upload the signed binary receipt last
and read it back as well:

```sh
set -euo pipefail
umask 077
mkdir -m 0700 "$WORK/readback"
fj release asset create "$TAG" "$WORK/canary-release-root.pub" \
  canary-release-root.pub -r TerraScale/ts-orchestrator
fj release asset download "$TAG" canary-release-root.pub \
  -r TerraScale/ts-orchestrator -o "$WORK/readback/canary-release-root.pub"
cmp -- "$WORK/canary-release-root.pub" "$WORK/readback/canary-release-root.pub"
fj release asset create "$TAG" "$WORK/canary-release-delegation.json" \
  canary-release-delegation.json -r TerraScale/ts-orchestrator
fj release asset download "$TAG" canary-release-delegation.json \
  -r TerraScale/ts-orchestrator -o "$WORK/readback/canary-release-delegation.json"
cmp -- "$WORK/canary-release-delegation.json" \
  "$WORK/readback/canary-release-delegation.json"
fj release asset create "$TAG" "$WORK/canary-linux-arm64.receipt.json" \
  canary-linux-arm64.receipt.json -r TerraScale/ts-orchestrator
fj release asset download "$TAG" canary-linux-arm64.receipt.json \
  -r TerraScale/ts-orchestrator -o "$WORK/readback/canary-linux-arm64.receipt.json"
cmp -- "$WORK/canary-linux-arm64.receipt.json" \
  "$WORK/readback/canary-linux-arm64.receipt.json"
```

The image workflow checks those names and digests against its pinned input
manifest before verifying the binary or building the image. Any optional JSON
copy of the review record is audit-only, is not one of the image's admission
inputs, and must not be represented as authenticated approval.

### Image CI provenance

`image.yml` builds the image under the attempt-specific tag
`image-${SOURCE_SHA}-run-${GITHUB_RUN_ID}-attempt-${run_attempt}`. Before
publishing, `build-ci.sh` uses the pinned `fj actions run-detail` extension to
bind the tag to the exact source SHA, image workflow, run ID and number, and
the active `build/qualified-gru-arm64-image` job ID and attempt. The retained
`image-qualification.json` records the source revision and tree, those run and
job identities, the job status observed at publication, the required final
run and job statuses (`success`), and the image and kernel digests. It also
records the pinned input-manifest digest and build tool versions.

The image workflow uploads and reads back `terrascale-gru-arm64.qcow2`,
`guest-kernel`, and `SHA256SUMS` before uploading and reading back
`image-qualification.json` last. It then writes one
`TS_IMAGE_QUALIFICATION_V1` log marker with the source SHA, run ID and number,
job ID, attempt, image SHA-256, kernel SHA-256, provenance SHA-256, and tag.
The manifest and marker are produced before the job finishes; the observed
status may be `running` or `in_progress`, so they do not prove the workflow
ultimately passed.

After `image.yml` finishes, and before importing its image into OCI, use `fj`
to read back the completed image run and that attempt's job log. Require
the run and `build/qualified-gru-arm64-image` job to match the manifest's full
source SHA, `image.yml` workflow, run ID and number, job ID, and attempt, and
require both final statuses to be `success`. Match the exact marker in that
attempt's log to those identities, the manifest file digest, its output tag,
and the image and kernel digests. Then bind the imported image OCID and region
through the existing `image-candidate` and `sign-image` inputs.

Before importing, use `fj release asset download` on that exact
`image_release_tag` to retrieve the QCOW2, `guest-kernel`, `SHA256SUMS`, and
`image-qualification.json`. Check the QCOW2 and kernel sizes and SHA-256 values
against the completed manifest. Check the downloaded qualification file's
SHA-256 against the marker's `provenance_sha256`, and check the `SHA256SUMS`
entries for the QCOW2, kernel, and qualification file against their downloaded
bytes. Import that verified QCOW2; use the downloaded kernel for
`image-candidate` and signing inputs, and retain the qualification and checksum
files as operator provenance evidence. The build job's publish-time asset
readback occurs before final job success and does not replace this
post-success operator readback.

`sign-image` does not currently consume `image-qualification.json` or verify
the image workflow run and marker. Its `--qualification` input is the original
`ci.yml` binary qualification manifest; it verifies that binary run and its
qualification marker, then checks the signed binary, candidate QCOW2, base
image, and kernel files. The completed image-run readback and marker match are
therefore separate operator evidence and must not be described as enforced by
`ts-release`.

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

`cmd/ts-release` checks static ELF and embedded Go build metadata and consumes
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

`deploy/image/build-offline.sh` verifies the signed binary, requires a
standalone QCOW2 base, and completes the candidate through filesystem-only
guestfish operations. It audits the guest's Noble systemd 255 unit metadata,
stages account creation with host `systemd-sysusers --root`, and stages unit
enablement with host `systemctl --root`; the resulting files and symlinks are
written and read back offline. A scoped container runner can be supplied as
`TS_OFFLINE_GUESTFS_RUNNER` when guestfish is unavailable on the build host.
Supply a build-time `ts-bootstrap` executable,
the signed v2 anchor, its strict canonical schema-version-1 identity JSON with
`schemaVersion`, `deploymentId`, `environment`, and `cell`, and one or more
public bootstrap root PEMs. The exact identity bytes passed to the verifier
are installed in the image. The builder keeps `--root-key` for release-binary
verification and passes only the repeatable `--bootstrap-root` inputs to
`ts-bootstrap verify-anchor --anchor ... --identity ... --root-key ...`. It
requires current anchor, identity, grant, and intent verification to succeed
before it creates a candidate or copies files into the guest; the identity's
schema version and environment must match the runtime contract and release
environment. The anchor is bounded to 64 KiB, the identity to 4 KiB, and the
root set to 1 through 16 files, each bounded to 16 KiB and 64 KiB total. The
verifier executable is used only on the build host and is not installed in
the image.

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

The candidate contains the signed anchor at
`/etc/terrascale-orchestrator/bootstrap/anchor.json`, the public identity at
`/etc/terrascale-orchestrator/bootstrap/identity.json`, and the verified root
set as sequential `trust-roots/NNN.pem` files starting at `001.pem`, matching
the runtime loader's accepted names. Those files are root-owned and mode
`0444`; their directories are root-owned and mode `0755`. The image also
has the root-owned `0755` bootstrap marker directory and the empty
`terrascale-orchestrator`-owned `0700` secret-material directory. The runtime
bootstrap unit creates its `0700` `/run` staging directory for each start.
The signed anchor, identity, and trust roots are public inputs; no private
signing keys, release tools, or runtime secret bytes are copied into the guest.

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
prints its SHA-256 for review. The deployment must provide reachable NTP
endpoints for its network, and the builder does not bake the lab endpoint. The
resulting config is part of the image signed by the normal release flow.

Before installation, the builder fails closed if it finds an active static
`NTP=` or `FallbackNTP=` assignment in the base image's timesyncd config. It
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

For a host-enrollment image, the offline builder also checks that the base guest
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
service's mount namespace. [`offline-guestfs.py`](../deploy/image/offline-guestfs.py), [image-builder tests](../tests/deploy/test_build_offline.py), [initializer service](../deploy/systemd/terrascale-orchestrator-host-volume-init.service), [initializer socket](../deploy/systemd/terrascale-orchestrator-host-volume-init.socket).

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
when `host.managed_runtime_root` selects it. A host image is built with a
SHA-pinned public enrollment bundle; the builder fixes workload UID/GID to
`2000:2000` and provisions `/srv/ts-managed` as `root:2000` mode `0750`.
The bundle fixes `host.install_root` and `host.state_root` to separate children
under `/var/lib/terrascale-orchestrator-host`.
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
