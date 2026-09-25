# Build and release boundaries

The Forgejo verification workflow checks out the event's exact Git revision and
requires a clean tree. It runs Go formatting checks, tests, `go vet`, and
race-enabled tests using Go 1.27.1. The `terrascale-builder` image supplies
that exact Go version; `.mise.toml` pins the same version for local development.

The artifact job cross-compiles one static executable for Linux amd64 and one
for Linux arm64 with cgo disabled. It checks the ELF machine type, absence of a
dynamic interpreter and linked libraries, the embedded Git revision, and
SHA-256 digests. It prints a `SHA256SUMS` receipt in the job log.

The separate `release.yml` workflow is dispatch-only on protected `main`. Its
`sign_release` and `publish` inputs both default to `false`; it does no work
when both are false. Signing uses a currently valid root-signed scoped
delegation and an owner-only delegated key supplied only by the protected
`production-release` environment. The root private key stays offline. The
optional `publish` input uses the release runner's OCI instance principal and
conditionally creates immutable, source-revision-keyed objects. It publishes
only signed Linux binaries and their signed receipts. No release was signed or
published for this change, and the workflow was not run. Configure environment
reviewers and the release runner's least-privilege OCI policy before any future
manual use.

`internal/release` owns the v1 binary and image receipt wire types, scope rules,
and current and historical verification. Current verification requires a live
root-signed release delegation with a maximum 365-day lifetime and a receipt
with its separately defined 365-day maximum. Signing applies the same limits
and caps receipt expiry at the remaining delegation lifetime. Historical
verification returns a distinct audit-only proof and cannot serve as current
authorization. The verified image proof exposes SHA-256 of the exact canonical
envelope wire; this is the digest pinned by
`Manifest.ReleaseReceiptSHA256`, not a payload-only digest.
The accepted bootstrap wire direction carries the public image-receipt
envelope and release-delegation envelope in the root-signed manifest after OCI
image import; the runtime checks the envelope digest against this pin before
trusting the receipt.

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
standalone QCOW2 base, and locally prepares a candidate with
`virt-customize --no-network`. Supply a build-time `ts-bootstrap` executable,
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
and bootstrap, controller, and host systemd units. It requires the base image
to provide both `systemd-timesyncd.service` and
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

The controller unit runs as the pre-created `terrascale-orchestrator` user,
reads `/etc/terrascale-orchestrator/controller.json`, and persists embedded
JetStream below `/var/lib/terrascale-orchestrator-controller`. Its config must
set `nats.embedded.store_dir` to a directory under that state root. The host
unit runs the one binary as root with `Delegate=yes`, `NoNewPrivileges=yes`,
and only `CAP_CHOWN`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, and `CAP_SETPCAP`; its
root-only config is `/etc/terrascale-orchestrator/host.json`. `host.state_root`
must be a private child of `/var/lib/terrascale-orchestrator-host`, while
`host.install_root` is a separate child for tenant-group executable files.
These host settings match the runtime owner's proposed path contract. The
service asset is ready for staging. The strict systemd guest security run
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
development](local-development.md#latest-local-qualification).
