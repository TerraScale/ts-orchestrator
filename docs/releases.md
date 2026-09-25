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
The runtime has not yet connected image receipt verification to controller or
host startup; this producer/consumer path remains an open admission gate.

`deploy/image/build-offline.sh` verifies the signed binary, requires a
standalone QCOW2 base, and locally installs the binary and both systemd units
with `virt-customize --no-network`. It does not install credentials or
configuration and makes no OCI call. Each service is enabled but has a
`ConditionPathExists` for its role config, so an unprovisioned image leaves
both inactive. A future image receipt can only be made after a custom image
has been imported and its OCI image OCID is known. This workflow has not been
run because the pinned base image, signer, and image-import authorization are
not yet approved.

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
`STA_CLOCKERR` clear and `maxerror` at most 250 ms. The image needs an enabled
NTP service such as chrony or systemd-timesyncd, with polling and reachability
appropriate for its network. A manually set wall clock is not evidence of
synchronization, and there is no startup bypass for the time check.

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
