# Qualification status

This is an implementation and local verification record, not production
acceptance. The requirements remain in `GOAL.md` and the workspace goal.

## Verified integration

Commit `b78ea943` integrates the previously unfinished host, bootstrap,
provider, and Firecracker work. Local linux/amd64 verification on 2026-09-04:

- `GOFLAGS=-p=4 make check` passed formatting, vet, build, and all race tests.
  Limiting build concurrency avoided a host process-exhaustion failure.
- `go test -p 4 -tags sandboxvm ./src/orchestrator/vmqual
  ./src/orchestrator/sandboxvm ./cmd/vm-qualify` passed.
- `make vm-image` prepared and verified Ubuntu 24.04.3 and the pinned kernel.
- `make vm-doctor` passed using the root-owned qualification directory
  `/var/lib/terrascale-qualification/ts-orchestrator`, the pinned Firecracker
  1.15.1 and jailer, and installed e2fsprogs tools added to PATH. The host has
  writable KVM and the required root networking and cgroup capabilities.

The image manifest digest is
`ecd6294ded8ac0e246c461a7b190303e62e9a644756985a28e683bbf1d7e7f9b`.
The kernel SHA-256 is
`e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2`.
The declared rootfs input SHA-256 is
`c9d17b2554832605cdb377ace2117822fb02694e8fb56d82f900ce045c7aae57`.

The regression tests prove permanent global R3 state survives successive
fourth-and-later Region admissions, failed host retirement is retried after
restart, and background service errors propagate through runtime shutdown.
These are portable contract tests; they do not prove guest or provider
behavior.

## Unfinished qualification

No complete passing `vm-smoke`, six-host `vm-stack`, `vm-test`, or fourth-Region
guest result has been established for this integration. The native static
TerraBase build initially failed because the musl C compiler was absent. Its
replacement build succeeded with the installed musl cross compiler and the
repository's pinned Rust toolchain. The static amd64 binary is 17,787,952 bytes,
with SHA-256
`300d71b2c6e446555aa62eb03c04a07937a83503da1c4393da39074a19444aa7`.
It was built from the adjacent TerraBase worktree, which contained uncommitted
changes; the binary digest identifies this qualification input.

The first smoke invocation rejected that binary because service artifacts
shared the 16 MiB diagnostic-transfer bound. Signed service artifacts now use
a separate 64 MiB bound. The next invocation found that the production factory
selected per-run network locks, which the host runner correctly refused.
Production and cleanup-probe networking now use the shared host lock domain.
Further real boots exposed a jailed-process identity mismatch and a seed
filesystem mismatch. Firecracker reports its executable as `/firecracker`
inside the jail; inspection now verifies both the jail root and executable
inodes before accepting that path. The pinned kernel supports ext4 but lacks
the ISO9660/FAT support required by cloud-init block seed discovery. The
qualification runner now writes the NoCloud directory into the private guest
rootfs and checks exact readback plus `e2fsck -fn`.

With that change, the real guest reached Ubuntu systemd, consumed the local
seed, and configured `eth0` as `10.77.0.10/24` with gateway `10.77.0.1`.
The 256 MiB profile then exceeded its two-minute readiness deadline while
cloud-init processed a roughly 22 MiB user-data file. SSH was unavailable.
Firecracker exited successfully after the shutdown request, and the cleanup
command returned success. The smaller seed now keeps the ELF payloads outside YAML. A real retry reached
cloud-init final, verified the actual ts-node digest and signature, and started
chrony. Selected console lines and the runner digest are retained in
[the boot evidence](../evidence/vm-boot-2026-09-04.txt).

That retry still timed out on SSH: the controller used the root network
namespace, where guest-subnet routes are intentionally absent. SSH now creates
its socket in the exact validated guest namespace, restores the caller's
namespace before connecting, and pins the observed guest host key. A real
isolated namespace test proved connection, host-route isolation, namespace
restoration, and cleanup. The full `make vm-test` invocation then reached GRU boot and namespace SSH but
failed initial ts-node admission. No scenario ran; the machine report is
[retained here](../evidence/vm-test-2026-09-04.json), with its
[failure output](../evidence/vm-test-2026-09-04.txt). Root networking used
100.64.0.0/10 uplinks, which this host's Tailscale input chain rejects.
Qualification now uses disjoint 198.18.0.0/16 uplinks and 198.19.0.0/16 service
addresses, with the existing ownership locks and collision refusal. No host
firewall configuration was changed.

A retry with the corrected address pool reached chrony startup, but
`chronyc waitsync` returned `506 Cannot talk to daemon`. Setting the command
socket directory to chrony's required mode 0750 fixed communication with the
daemon. The next real smoke attempt still failed bootstrap: chrony reported
zero received samples and `Not synchronised`. Read-only inspection showed
that the host's NixOS INPUT chain drops fresh connections to all qualification
listeners. The namespace forwarding and listener existed, but host input
admission remains to be implemented. No host firewall or clock configuration
was changed. Cleanup succeeded. Selected evidence is retained in
[the input-path failure record](../evidence/vm-smoke-input-2026-09-04.txt).

The Cloudflare wire changes and real TBEP observation client are committed as
`52aeac50`. A later local `GOFLAGS=-p=4 make check` also passed after removing
the separate qualification seed-drive fields. The final portable check and tagged race tests also passed after immutable
launch configuration, initial activation, expiry-aware rotation, smaller
NoCloud seeds, chrony provisioning, and namespace SSH integration.

## Real TBEP observation

`orchestrator observe-member --config FILE` successfully queried the actual
static TerraBase binary identified above over TLS 1.3 mTLS. The response
reported serving health, network mTLS, standalone cluster mode, and registry
version 1.4. A wrong admitted SPIFFE server identity failed with no observation
JSON. The experiment server terminated cleanly. Exact commands and nonsecret
output are retained in [the TBEP client evidence](../../src/orchestrator/tbep/README.md).
This experiment used isolated local-development engine state. It does not
establish placement, replication, drain, backup, or restore readiness.

## Guest time and host prerequisites

Qualification now extracts real chronyd/chronyc ELF binaries from checksum-
pinned Ubuntu chrony 4.5-1ubuntu4.2 packages for amd64 and arm64. Both package
extraction and tamper-refusal tests passed. Only the native amd64 guest ran.
The private guest receives a chrony service/config and uses a bounded local
NTP endpoint, without a public guest route or general UDP allowance.

The local NTP service checks the host kernel clock before every response and
withholds time when synchronization or the reported clock state is invalid.
It advertises the observed kernel maximum error as NTP root dispersion, rounded
up to the protocol precision, and preserves pending leap indicators. Doctor
reports this uncertainty. Guest chrony selects the source and measures its
clock correction; the goal's 500 ms write fence applies to measured offset.

An earlier implementation incorrectly applied that 500 ms threshold to host
kernel maximum error and withheld replies from a synchronized host reporting
748.5 ms uncertainty. That inferred restriction has been removed. No host
clock or host time-service configuration was changed.

## Package and network verification

Qualification code is separated into `vmqual` core/lifecycle,
`vmqualruntime` guest execution, and `vmqualsuite` scenario contracts.
Each package remains below 10,000 lines including tests and build variants.
The full portable gate and `go test -p 4 -tags sandboxvm -race ./...` passed
after the split. Early startup diagnostics are retained before cleanup, and
readiness requires the local orchestrator on every member host.

Network planning accepts explicit additional Regions through twenty total,
while the default remains GRU/SFO/FRA with six guest slots. Admission keeps
existing guest and cross-Region link addresses stable. A real four-namespace
fixture created the topology, sent an actual packet from IAD to GRU, and
successfully cleaned up its owned resources. This proves network behavior;
it does not prove fourth-Region guest admission, TBEP management, or quorum.

The fourth-Region scenario now creates and checks two IAD guests after control
admission. It journals both host obligations before either create and requires
the predeclared network slots. The three global control replicas remain in
GRU/SFO/FRA. Tagged race tests cover duplicate admission, failed second-host
readiness, budget refusal, and cleanup ownership. The real baseline has not
yet passed, so this guest scenario has not executed successfully.

Smoke failures now retain bounded console and metrics evidence before deleting
resources, including canceled startup. Production reconciliation now cancels
provider work when a required background service exits and retains shutdown
errors. Command race tests cover failures during in-flight provider work.
The full `GOFLAGS=-p=4 make check` and
`go test -p 4 -tags sandboxvm -race ./...` passed after these changes.
Logs are `/tmp/ts-orchestrator-integration-check.log` and
`/tmp/ts-orchestrator-integration-tagged.log` on the qualification host.

## Remaining production work

Production startup still has an unconditional missing-composition error.
The concrete missing adapters and absent TerraBase lifecycle RPCs are listed
in [production readiness](production-readiness.md). OCI tags and instance
lifecycle alone do not prove NATS synchronization, quorum, bootstrap handoff,
or TerraBase readiness. Cloudflare adapters now use multipart code uploads,
Snippet content reads and zone-wide `snippet_rules`, and actual Worker version
and deployment response shapes. Worker digest identity uses the supported
release annotation; Snippet identity hashes returned source bytes. Tests cover
ETags when supplied, not a guarantee that Cloudflare provides atomic rule-set
updates. These adapters still require real-zone qualification.

Real OCI/Cloudflare checks, security gates, a seven-day soak on release
digests, per-Region rollback rehearsals, and fourteen consecutive daily
restore drills remain unverified. None of the local results closes those
gates or establishes arm64 qualification.
