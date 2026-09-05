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
listeners. The namespace forwarding and listener existed, but the run had no host input
admission rules. No host firewall or clock configuration
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

## Qualification host input

Network journal version 8 includes temporary INPUT allowances for each exact
owned root veth, source /32, listener /32, protocol, and declared port. Rules
carry the full run identity and are journaled before insertion. Cleanup deletes
full matching specifications and retains its allocation lease if deletion
fails. It never changes a firewall policy or flushes a chain. The host now
requires `iptables` alongside the existing networking tools.

Real privileged tests passed on this NixOS host. A fixture DROP restricted to
the unique owned veth blocked undeclared TCP/UDP ports and an alternate source,
while the declared tuples passed. Cleanup removed qualification allowances and
preserved the fixture rule until its own teardown. A second test received real
48-byte NTP replies through both the direct Region path and a guest-side veth,
bridge, gateway port 123, DNAT/SNAT, and host INPUT. The observed stratum was 14,
leap indicator 0, and root dispersion 0.372009 seconds; round trips were below
0.3 ms. This measures packet exchange, not guest chrony synchronization.

The NTP-only fixture exposed an empty-DNS cleanup validation bug. The fix passed
a serialized-journal regression, and the exact interrupted run was recovered.
Both fixtures then passed, with no owned namespaces or INPUT rules remaining.
Normalized `iptables-save` output before and after the fixtures was identical,
excluding timestamps and counters. Affected packages passed tagged race tests
in `/tmp/ts-host-input-race-final.log`.

The subsequent real smoke run synchronized guest chrony, completed cloud-init,
and kept ts-node running. Initial signed host installation admission still
exceeded its two-minute deadline; neither application service was activated.
The final request error does not identify whether subscriptions were absent
or a handler blocked. Sanitized systemd states and bounded console/metrics
survived cleanup. Evidence is retained as
[the controller record](../evidence/vm-smoke-host-input-2026-09-04.txt) and
[the diagnostic report](../evidence/vm-smoke-host-input-2026-09-04.json).
No namespaces or qualification firewall rules remained, and the ambient rule
set matched its pre-test snapshot. The full portable gate and full sandboxvm
race suite passed after input admission and startup diagnostics; logs are
`/tmp/ts-orchestrator-host-input-check.log` and
`/tmp/ts-orchestrator-host-input-tagged.log`.

## Detached release signatures and host observations

The repeated installation failure had a concrete wire mismatch. `vm-artifacts`
wrote Base64 signature sidecars, and qualification served those encoded bytes.
The host installer accepted raw signatures, so each rejected pass discarded
its staged binary and retried. The adjacent `ts-deploy` release writer emits
raw 64-byte Ed25519 sidecars and verifies that exact representation.

Qualification signing, input verification, HTTPS serving, host installation,
and the production Forgejo delivery reader now use raw 64-byte detached
signatures throughout. Encoded sidecars and added whitespace are rejected;
a newline-valued byte inside the 64-byte signature is preserved. JSON command
and proof encodings are separate and unchanged. A real HTTPS-handler-to-installer
regression installs a signed artifact, revalidates its immutable slot on a
second call, and observes only the original artifact/signature request pair.

Host status previously waited behind the lifecycle lock held during downloads.
It now reports bounded unknown/busy observations during mutation, with fixed
current and last-failed phase labels. Filesystem and clock observations share
a five-second deadline and recheck lifecycle coherence. No cached progress
value substitutes for signature or artifact verification. Activation timeouts
retain the last meaningful error rather than replacing it with cancellation.

The complete portable gate and sandboxvm race suite passed after these fixes.
Logs are `/tmp/ts-orchestrator-raw-signature-check.log` and
`/tmp/ts-orchestrator-raw-signature-tagged.log`. Real VM qualification remains
in progress; these code and HTTPS tests do not establish service readiness.

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
