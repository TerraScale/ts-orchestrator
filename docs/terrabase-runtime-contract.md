# TerraBase runtime contract

Status: **implemented in source and tested locally against a published
release; not deployed or tested on OCI.** This is the contract between the
orchestrator and the C# TerraBase single-file binary (repository
`TerraScale/terrabase`). Package [`internal/terrabase`](../internal/terrabase)
holds the orchestrator side: release assets
([`release.go`](../internal/terrabase/release.go)), settings, peer list,
layout and health probe ([`contract.go`](../internal/terrabase/contract.go)),
member certificates ([`ca.go`](../internal/terrabase/ca.go)) and the
`ts-orch terrabase` command ([`cli.go`](../internal/terrabase/cli.go)). The
host side is [`internal/host/terrabase.go`](../internal/host/terrabase.go).

The operator workflow is in [TerraBase deployment](terrabase-deployment.md);
what serving, replication and scale-in still need is in
[TerraBase serving lifecycle](terrabase-serving-lifecycle-plan.md).

## Release

Every TerraBase `main` push that passes CI publishes the prerelease
`ci-<commit>-run-<run id>`; a version tag `v<Version>` publishes the release
`v<Version>`. Each carries two assets: `terrabase-linux-amd64` and
`terrabase-linux-amd64.sha256` (one `sha256sum` line). The first published
release is `ci-641274f7482bcf0ce2ae556af8be162d49e445be-run-13121`, SHA-256
`69d132e76471089268ef1a807e69d4aef1e00a92995930817b0457ada0c02194`.

**ARM64 gap.** OCI workload hosts are ARM64 (`VM.Standard.A1.Flex`), but
TerraBase CI builds only `linux-x64` and publishes only
`terrabase-linux-amd64`. A live OCI deployment needs TerraBase CI to also
publish `terrabase-linux-arm64` and `terrabase-linux-arm64.sha256`. The
orchestrator already accepts either asset name.

`terrabase.VerifyRelease` checks that the file is named
`terrabase-linux-amd64` or `terrabase-linux-arm64`, starts with the ELF
magic, is at most 512 MiB (the controller's artifact admission limit), and
matches the single line of its `.sha256` asset. The verified digest is the
artifact digest the rollout pins. TerraBase publishes no source digest, so
the artifact's source claim is repository
`https://git.terrascale.tech/TerraScale/terrabase`, the commit, and the
SHA-256 of `git archive --format=tar <commit>` in a TerraBase checkout.

## The binary

The executable is a self-contained single-file .NET 11 JIT build with
invariant globalization (no ICU). Its native libraries are extracted at
startup to `DOTNET_BUNDLE_EXTRACT_BASE_DIR`, or to a writable `HOME`; with
neither it exits with `DOTNET_BUNDLE_EXTRACT_BASE_DIR is not set`. The host
sets that variable.

Every setting is a `TERRABASE_<NAME>` environment variable or a
`--name=value` argument. The argument wins, and an empty value means unset.
An unknown `--name` exits with code 2; unknown `TERRABASE_*` variables are
ignored. A configuration error exits with code 2 and never prints a value.

| Setting | Default | Meaning |
| --- | --- | --- |
| `admin-port` | 9464 | Loopback-only (`127.0.0.1`) HTTP listener: `GET /healthz` answers 200 `{"status":"ok","version":"0.1.0"}`; also `/metrics` (Prometheus) and OpenAPI. |
| `data-directory` | `data` | One SQLite file per database. |
| `client-port`, `client-certificate`, `client-private-key` | unset | HTTPS client API on all interfaces, HTTP/1.1 and HTTP/2. All three or none. |
| `peer-port`, `peer-certificate`, `peer-private-key`, `peer-client-ca` | unset | Inter-node gRPC service `terrabase.v1.Replication/Sync` over HTTP/2 with mutual TLS on all interfaces. A connecting peer's client certificate must chain to `peer-client-ca` and carry the clientAuth EKU. All four or none. |

There is no `/readyz`: `/healthz` is liveness only. The `Sync` service exists
but rejects the handshake with `Unimplemented` until TerraBase TS-464. The
binary has no peer-list setting yet; N-node membership is TerraBase TS-469.

On SIGTERM the binary runs ASP.NET Core shutdown: it stops accepting,
drains in-flight requests (default host shutdown timeout 30 s), and exits 0.

## Workload profile

A member is a native workload of role `terrabase`. Its settings come from
the signed controller config `controller.workloads.terrabase`
(`{resources, env}`); every member of the role gets the same `env`. A C#
profile sets no `args`: the binary lets an argument override the host-owned
settings, so the controller rejects them and the host refuses a member with
arguments. When a `terrabase` profile has a non-empty `env`, the controller
validates it at startup and refuses to start when it fails these checks:

| Key | Rule |
| --- | --- |
| `TERRABASE_PEER_PORT` | Required port. |
| `TERRABASE_ADMIN_PORT` | Optional port, default 9464. |
| `TERRABASE_CLIENT_PORT` | Optional port; unset disables the client listener. |
| `TERRABASE_PEERS` | Required. Comma-separated `name=ip:port` for every member of the cell, this one included. `name` is the member host's node name (lowercase letters, digits and `-`, at most 63 characters). Names and addresses are unique, every port equals `TERRABASE_PEER_PORT`, at most 64 entries. |

The admin, peer and client ports must differ. A profile must not set the
host-owned keys `TERRABASE_DATA_DIRECTORY`, `TERRABASE_PEER_CERTIFICATE`,
`TERRABASE_PEER_PRIVATE_KEY`, `TERRABASE_PEER_CLIENT_CA`,
`TERRABASE_CLIENT_CERTIFICATE`, `TERRABASE_CLIENT_PRIVATE_KEY` or
`DOTNET_BUNDLE_EXTRACT_BASE_DIR`.

Recommended GRU values: `TERRABASE_PEER_PORT=9443`,
`TERRABASE_CLIENT_PORT=9465`, admin port 9464 (loopback). Cell and host
names follow `<region>-<index>`: cell `gru-1`, members `gru-1-db-1`,
`gru-1-db-2`, `gru-1-db-3`:

```text
TERRABASE_PEERS=gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443
```

**`TERRABASE_PEERS` is a PROPOSED setting.** The current binary ignores it as
an unknown variable. TerraBase TS-469 must adopt a `peers` setting with this
`name=ip:port` format, or the orchestrator renames it. The orchestrator uses
it today to decide which hosts may hold a member certificate and which name
and address the certificate carries. The list is static per signed profile:
a membership change needs a signed controller config change and a new
release, and a running member reads it only at start.

## Member CA and certificates

`ts-orch terrabase member-ca --cell gru-1 --out DIR` creates a new directory
`DIR` (0700) with `member-ca.pem` (0644) and the owner-only `member-ca.key`
(0600): an ECDSA P-256 CA valid for 10 years. It refuses an existing `DIR`,
so a CA is never overwritten. The controller config keys
`controller.terrabase_ca_cert_file` and `controller.terrabase_ca_key_file`
point at the two files; the key must be a regular file, not a symlink,
owned and readable only by the controller's user. Without them the
controller refuses every member certificate request, and members never
start. Hosts never see the CA key.

The host agent creates `<terrabase_root>/tls/member.key` (ECDSA P-256, PKCS#8)
once; the key never leaves the host. When the member certificate is missing,
does not match the key, does not chain to `ca.pem`, does not name this
member, or has fewer than 30 days left, the host sends a certificate request
over its authenticated session as host operation `terrabase-peer`. The
controller signs it only when the CSR is a valid ECDSA P-256 request, the
host's registration has role `terrabase` and no `managed_oci` binding, and
the host's current desired for `terrabase` is active, non-managed, valid for
its current registration (including its environment), and has a profile
whose `TERRABASE_PEERS` lists this node. It ignores any names in the
request and issues:

- CN and DNS SAN: the node name; IP SAN: the listed IP;
- EKU serverAuth and clientAuth; validity 90 days, capped at the CA's expiry.

The host writes `member.pem` and `ca.pem` atomically. The same certificate is
the peer listener's server certificate, the client certificate a member
presents to other members, and, when `TERRABASE_CLIENT_PORT` is set, the
client HTTPS certificate; clients trust `member-ca.pem`.

Renewal runs on every poll while the member runs and is best effort: an
error is reported but does not stop the member. The host replaces each file
atomically (write, fsync, rename). A binary with TerraBase TS-464 re-reads
the peer certificate, key and CA on its next TLS handshake after they
change, so peer renewal is live; its client listener still loads its
certificate once, so a member with a client port still restarts once per
renewal. The current release binary loads all of them only at start. Between one and seven days (a fixed offset per node, so a cell's
members do not restart together) before the certificate the member started
with expires, the host completes a TLS handshake with the member's peer
listener, and client listener when set, on loopback, presenting the
member's own certificate. If a listener still serves an expiring
certificate, or the handshake fails, the host restarts the member with a
drain so it loads the renewed one; a member whose listeners already serve
the renewed certificate keeps running. If the stop fails, the host retries
on the next poll. Releases restart members long before
that.

## Host layout and launch

Host config `host.terrabase_root` enables C# members on a host. It must be
absolute, clean, not `/`, and separate from the install and state roots.
Every ancestor must already exist; only the member root may be created.
The root and every ancestor must be real directories, not symlinks, that
the workload identity can traverse but not replace, the workload must not
be able to create entries in the root's parent (sticky or not), and the
path must resolve to itself; the agent checks this at start and again before every
member preparation. It changes the owner and mode of each managed
directory through a descriptor opened with `O_NOFOLLOW`, so a symlink is
never followed.
Use `/srv/ts-managed/terrabase` on the image: the host unit
(`ProtectSystem=strict`) can write only below `/srv/ts-managed`, so another
root needs a unit drop-in. It is a host-local option: a host credential
renewal that rewrites `host.json` keeps it. On such a host a
non-managed `terrabase` desired is launched as a C# member.

| Path | Owner, group, mode | Content |
| --- | --- | --- |
| `<root>` | supervisor, workload group, 0750 | |
| `<root>/tls` | supervisor, workload group, 0750 | `member.key`, `member.pem`, `ca.pem`, each supervisor-owned, workload group, 0440 |
| `<root>/data` | workload user, 0700 | SQLite databases |
| `<root>/bundle` | workload user, 0700 | Extracted native libraries |

The member's environment is the host base environment
(`HOME=/ LANG=C PATH=/usr/bin:/bin`), then the profile `env`, then:

| Variable | Value |
| --- | --- |
| `TERRABASE_DATA_DIRECTORY` | `<root>/data` |
| `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | `<root>/bundle` |
| `TERRABASE_PEER_CERTIFICATE` | `<root>/tls/member.pem` |
| `TERRABASE_PEER_PRIVATE_KEY` | `<root>/tls/member.key` |
| `TERRABASE_PEER_CLIENT_CA` | `<root>/tls/ca.pem` |
| `TERRABASE_CLIENT_CERTIFICATE`, `TERRABASE_CLIENT_PRIVATE_KEY` | The member certificate and key, only when `TERRABASE_CLIENT_PORT` is set |

The process runs as the workload user (`terrascale-workload`, uid/gid 2000 on
the image) in its own cgroup under the host agent. There is no per-member
systemd unit: the host agent
([`terrascale-orchestrator-host.service`](../deploy/systemd/terrascale-orchestrator-host.service))
is the supervisor, and the member's stdout and stderr go to that unit's
journal. The C# path attaches no block volume: member data lives on the
host's filesystem under `terrabase_root` and does not survive replacement
of the host.

## Readiness

After launch the host reports the member `starting`. On every poll (5 s by
default) it calls `GET http://127.0.0.1:<admin-port>/healthz` and reports
`running` only when the answer is 200 with `{"status":"ok"}`. A member that
stops answering goes back to `starting` with the probe error. A member
whose process exits is reported `failed` once and relaunched on the next
poll, so a release that crashes after start fails its gate at once.
`operator terrabase-release` counts only `running` as ready.
This is liveness, not a serving or replication claim.

## Stop and drain

Stopping or replacing a C# member sends SIGTERM through a pidfd and waits up
to 45 s for its cgroup to empty, then kills the cgroup. The host unit's
`TimeoutStopSec=90s` leaves room for it. Session loss, agent shutdown and
agent restart recovery still kill the cgroup at once: workloads must stop before the host lease
reserve runs out. The drain is not a durable drain receipt.

## Qualification

T0 unit tests in [`internal/terrabase`](../internal/terrabase) cover profile
and peer parsing, the host-owned environment, release verification, CA and
member certificate issue and renewal checks, and the health probe.
`TestTerraBaseReleaseGateWithFakeMember` (`internal/app`, T0) runs
`operator terrabase-release` against an in-process controller and host agent
with an in-process stand-in for the binary that serves `/healthz` only when
the host prepared its data directory and a member certificate chaining to
the cell CA: deploy, upgrade, and a release that crashes after start, which
fails the gate at once and is rolled back in place.
`TestTerraBasePlacementKeepsMembersOnListedHosts` checks that members are
placed only on listed hosts and replaced in place. In `internal/host`,
`TestTerraBaseMemberRestartsBeforeLoadedCertificateExpires` (against a TLS
listener serving the renewed or the expiring certificate),
`TestTerraBaseExitReportedOnceBeforeRelaunch`,
`TestTerraBasePeerCertificateFollowsCurrentRegistration`,
`TestTerraBaseRootMustBeSeparate` and `TestTerraBaseMemberRefusesArguments`
cover the certificate restart, exit reporting, certificate signing against
the current registration, root validation and argument refusal. In
`internal/app`, `TestTerraBaseReleaseStateRules`,
`TestTerraBaseProfileRejectsArguments` and the broken-stdout step of the
fake-member test cover the gate's state rules, profile arguments and
output errors. `TestNativeDrainSendsTermBeforeKill`
(`internal/host`) checks the cgroup runner's SIGTERM drain and its kill after
the timeout; like the other native runner tests it needs root and a
delegated cgroup and skips otherwise.

Two T2 tests run the real binary. They skip unless `TS_TERRABASE_BINARY`
names a `terrabase-linux-<arch>` asset with its `.sha256` file beside it:

- `TestTerraBaseBinaryPeerMesh` (`internal/terrabase`): three members on
  local ports, configured only through the host's environment contract. The
  mutual-TLS mesh accepts orchestrator-issued peer certificates and rejects
  foreign-CA and certificate-less clients; SIGTERM drains and exits 0.
- `TestTerraBaseReleaseDeployUpgradeRollback` (`internal/app`): an
  in-process controller and host agent with the real binary: deploy,
  readiness, upgrade to a second digest, and a broken release rolled back
  automatically.

Run them with `make terrabase-release-process TERRABASE_BINARY=<path>`, or
as the `terrabase-binary` and `terrabase-release` suites of
`scripts/ci/qualify-image.sh`. Both passed locally against the linux-amd64
asset of `ci-641274f7482bcf0ce2ae556af8be162d49e445be-run-13121`: the mesh
members answered `Replication/Sync` with gRPC status 12 (`Unimplemented`)
over mutual TLS, which shows the call reached the service.

`TestLiveOCITerraBaseHostsReadOnly` (`internal/terrabase`) is an opt-in,
read-only check against the real OCI API through the shared client factory
and the operator's `~/.oci/config` DEFAULT profile. With
`TS_OCI_LIVE_COMPARTMENT_ID` set (optional `TS_OCI_LIVE_REGION`,
`TS_OCI_LIVE_HOST_PREFIX`, default `gru-1-db-`, and `TS_OCI_LIVE_PEER_PORT`,
default 9443) it checks that the region offers `VM.Standard.A1.Flex`
(Ampere, 1 OCPU, 6 GB per OCPU), that A1 cores are left, and that an Ubuntu
ARM64 image fits A1. For the running hosts of the prefix it checks the A1
shape, distinct fault domains and that every member's NSGs let the others
reach the peer port, and logs the `TERRABASE_PEERS` value their primary
private IPs give. It only lists and gets. On 2026-10-04 it passed for
`sa-saopaulo-1` (A1 offered, 248 A1 cores available, 17 Ubuntu A1 images;
GRU had no TerraBase hosts during its rebuild), and its host path read the
VNIC and private IP of the running `ts-ops` A1 instance.

Not tested: any live OCI host running a member, ARM64, the cgroup process runner as root with
the real binary (its drain is covered by a root-only runner test), and real
replication, which the binary does not implement yet.

## Retired terrabase-rust managed path

Before this contract, TerraBase was the Rust `tb-server`, launched through a
managed-member path: schema-5 placement in `internal/placement`, pinned
member material in `internal/managedmaterial`, retained OCI volumes mounted
by the host, and a native serving proof read through `internal/memberstatus`.
That code remains in the repository with its operator commands, but it
targets the retired binary and must not be used for the C# binary. Git
history keeps the full previous text of this document, including its source
identities and qualification records.
