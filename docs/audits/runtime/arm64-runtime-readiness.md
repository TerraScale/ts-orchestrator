# Phase 0 ARM64 host and runtime readiness

- Status: proposal and evidence inventory; no candidate selected or qualified
- Audit date: 2026-07-13
- Target: OCI `VM.Standard.A1.Flex`, Linux `aarch64`
- Machine-readable record: `testlab/pins/arm64-runtime-candidates.json`
- Traces: `REQ-O005`, `REQ-O012`, `REQ-O017`, `REQ-O020`, `INV-009`, `INV-017`

This audit compares candidates and defines their exit evidence. It is not an
ADR, pin, image approval, filesystem choice, package installation, or permission
to start an L1R/L4 environment. The host image, kernel, glibc package,
filesystem, systemd build, containerd, runc, and BuildKit selections all remain
`null` in the machine-readable record.

## Evidence classes

The words in this audit have deliberately narrow meanings:

| Class | Meaning |
|---|---|
| Primary-source claim | A current vendor/upstream page says a family, architecture, package, release, or feature exists. It does not prove the exact image or runtime works for TerraScale. |
| Candidate | A family is plausible enough to enter qualification. It is not selected, mirrored, pinned, security-approved, or supported by measured evidence. |
| Local observation | A non-mutating fact about the current NixOS x86_64 workspace host. It cannot satisfy ARM64, distro, PID-1 adapter, filesystem-growth, L1R, or L4 gates. |
| L1R evidence | Signed results from the exact pre-gated tree on a real aarch64 Linux host with systemd as PID 1 and permissioned scratch storage. It proves Linux/runtime behavior, not OCI provider behavior. |
| L4 evidence | Signed results from an explicitly authorized disposable OCI A1 environment using immutable image identifiers, real IAM/network/block-volume boundaries, and cleanup proof. |

The architecture requires real systemd-as-PID-1 and OCI A1 qualification in
addition to SmolVM (`ORCHESTRATOR.md:63-65`). A cross-publish, an x64 run, a
container pretending to be an ARM host, or a package catalog entry is not ARM64
qualification (`ORCHESTRATOR.md:333-368`, `ORCHESTRATOR.md:1734-1751`).

## Current primary-source findings

All current claims below are bounded by the cited official source and the audit
date. Moving package repositories and release pages are discovery evidence;
the eventual pin must record immutable image IDs, artifact hashes/signatures,
package manifests, and internally mirrored artifacts.

- OCI documents Ampere A1 as Arm compute and supports Oracle Linux and Ubuntu
  platform images on Arm ([OCI Arm-based Compute](https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm)).
- OCI's current platform catalog lists Oracle Linux 9 and Ubuntu 24.04 for Arm.
  It explicitly directs Arm users to the standard Ubuntu image rather than
  Minimal Ubuntu ([OCI Platform Images](https://docs.oracle.com/en-us/iaas/Content/Compute/References/images.htm)).
  The separate release-note catalog shows Ubuntu 24.04 aarch64 image families,
  but this audit does not select one ([OCI Ubuntu 24.04 images](https://docs.oracle.com/en-us/iaas/images/ubuntu-2404/)).
- Canonical identifies Ubuntu 24.04 and 26.04 as ARM64 LTS releases, with
  standard maintenance through May 2029 and May 2031 respectively
  ([Ubuntu release cycle](https://ubuntu.com/about/release-cycle)). OCI's cited
  catalog does not currently list 26.04, so 26.04 is a watch item rather than an
  OCI candidate.
- Canonical's Noble package catalogs expose the glibc 2.39 and systemd 255
  families for arm64 ([Noble arm64 libraries](https://packages.ubuntu.com/noble/arm64/libs/),
  [Noble systemd](https://packages.ubuntu.com/noble/systemd)). These are not the
  exact builds in any uninspected OCI image.
- Oracle documents Oracle Linux 9 on aarch64 with UEK
  ([Oracle Linux 9 architectures](https://docs.oracle.com/en/operating-systems/oracle-linux/9/relnotes9.3/ol9-AboutOracleLinux9.html)).
  UEK 8 is available to OL9 aarch64 and is the fresh-install default beginning
  with OL9.6, but only booted immutable-image evidence can establish the actual
  OCI kernel ([UEK 8 availability](https://docs.oracle.com/en-us/iaas/oracle-linux/uek/8/uek8.0-installation-and-availability.htm)).
  The moving OL9 aarch64 BaseOS repository carries glibc 2.34 packages; it is
  not an immutable image manifest
  ([Oracle Linux 9 aarch64 BaseOS](https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/aarch64/index.html)).
- containerd's upstream 2.3 line is its first annual LTS track and publishes
  ARM64 artifacts; exact patch, mirror, signature/checksum, and pairing are
  unset ([containerd releases](https://github.com/containerd/containerd/releases),
  [containerd installation](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)).
- runc's supported stable branch must be re-evaluated at freeze. The project
  says official releases are signed and that runc is Linux-only
  ([runc releases](https://github.com/opencontainers/runc/releases),
  [runc project](https://github.com/opencontainers/runc)). Distribution builds
  remain a separate candidate because package versions can differ by
  architecture; Canonical's current Noble page visibly demonstrates that risk
  ([Ubuntu runc](https://packages.ubuntu.com/noble/runc)).
- BuildKit 0.30 is a candidate track, not an LTS selection. Its upstream release
  publishes architecture-specific artifacts and supply-chain metadata; the
  project documents workers, rootless operation, multi-platform output, and
  reproducibility controls ([BuildKit releases](https://github.com/moby/buildkit/releases),
  [BuildKit project](https://github.com/moby/buildkit)).
- Upstream filesystem tools document online mounted growth for ext4 and XFS,
  but neither documentation nor local tool presence proves safe crash recovery:
  [resize2fs](https://git.kernel.org/pub/scm/fs/ext2/e2fsprogs.git/tree/resize/resize2fs.8.in)
  and [xfs_growfs](https://git.kernel.org/pub/scm/fs/xfs/xfsprogs-dev.git/tree/man/man8/xfs_growfs.8).

## Candidate and readiness matrix

### Host image bundles

The host image is evaluated as a bundle. Kernel, glibc, systemd, cloud-init,
boot layout, firewall/link-local rules, package provenance, and filesystem
defaults cannot be mixed from catalog pages to manufacture a qualified stack.

| Candidate | Primary-source eligibility | Provisional strengths | Qualification blockers | Readiness |
|---|---|---|---|---|
| Oracle Linux 9 aarch64 OCI platform image | OCI Arm-supported image family; OL9 aarch64 uses UEK | OCI-native support path; aarch64 UEK; long-lived enterprise family | Immutable regional image IDs; actual booted UEK build; glibc/systemd/package manifest; cgroups v2; A1 boot/reboot/network/block behavior; security-update and generation-rotation policy | Candidate, unqualified |
| Ubuntu 24.04 LTS standard aarch64 OCI platform image | OCI Arm-supported standard image; Canonical ARM64 LTS | Stable LTS family; known glibc/systemd ABI families; broad upstream packaging | Immutable regional image IDs; actual kernel/glibc/systemd builds; standard-versus-Minimal enforcement; A1 boot/reboot/network/block behavior; security-update and generation-rotation policy | Candidate, unqualified |
| Ubuntu 26.04 LTS ARM64 | Canonical LTS exists, but no cited OCI platform-image family | Longer standard support window | OCI image/A1 availability absent from current primary evidence; no immutable image or boot evidence | Watchlist, not an OCI candidate |

No row wins by documentation. Selection needs comparable L1R/L4 results,
security/support review, package/mirror operations, cost/boot/resource evidence,
and an owner-approved ADR.

### Kernel and glibc tracks

Kernel and glibc are not independently selected from their host bundle. The
rows below prevent a family-level source claim from being mistaken for an exact
booted build.

| Host candidate | Kernel candidate track | glibc candidate track | Exact selection | Required proof |
|---|---|---|---|---|
| Oracle Linux 9 aarch64 | Image-supplied UEK. Oracle's current docs establish aarch64 UEK and UEK 8 availability, but OCI catalog/release-note differences make the exact booted branch/build an observation gate. | OL9 glibc 2.34 ABI family | Unset | Immutable image IDs in every target region; booted `uname -r`; kernel package NEVRA/hash/config; command line/modules; glibc package NEVRA/hash and loader; security/update/reboot/rollback policy; A1 runtime and block tests |
| Ubuntu 24.04 LTS standard aarch64 | OCI image-supplied Ubuntu kernel; no version inferred from an amd64, archive, GA, or HWE catalog row | Noble glibc 2.39 ABI family | Unset | Immutable image IDs; booted kernel package/version/config and loader/package manifest; security/update/reboot/rollback policy; A1 runtime and block tests |

A self-contained .NET `linux-arm64` artifact still has a native loader/kernel
boundary. Publishing it on x64 does not prove it starts against either candidate
glibc/image bundle, and an OCI multi-platform index does not prove the selected
ARM64 child runs.

### Filesystems

| Candidate | Known capability | Mandatory comparison | Readiness |
|---|---|---|---|
| ext4 + pinned e2fsprogs | Online growth is supported when kernel/filesystem permit it; `resize2fs` does not grow the underlying block device/partition | Format/mount options, UUID stability, provider-rescan sequence, partition/LVM choice, crash matrix, fsck/recovery, online expansion under load, latency/throughput/IOPS, wrong-device/no-format/shrink rejection | Candidate, unqualified |
| XFS + pinned xfsprogs | `xfs_growfs` expands a mounted filesystem | Same exact identity, rescan, crash, recovery, load, SLO, denial, package/mirror, and operational comparison as ext4 | Candidate, unqualified |

The approved storage SLO and layout are missing. This audit therefore does not
select ext4, XFS, partitions, LVM, mount options, or tool versions.

### Runtime and build stack

| Component/track | Candidate basis | Evidence still required | Readiness |
|---|---|---|---|
| systemd from selected distro | Must be the real system manager; distro bundles are candidate-coupled | PID 1, D-Bus reconnect/transient units, credentials, cgroups v2 CPU/memory/IO/PIDs, journald, watchdog, timeout/drain/restart/rollback/daemon-reexec | Candidate, unqualified |
| containerd 2.3 LTS upstream | ARM64 upstream artifact and LTS line exist | Exact patch/signature/hash/mirror; glibc/static choice; paired runc; configuration/socket; pull-by-digest; snapshot/GC; cgroup/seccomp/mount/user/signal/log lifecycle; N/N-1 | Candidate, unqualified |
| containerd distro package | Vendor package may simplify security updates/integration | Architecture-specific exact build and support; provenance; full same runtime matrix; paired runc; compare update cadence to upstream LTS | Candidate, unqualified |
| runc upstream supported stable | Signed upstream Linux releases exist | Re-evaluate supported branch at freeze; exact ARM64 artifact/signature/mirror; containerd pairing; OCI conformance; capabilities/seccomp/cgroups/mount/user denial; escape regressions; N/N-1 | Candidate, unqualified |
| runc distro package | Vendor package may align with distro security updates | Exact ARM64 build rather than amd64 assumption; provenance/support; same denial/conformance/pairing matrix | Candidate, unqualified |
| BuildKit 0.30 upstream | Current upstream candidate with ARM64 artifacts and provenance/SBOM | Exact patch/signature/hash/mirror; isolated worker threat model; no Docker socket/production credentials; reproducible multi-platform digests; cache/secret/network/cancellation/disk/cleanup adversarial tests | Candidate, unqualified; no LTS claim |

There is an immediate packaging compatibility gate: containerd's current 2.3
release notes say its recommended dynamic binaries are linked against glibc
2.35, while the Oracle Linux 9 candidate is on the glibc 2.34 ABI family. That
dynamic artifact therefore cannot be assumed usable on OL9. The alternatives
(vendor package, reviewed source build, or upstream static artifact) remain
unselected; upstream also notes that the static build is not position
independent, so using it needs an explicit hardening disposition. Ubuntu 24.04's
newer glibc family removes that particular floor mismatch but still requires
exact artifact inspection and L1R/L4 execution.

BuildKit is a CI worker capability, not permission to put a privileged daemon on
production database/control hosts. Worker isolation and runtime selection remain
separate decisions.

## Local observation: x86_64 only

Read-only inspection on 2026-07-13 observed:

| Fact | Observation | Qualification value |
|---|---|---|
| Host | NixOS 26.11, `x86_64`, kernel 6.18.38, glibc 2.42 | Local developer-host context only |
| PID 1 / systemd tools | PID 1 is systemd; `systemctl`, `journalctl`, and `busctl` report systemd 261 | Does not prove a candidate distro, ARM64, orchestrator D-Bus adapter, or L1R |
| Root filesystem | ext4 | Does not prove format/layout, online growth, crash recovery, performance, or OCI volumes |
| Filesystem tools | `resize2fs` 1.47.4 present; `xfs_growfs` absent | Presence/absence only; no scratch device was touched |
| Runtime/build tools | containerd, runc, buildkitd, and buildctl absent from PATH | No runtime qualification exists locally |

Exact command classes are recorded in the machine-readable file. No package was
installed, service/VM was started, filesystem was changed, image was downloaded,
or cloud API was called. Although local PID 1 happens to be systemd, this turn did
not run a unit, D-Bus lifecycle, container, or filesystem test.

## L1R evidence plan

L1R starts only after valid exact-tree L0/L0C pre-deployment evidence exists
(`ORCHESTRATOR.md:1114-1154`). Run each host candidate independently on a real
aarch64 Linux host with systemd as PID 1. Within each host run both filesystem
candidates. Readiness therefore requires this full interaction matrix:

| Host | ext4 | XFS |
|---|---|---|
| Oracle Linux 9 aarch64 | Required L1R report | Required L1R report |
| Ubuntu 24.04 LTS standard aarch64 | Required L1R report | Required L1R report |

Never reuse one host's filesystem result for the other: kernel, block-rescan,
partition/LVM, filesystem-tool, systemd-mount, package, and recovery behavior can
differ. The machine-readable record enumerates all four combinations explicitly.
A later owner-approved ADR may narrow future qualification only by selecting a
coupled host/filesystem pair and revising the record/validator deliberately; a
standalone host or filesystem preference, missing row, or convenient result is
not such a selection.

### Required immutable inputs

- candidate manifest containing image/source digest, package repository snapshot,
  kernel/glibc/systemd/containerd/runc/BuildKit packages and hashes, configuration,
  test-harness tree/digest, and expected architecture;
- internally mirrored and verified runtime/build artifacts;
- a dedicated disposable scratch block device or loop backing file carrying a
  harness-generated nonce and explicit destruction approval; and
- signed `pre-deployment-evidence.json` matching the test tree and binaries.

### Exact fact-capture commands

Run inside the candidate after boot, preserving stdout, stderr, exit code, and
monotonic start/end times in the signed evidence bundle:

```text
uname -m
uname -r
cat /etc/os-release
getconf GNU_LIBC_VERSION
cat /proc/1/comm
systemctl --version
systemctl is-system-running
stat -fc %T /sys/fs/cgroup
systemctl show --property=ControlGroup --value init.scope
findmnt --json
lsblk --json --output NAME,KNAME,TYPE,SIZE,FSTYPE,UUID,MOUNTPOINTS
containerd --version
runc --version
buildkitd --version
buildctl --version
resize2fs -V
xfs_growfs -V
```

The eventual harness must reject unless `uname -m` is `aarch64`, `/proc/1/comm`
is `systemd`, cgroups v2 is mounted, the manifest matches the booted packages,
the scratch device identity/nonce matches exactly, and the pre-deployment
attestation covers the harness and artifacts.

### Scenario command contract

The qualification harness does not yet exist; implementing it is an explicit
blocker, not something this audit fakes. Its stable invocation contract must be:

```text
runtime-qualification l1r verify-inputs --manifest <signed-manifest> --predeployment-evidence <signed-evidence>
runtime-qualification l1r systemd --manifest <signed-manifest> --scenario all
runtime-qualification l1r container --manifest <signed-manifest> --scenario all
runtime-qualification l1r buildkit --manifest <signed-manifest> --scenario all
runtime-qualification l1r filesystem --manifest <signed-host-manifest> --host-candidate <host-candidate-id> --filesystem ext4 --scratch-id <approved-id> --crash-checkpoint each
runtime-qualification l1r filesystem --manifest <signed-host-manifest> --host-candidate <host-candidate-id> --filesystem xfs --scratch-id <approved-id> --crash-checkpoint each
runtime-qualification evidence finalize --layer L1R --output <host-candidate-id>-l1r-evidence.json
runtime-qualification evidence verify <host-candidate-id>-l1r-evidence.json
```

`--scenario all` must include success plus denials, stale generation/fence,
timeout, cancellation, process/daemon crash, reboot, D-Bus/containerd reconnect,
resource exhaustion, signal/drain, credential redaction, log bounds, image-digest
mismatch, cache poisoning, and N/N-1 upgrade/rollback. Filesystem checkpoints
cover cloud/device-size observation (faked only at L1R), guest rescan, partition
or LVM growth if selected, filesystem grow, verification, reboot/fsck, and retry.
Known data is never formatted; shrink requests always fail.

L1R readiness passes only with four complete host-by-filesystem reports—OL9/ext4,
OL9/XFS, Ubuntu/ext4, and Ubuntu/XFS—plus both host/runtime reports. One ext4 and
one XFS report on different hosts is insufficient. A later owner choice may use
these comparable results; the harness must not mark a host or filesystem
selected.

## L4 evidence plan

L4 requires explicit cloud-mutation authorization, a credential scope limited to
fresh disposable resources, approved cost/TTL, default-closed ingress, and a
cleanup/quarantine owner. It repeats relevant L1R commands on the exact OCI A1
image and adds provider boundaries. Until an explicit coupled host/filesystem
selection deliberately narrows the matrix, L4 also requires all four host-by-
filesystem combinations because OCI image kernels, guest tooling, and provider
block integration can change the outcome.

```text
runtime-qualification l4 verify-inputs --manifest <signed-manifest> --predeployment-evidence <signed-evidence> --shape VM.Standard.A1.Flex
runtime-qualification l4 provision --manifest <signed-manifest> --ttl <approved-ttl> --ingress closed
runtime-qualification l4 host --scenario boot-reboot-replace-generation
runtime-qualification l4 orchestrator --artifact <linux-arm64-digest> --scenario start-health-restart-rollback
runtime-qualification l4 container --manifest-digest <multi-platform-digest> --scenario all
runtime-qualification l4 volume --host-candidate <host-candidate-id> --filesystem ext4 --scenario attach-rescan-expand-crash-detach-reattach
runtime-qualification l4 volume --host-candidate <host-candidate-id> --filesystem xfs --scenario attach-rescan-expand-crash-detach-reattach
runtime-qualification l4 boundaries --scenario iam-metadata-network-link-local-wrong-volume-stale-fence
runtime-qualification l4 performance --storage-slo <approved-slo> --runtime-budget <approved-budget>
runtime-qualification l4 cleanup --operation-id <operation-id>
runtime-qualification l4 inventory --operation-id <operation-id> --expect-empty-or-quarantined
runtime-qualification evidence finalize --layer L4 --output <candidate-id>-l4-evidence.json
runtime-qualification evidence verify <candidate-id>-l4-evidence.json
```

The L4 evidence must bind per-region image OCIDs, launch-template generation,
booted package manifest, kernel command line, shape/OCPU/memory, block-volume IDs
in hashed/redacted form, filesystem UUIDs, artifact/platform digests, every
provider work request, scenario results, performance measurements, cost window,
and cleanup inventory. A denied or incomplete inventory cannot claim cleanup.

Qualification fails on x86 execution, emulation standing in for A1, systemd not
being PID 1, mutable image aliases without resolved IDs, package drift, missing
runtime signature/hash, unexpected platform digest, skipped crash checkpoint,
unknown/wrong device, secret output, broad IAM, public ingress, SLO failure, or
unresolved cleanup ambiguity.

## Readiness decision

No component is selected. The only justified state is:

- two host-image candidates, both unqualified;
- ext4 and XFS candidates, both unqualified and unselected;
- all four host-by-filesystem combinations required independently at L1R and L4;
- systemd/containerd/runc/BuildKit tracks requiring exact pins and L1R/L4 proof;
- local x86_64 observation with zero qualification layers; and
- L1R/L4 not run because image/tool selections, harness, approved SLOs,
  pre-deployment evidence, and mutation authority do not yet exist.

The deterministic validator enforces this state and rejects adversarial attempts
to accept/select a candidate, masquerade x64 observation as ARM64 evidence,
remove a filesystem candidate or one required interaction pair, or cite an
unknown source.
