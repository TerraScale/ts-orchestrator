# Phase 0 local toolchain audit

- Audit date: 2026-07-13
- Host: NixOS 26.11, Linux 6.18.38, x86_64
- Scope: read-only command/path/version inspection only
- Qualification status: not a production, L1R, L3S, or L4 qualification

No package was installed or upgraded, no service or VM was started, and no cloud API was called. `oci --version` and `pulumi version` are local executable queries, not provider operations. Presence means only that the executable was found; it does not establish an approved pin, configuration, compatibility window, credential boundary, or runtime behavior.

## Findings

| Capability | Local observation | Readiness judgment | Required exit evidence |
|---|---|---|---|
| .NET SDK | `dotnet` 10.0.301 at `/home/mariogk/.local/bin/dotnet`; `global.json` requests 10.0.301 with `latestFeature` roll-forward | Baseline pin present; local NixOS publish is not portable release evidence | Pinned ordinary-Linux hermetic image; locked restore/build/test; reproducible x64/ARM64 digests; real A1 run |
| .NET test packages | TUnit 1.56.18 and YamlDotNet 18.1.0 are centrally pinned | Incomplete for the mandated property/model/fuzz/mutation/static-analysis suite | Select and centrally pin all test, coverage, mutation, fuzz, analyzer, vulnerability, license, and secret-scan tools |
| NATS server | `nats-server` v2.14.3 present | Version is observed but not selected/pinned; CLI `nats` is absent; N/N-1 policy and L0C evidence absent | Pin server/client/CLI and N/N-1 matrix; mirror artifacts; run credential-free L0C conformance |
| containerd/runc | Both absent | Runtime boundary unavailable locally | Pin versions and install only in an approved hermetic L1R image; prove gRPC/runtime/cgroup/seccomp contract |
| systemd | systemd 261 present; its local build-feature banner was recorded | Version observed, but this audit did not inspect PID 1 behavior or run D-Bus/unit tests | Pin production host version/image and run L1R systemd-as-PID-1 D-Bus, credentials, cgroups, journald, and rollback tests |
| BuildKit | `buildctl` and `buildkitd` absent | CI build engine unavailable locally | Pin client/daemon and worker isolation profile; prove rootless/isolated build and cache/publish boundaries |
| Rootless Podman | Replacement selected after this audit; no result is inherited from the retired hypervisor lane | Unqualified until fresh rootless status, version, network, storage-driver, cgroup, image-digest, isolation, resource-limit, and cleanup evidence is recorded | Pin Podman and image manifest digests; prove closed-catalog enforcement, nine-container startup, network isolation, persistence, limits, crash recovery, and orphan-free cleanup |
| OCI CLI | OCI CLI 3.89.1 present | Observed, not pinned; no authentication or cloud call attempted; SDK/API contract unqualified | Pin OCI .NET SDK/CLI used by approved tooling, cite API semantics, and defer mutation evidence to credential-gated L4 |
| Pulumi | Pulumi v3.251.0 present | Observed, not pinned; no stack/login/provider call attempted | Pin CLI/providers/plugins and hermetic runtime; model retain/unmanage/handoff; qualify only on fresh greenfield resources |
| ext4 tools | `resize2fs` 1.47.4 present | Partial local capability; no loop-device or online expansion test | Pin e2fsprogs in L1R image and run every expansion crash checkpoint |
| XFS tools | `xfs_growfs` absent | XFS candidate cannot be evaluated locally | Pin xfsprogs in L1R image and run the same online expansion/crash matrix as ext4 |
| Block discovery | util-linux `lsblk`, `findmnt`, and `blkid` 2.42.2 present | Read-only discovery commands available; not an allowlisted production adapter contract | Define typed allowlist/observations and prove wrong-device/UUID/provider-ID rejection |
| Partition/LVM growth | `growpart` and `parted` absent; `lvm` present but its version query could not access device-mapper as this user | Layout/growth path unqualified | Choose partition/LVM layout, pin required tools, and exercise permissioned loop/block harness in L1R |
| Signing | `cosign`, `notation`, and `oras` absent | No artifact/evidence signing implementation can be qualified | Select signing identity/format/tool, pin and mirror it, protect key/identity, prove verification and revocation |
| SBOM/vulnerability | `syft`, `trivy`, and `grype` absent | No SBOM or vulnerability scanner selected | Select and pin SBOM plus vulnerability/license policy tools; bind outputs into exact-tree evidence |
| ARM64 execution | Host is x86_64; `qemu-aarch64` and `aarch64-linux-gnu-gcc` absent | No local ARM64 execution or cross-toolchain qualification; cross-publish alone is insufficient | Qualify exact ARM64 artifact on approved OCI A1, with selected host loader/kernel/glibc and managed workload images |

## Exact inspection commands

The audit used only these non-mutating classes of command:

```text
uname -srmo
uname -m
read /etc/os-release
command -v <tool>
<tool> --version (or the tool's local version equivalent)
read global.json, Directory.Packages.props, and docs/audits/phase0-build-baseline.md
```

The `lvm version` query returned device-mapper permission errors, so no LVM version or usability claim is made. `resize2fs -V` printed 1.47.4 and then rejected the flag; only the version banner is recorded. Version output was bounded by a five-second timeout. No command used credentials or contacted an external endpoint.

## Blocking selections and measurements

The local machine cannot close Phase 0 toolchain readiness. The repository still needs approved pins for NATS and its N/N-1 window, Podman and image manifests, containerd/runc, BuildKit, host image/kernel/glibc, ext4/XFS tooling and layout, Pulumi/providers, OCI SDK, VPN, DNS, observability backends, regional artifact mirroring, signing/attestation, SBOM/vulnerability/license scanning, and the complete test stack. ARM64 remains an L4 real-A1 boundary.
