# MicroVM isolation on OCI Arm64

Status: research input; not an architecture decision
Date: 2026-08-23
Scope: one microVM (or an explicitly documented alternative sandbox) per tenant
allocation for stateless and serverless OCI workloads on OCI Ampere hosts.

## Result

Per-allocation microVM isolation is technically feasible on an Arm64 Linux host,
but it is not yet proven on `VM.Standard.A1.Flex`. The public OCI Compute
material reviewed here describes A1 as a VM shape but does not promise that an
A1 guest can open `/dev/kvm` or that nested virtualization is enabled. The
Oracle Compute API model also has no nested-virtualization launch field. This is
an evidence gap, not evidence that the device is absent; an OCI A1 probe and an
Oracle support confirmation are required before treating A1 as a production
microVM host.

The strongest OCI-first path is:

1. Qualify `VM.Standard.A1.Flex` with an executable KVM and runtime spike.
2. Keep `BM.Standard.A1.160` as the Arm64 escape hatch if A1 VMs do not expose
   KVM. OCI documents this as a bare-metal Ampere A1 shape with 160 OCPUs and
   1,024 GB of memory. Bare metal is the strongest OCI candidate for exposing
   the host kernel and hardware needed for KVM, but the exact image/kernel still
   requires a probe. It is a very different cost and failure-domain unit and
   must be benchmarked as such.
3. If the product must launch on A1 VMs before KVM is available, qualify gVisor
   `systrap` as an explicitly different sandbox. It supports ARM64 and runs as
   a normal process without KVM, but it is not a microVM and must not be reported
   as equivalent isolation.

The first VMM candidate should be Firecracker for a deliberately small
stateless/serverless allocation model. Cloud Hypervisor is the main alternative
to benchmark alongside it. Kata Containers is useful if containerd's OCI
runtime contract is more valuable than keeping the VMM layer minimal; crosvm is
an additional Arm64/KVM option, but it brings less of a ready-made OCI runtime
integration story. The control plane should own a capability-based runtime
contract, not a Firecracker-specific API.

TerraBase should remain a separately managed stateful product service. Its
durable block volumes, replication, backup, expansion, and recovery lifecycle
should not be inferred from the stateless tenant allocation contract. A
TerraBase service may eventually run in a qualified dedicated microVM, but that
is a separate storage and recovery qualification lane.

## What OCI currently proves (and does not prove)

OCI's Compute overview distinguishes a bare-metal instance, which gives
dedicated physical server access, from a VM, which runs on physical bare-metal
hardware and is isolated by virtualization. It does not state that a VM is a
valid KVM host: [OCI Compute overview](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/computeoverview.htm).

The current shape table lists `VM.Standard.A1.Flex` as an Arm-based Ampere A1
VM with 1--76 OCPUs and 1--472 GB of memory. It separately lists
`BM.Standard.A1.160` as Arm-based Ampere A1 bare metal with 160 OCPUs and 1,024
GB of memory. The A1 VM entry has no nested-virtualization or `/dev/kvm`
guarantee: [OCI Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm).

The dedicated-VM-host documentation says that those hosts place VM instances
on a single-tenant physical server. The dedicated-host shape table currently
lists X7/X9/E2/E3/E4/E5 and Optimized3 host shapes, but no A1 host shape. A
dedicated VM host therefore cannot currently be selected as an Arm A1 nested
virtualization answer from the published catalog: [dedicated VM hosts](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm),
[dedicated-host shape table](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm#dedicatedvmhost).

The Oracle-maintained Python SDK's `LaunchInstanceDetails` model exposes
`dedicatedVmHostId`, `shapeConfig`, and `platformConfig`, but no
`nestedVirtualization` or `kvm` launch property: [Oracle SDK model](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/launch_instance_details.py).
The base platform-config model documents secure boot, measured boot, memory
encryption, and related settings. The generic bare-metal platform-config model
has `areVirtualInstructionsEnabled`, described with AMD Secure Virtual Machine
and Intel VT-x examples; this is not a documented A1-VM nested-virtualization
switch: [platform config](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/launch_instance_platform_config.py),
[generic bare-metal platform config](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/generic_bm_launch_instance_platform_config.py).

These API/documentation observations cannot establish the runtime result. The
only acceptable A1 answer for production planning is an exact-tree, executable
probe on the exact image/kernel and shape, followed by Oracle support's written
confirmation of the supported posture. The probe must test the device and a
real guest boot; checking only `/proc/cpuinfo`, a CPU flag, or a cloud shape name
is insufficient.

## Runtime candidates

### Firecracker

Firecracker documents Linux `x86_64` and `aarch64` support and requires
read/write access to `/dev/kvm`; its getting-started guide shows checking the
KVM module and device permissions: [getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md).
The design describes one Firecracker process per microVM, KVM-backed vCPUs,
Virtio devices, TAP-backed networking, and file-backed block devices:
[Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md).

For production, Firecracker recommends the `jailer`; its production-host guide
calls out host/guest kernel and host microcode as part of the isolation boundary,
requires Firecracker's seccomp filters, and documents jailer cgroup/namespace
isolation and privilege dropping:
[production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).
The design includes a 128 MiB single-core example and a creation-rate example,
but those are project measurements for a minimal kernel and must not become
TerraScale density promises without measuring the selected guest image,
networking, storage, and host shape.

Firecracker is a VMM, not an OCI image unpacker or a complete containerd
runtime. The Orchestrator would need a trusted OCI-image-to-guest-rootfs/guest
kernel pipeline plus a host-side VMM adapter. OCI's image specification defines
the image manifest, layers, configuration, and unpacking into an OCI runtime
bundle: [OCI Image Specification](https://github.com/opencontainers/image-spec/blob/main/spec.md).

### Cloud Hypervisor

Cloud Hypervisor documents KVM/MSHV operation, low memory footprint, minimal
device emulation, low complexity, and a small attack surface. Its main supported
architectures are `x86-64` and `AArch64`; AArch64 requires a server or board
with GICv3, and the recommended host Linux kernel is 5.13 (with most CI on
5.15): [Cloud Hypervisor README](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/README.md).
It publishes an `aarch64` static binary and supports direct Arm64 guest kernel
boot. This is a credible second VMM for the same per-allocation model, but the
OCI-image conversion and host-networking integration still belong to TerraScale.

### crosvm

crosvm documents `aarch64` support and KVM on Linux/Android, requires a modern
Linux kernel with KVM access, and uses a process-per-device model with Minijail,
namespaces, seccomp, and dropped capabilities: [crosvm README](https://github.com/google/crosvm/blob/main/README.md),
[crosvm architecture](https://github.com/google/crosvm/blob/main/ARCHITECTURE.md).
It is a technically valid Arm64/KVM candidate. Its ChromeOS/Android-oriented
device and lifecycle model means that its host adapter, image pipeline, and
operational maturity for this product must be proven in the spike rather than
assumed from architecture support.

### Kata Containers

Kata Containers documents Arm64 (`aarch64`) support using Arm hardware
virtualization and exposes an OCI-compatible containerd shim runtime. It can
use QEMU, Cloud Hypervisor, Firecracker, or other configured VMMs: [Kata platform support](https://github.com/kata-containers/kata-containers/blob/main/README.md),
[Kata runtime](https://github.com/kata-containers/kata-containers/blob/main/src/runtime/README.md),
[Kata hypervisors](https://github.com/kata-containers/kata-containers/blob/main/docs/hypervisors.md).
Kata is attractive when the requirement is “run OCI containers with a VM-backed
runtime.” It adds a shim, guest agent, guest kernel/rootfs packaging, VMM
configuration, and containerd integration. The qualification must measure
whether the additional moving parts and per-sandbox memory are acceptable for
serverless density. A Kata sandbox can also host more than one container, so the
admission contract must explicitly enforce one tenant allocation per sandbox
if that is the security boundary: [Kata architecture](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md).

### gVisor as a non-KVM fallback

gVisor builds on ARM64 and uses an application kernel to reduce the host-kernel
surface seen by a container: [gVisor README](https://github.com/google/gvisor/blob/master/README.md).
Its default `systrap` platform runs without KVM. gVisor's platform guide says
that KVM requires `/dev/kvm`, that systrap is often faster than KVM when gVisor
is itself inside a VM, and that nested virtualization is not recommended for
production because of poor performance and historical security issues:
[gVisor platform selection](https://gvisor.dev/docs/user_guide/platforms/).
The same guide says `ptrace` is no longer supported and is expected to be
removed, so it is not a fallback to design around.

gVisor systrap is therefore a useful A1-VM fallback for a lower isolation tier,
not a substitute for a per-tenant microVM. The API must expose the distinction
and prevent a policy that requires a microVM from silently downgrading to
systrap.

## OCI image and runtime boundary

OCI image indexes identify platform-specific manifests, including the `arm64`
architecture value. The image admission path must resolve an `arm64` manifest,
verify its digest/signature policy, unpack layers into a controlled rootfs, and
translate the image configuration into the guest launch contract: [OCI image index](https://github.com/opencontainers/image-spec/blob/main/image-index.md),
[OCI image specification](https://github.com/opencontainers/image-spec/blob/main/spec.md).

The OCI Runtime Specification describes a runtime bundle with a root filesystem
and process configuration, then requires the runtime to implement create/start/
kill/delete lifecycle operations: [OCI runtime config](https://github.com/opencontainers/runtime-spec/blob/main/config.md),
[OCI runtime lifecycle](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md).
An OCI-compatible public API can therefore remain stable while the provider
adapter chooses Firecracker, Cloud Hypervisor, Kata, or an explicitly lower
tier. The VMM-specific details must remain behind that adapter; OCI compliance
does not imply KVM availability or a specific isolation strength.

## Trade-offs

| Option | KVM/Arm requirement | Isolation and compatibility | Density/boot expectation | Operational burden |
| --- | --- | --- | --- | --- |
| Firecracker on A1 VM | Exact A1 `/dev/kvm` access and Arm KVM must pass | Small VMM; one process/VM; Linux guest; OCI conversion is needed | Designed for small microVMs; published numbers are workload-specific examples, not a TerraScale SLO | Kernel/rootfs pipeline, jailer, TAP, block backing, VMM lifecycle, snapshots/recovery, and host security updates |
| Cloud Hypervisor on A1 VM | KVM, Arm64 server, GICv3; recommended host kernel 5.13 | Small VMM with broad Virtio/hotplug features; OCI conversion is needed | Low-footprint objective; actual boot/RSS/density must be measured | Similar to Firecracker, with more device/firmware choices to qualify |
| crosvm on A1 VM | Linux KVM access and modern 5.x kernel | Strong process-per-device sandbox; OCI adapter is product work | No directly applicable TerraScale density data found | VMM/device policy and host adapter are product-owned |
| Kata on A1 VM | Configured hypervisor still needs KVM; Arm64 support is documented | OCI/containerd-compatible VM-backed runtime; sandbox may contain multiple containers | More layers and guest components; likely higher fixed cost; measure one-sandbox-per-allocation | Lowest OCI-runtime integration risk, highest component count |
| Firecracker/Cloud Hypervisor on BM A1 | Bare-metal Arm A1 host; KVM probe should pass, but still verify image/kernel | Strong candidate for untrusted tenants | Large host amortizes many VMs, but coarse acquisition and host-failure blast radius | Host replacement, maintenance, and capacity are much heavier than a small Flex VM |
| gVisor systrap on A1 VM | No KVM; ARM64 build and Linux host | Application-kernel sandbox, not a VM; lower compatibility/performance trade-off must be measured | Usually better nested-VM behavior than KVM-in-VM according to gVisor docs; no microVM equivalence | Easier VMM operations, but explicit weaker isolation tier and gVisor compatibility lifecycle |

The host kernel, VMM, guest kernel, rootfs, network bridge/TAP, block backing,
NATS host agent, logging, and cgroup accounting all consume resources. A
serverless scheduler must charge the complete allocation footprint, including
fixed VMM/guest overhead, rather than packing only the declared application
memory. Firecracker explicitly leaves host memory/storage accounting to the
operator: [Firecracker production setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).

For arbitrary customer code, a microVM reduces the shared-kernel exposure but
does not eliminate the need for a hardened host, patched guest and VMM, strict
device exposure, network isolation, image provenance, resource limits, and
reconciliation after crashes. Firecracker's production guidance and crosvm's
Minijail architecture both treat host process restrictions as part of the
security boundary; they are not optional hardening after launch.

## Recommendation

Adopt a capability-based provider/runtime contract with at least these explicit
capabilities:

- `oci-arm64-image` (the provider can resolve and run a signed `arm64` image);
- `microvm-kvm` (the exact host exposes usable KVM and can boot the selected VMM);
- `microvm-vmm` (Firecracker, Cloud Hypervisor, crosvm, or Kata plus its exact
  versions and guest artifacts);
- `sandbox-systrap` (gVisor fallback, explicitly weaker than a microVM);
- `ephemeral-rootfs`, `scratch-storage`, `network-isolation`, and
  `resource-accounting`;
- `terrabase-managed-storage` as a separate stateful service capability.

The initial qualification order should be Firecracker and Cloud Hypervisor on
`VM.Standard.A1.Flex`, then the same pair on `BM.Standard.A1.160` if the VM
probe fails. Keep crosvm and Kata as comparison lanes. Do not make a production
claim for “microVM per tenant” until one complete A1 or BM A1 lane proves KVM,
boot, network/storage isolation, density, crash recovery, and host-agent
reconciliation. If A1 VM has no usable KVM, either select the bare-metal A1
lane or offer a clearly named gVisor-systrap isolation tier; do not silently
downgrade the requested boundary.

## Executable spike and benchmark matrix

The spike must use the exact OCI image, Linux kernel, region, shape, IAM policy,
block-volume class, and host-agent build intended for qualification. It must be
run in a disposable, non-production compartment with pre-deployment evidence;
no result from a local x86 VM or a container can qualify OCI Arm/KVM behavior.

| Lane | Inputs | Measurements/evidence | Gate or unresolved question |
| --- | --- | --- | --- |
| OCI capability | A1 Flex at 1, 2, 4, and 8 OCPU; exact Arm64 Linux image | `/dev/kvm` existence/permissions, KVM module, KVM ioctl open/create-VM, VMM startup, guest `uname -m`, host/guest kernel logs, OCI support response | Does A1 expose a supported KVM path? Is nested KVM supported, or merely observable? |
| Bare-metal fallback | `BM.Standard.A1.160`, same image and agent | Same KVM/VMM checks plus host CPU/memory/network topology and replacement time | Is bare metal available in target regions and economically usable for density? |
| Alternative Arm shape | An OCI Arm VM shape available in the catalog, such as A2 Flex, if enabled | Repeat the complete capability lane; never infer from A1 or CPU branding | Is there a smaller or more available Arm VM with a supported KVM capability? |
| VMM boot | Firecracker and Cloud Hypervisor; crosvm/Kata comparison; 1/2 vCPU and 128/256/512 MiB guest profiles | Time from admission to guest-ready, p50/p95/p99; VMM/guest RSS; CPU at idle and boot; teardown time; boot-failure rate; artifact digests | Which VMM meets the approved boot and fixed-overhead budget? |
| OCI image path | Signed multi-arch OCI image indexes with `arm64` and negative cases | Manifest selection, digest/signature verification, layer unpack time, rootfs correctness, entrypoint/env/UID behavior, rejection of wrong architecture and privileged features | Can arbitrary stateless images run without widening host access? |
| Density | 1, 4, 16, 32, 64, then bounded higher counts per A1/BM host; realistic HTTP/serverless workload | Maximum admitted allocations, host RSS, CPU steal/load, p95/p99 request latency, boot queueing, reclaim/teardown, NATS/agent overhead, disk use | What density is stable under the workspace/production host budget? |
| Network | Per-VM TAP/bridge/NAT design and NATS egress | Tenant-to-tenant isolation, ingress/egress throughput and p99 latency, connection churn, host-network denial, restart/reconnect behavior | Can the host provide isolated networking without one VNIC per microVM? |
| Ephemeral storage | Read-only rootfs plus scratch disk; OCI Block Volume where used | Read/write/fsync latency, image cache amplification, disk-full behavior, teardown cleanup, crash consistency, no host-path exposure | What scratch model is safe and affordable for stateless services? |
| TerraBase integration | Managed TerraBase outside ordinary tenant admission; network clients from VMs | Connection/retry latency, TLS identity, regional outage behavior, backup/restore and volume-expansion workflow | What managed service contract makes TerraBase stateful hosting easy without exposing storage controls? |
| Security | Untrusted test images and adversarial lifecycle requests | Device/namespace/cgroup audit, jailer/seccomp/Minijail policy, no privileged/host mounts/host networking, image escape tests, VMM crash and guest reboot | Does the chosen lane meet the owner-approved tenant isolation floor? |
| Failure/reconciliation | Kill guest, VMM, jailer, host agent, NATS link, and storage path at each lifecycle phase | Recovery time, duplicate command safety, stale-generation fencing, orphan cleanup, no cross-tenant attachment, durable audit evidence | Can regional autonomy repair allocations without losing isolation? |
| Portability | Same OCI manifest and typed allocation on OCI VM, OCI BM, and a second provider fixture | Provider capability negotiation, deterministic unsupported-feature errors, no cloud-specific image or network assumptions | Is OCI interchangeability real at the contract boundary? |

Record raw measurements and exact artifact/config identities. The current
evidence must remain “A1 KVM unknown” until the capability lane passes on the
exact production posture.

## Primary sources

- [Oracle Compute overview](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/computeoverview.htm)
- [Oracle Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)
- [Oracle dedicated VM hosts](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm)
- [Oracle OCI Python SDK `LaunchInstanceDetails`](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/launch_instance_details.py)
- [Oracle OCI Python SDK platform config](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/launch_instance_platform_config.py)
- [Oracle OCI Python SDK generic bare-metal platform config](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/generic_bm_launch_instance_platform_config.py)
- [Linux KVM API](https://www.kernel.org/doc/html/latest/virt/kvm/api.html)
- [Linux KVM Arm documentation](https://www.kernel.org/doc/html/latest/virt/kvm/arm/index.html)
- [Firecracker getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
- [Firecracker design](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Cloud Hypervisor README](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/README.md)
- [crosvm README](https://github.com/google/crosvm/blob/main/README.md)
- [crosvm architecture](https://github.com/google/crosvm/blob/main/ARCHITECTURE.md)
- [Kata Containers README](https://github.com/kata-containers/kata-containers/blob/main/README.md)
- [Kata runtime](https://github.com/kata-containers/kata-containers/blob/main/src/runtime/README.md)
- [gVisor README](https://github.com/google/gvisor/blob/master/README.md)
- [gVisor platform selection](https://gvisor.dev/docs/user_guide/platforms/)
- [OCI Image Specification](https://github.com/opencontainers/image-spec/blob/main/spec.md)
- [OCI Image Index Specification](https://github.com/opencontainers/image-spec/blob/main/image-index.md)
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec/blob/main/config.md)
- [OCI Runtime lifecycle](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md)
