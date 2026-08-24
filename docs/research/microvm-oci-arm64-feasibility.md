# MicroVM isolation on OCI Arm64

Status: research input; not an architecture decision
Date: 2026-08-23
Scope: one microVM (or an explicitly documented alternative sandbox) per tenant
allocation for stateless and serverless OCI workloads on OCI Ampere hosts.

## Result

Per-allocation microVM isolation is technically feasible on an Arm64 Linux host,
and OCI has credible Arm bare-metal candidates, but no OCI Arm VM shape is a
supported production KVM host. Oracle Linux's current KVM host requirements
state that nested virtualization is unsupported for KVM deployments. A VM may
happen to expose `/dev/kvm`, but that observation cannot qualify a production
microVM tier. The Oracle Compute API model also has no nested-virtualization
launch field. OCI bare-metal shapes still require an exact image, kernel, and
VMM qualification plus Oracle support confirmation.

The strongest OCI-first path is:

1. Qualify `BM.Standard.A1.160` first with an executable KVM and runtime spike.
   OCI documents this as a bare-metal Ampere A1 shape with 160 OCPUs and 1,024
   GB of memory. It is the safest OCI planning baseline, but the exact
   image/kernel/VMM, capacity, recovery, and support posture still require
   qualification. It is a very different cost and failure-domain unit and must
   be benchmarked as such.
2. Qualify `BM.Standard.A4.48` and `BM.Standard.A4.Ax.48` alongside or after
   A1. These are credible newer Arm candidates, but they remain unproven until
   the exact capability and recovery lane passes.
3. Keep `VM.Standard.A1.Flex`, `VM.Standard.A2.Flex`, `VM.Standard.A4.Flex`,
   and `VM.Standard.A4.Ax.Flex` as disposable diagnostic probes only. Record
   observed capabilities and Oracle's support response, but do not create a
   supported production tier from a VM result unless Oracle officially changes
   the nested-KVM support posture. If a product tier can accept weaker
   isolation, qualify gVisor `systrap` separately. It supports ARM64 and runs as
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

## 2026-08-23 addendum: OCI ARM KVM support and economics

This addendum supersedes the earlier description of `VM.Standard.A1.Flex` as
merely an evidence gap for production KVM. Oracle Linux's current KVM host
requirements explicitly say that KVM can be used on a bare-metal host, that
nested virtualization scenarios are not supported for KVM deployments, and that
Arm (`aarch64`) CPUs can be used when virtualization features are available:
[Oracle Linux 9 KVM host system requirements](https://docs.oracle.com/en/operating-systems/oracle-linux/9/kvm-user/kvm-SystemRequirementsandRecommendations.html).

That is a support negative for KVM inside an OCI VM, even if a particular VM
happens to expose a `/dev/kvm` device. It does not prove that every OCI VM
image hides the device, but it is enough to prohibit planning the VM shapes as
the supported production microVM host. The same conclusion applies to
`VM.Standard.A2.Flex`, `VM.Standard.A4.Flex`, and `VM.Standard.A4.Ax.Flex`:
they are VM shapes, and no OCI document reviewed here promises nested KVM or
provides a nested-virtualization launch switch. The current OCI shape catalog
lists those Arm VM shapes and their capacities but makes no KVM claim:
[OCI Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm).

### Shape-by-shape decision

| OCI shape | What the public sources establish | Planning status for TerraScale microVMs |
| --- | --- | --- |
| `VM.Standard.A1.Flex` | Ampere A1 VM, 1--76 OCPUs and up to 472 GB; no nested-KVM guarantee or launch option. Oracle Linux explicitly says nested KVM is unsupported. | **Unsupported for the production KVM floor.** A disposable probe may document an accidental capability, but must not turn it into a supported tier. |
| `BM.Standard.A1.160` | Ampere A1 bare metal, 160 OCPUs and 1,024 GB. Oracle Linux documents KVM on bare metal and Arm64 CPUs. | **Safe OCI shape to plan around today**, subject to the exact image/kernel/VMM probe, regional capacity, and Oracle support confirmation. |
| `VM.Standard.A2.Flex` | AmpereOne A2 VM, up to 78 OCPUs and 946 GB; no nested-KVM guarantee. OCI's Arm reference documents A2 as VM-only. | **Unsupported for the production KVM floor.** |
| `VM.Standard.A4.Flex` / `VM.Standard.A4.Ax.Flex` | AmpereOne M A4 VM shapes, up to 45 OCPUs and 700/720 GB; no nested-KVM guarantee or launch option. | **Unsupported for the production KVM floor.** |
| `BM.Standard.A4.48` / `BM.Standard.A4.Ax.48` | Current catalog lists Arm bare metal with 48 OCPUs and 768 GB. Oracle Linux's generic Arm64 bare-metal KVM requirement makes this a credible candidate, but no Oracle OCI/A4-specific KVM support matrix was found. | **Likely candidate, not yet proven.** Qualify beside A1; do not make it the only launch shape until the exact lane passes. |
| OCI dedicated VM hosts | The dedicated-host table lists x86 host shapes and x86 VM series only; it has no Arm A1/A2/A4 dedicated-host shape. A dedicated VM host is still a physical host for OCI VMs, not a nested-KVM contract. | **Not an Arm solution.** Dedicated x86 capacity cannot satisfy the Arm64 microVM lane. |

The OCI Arm reference itself currently says that A1 supports both
`BM.Standard.A1.160` and `VM.Standard.A1.Flex`, while A2 is VM-only:
[OCI Arm-Based Compute](https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm).
The newer shape table is the source for the A4 additions and their exact
capacity: [OCI Compute shapes, Arm entries](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm#flexible).
The dedicated-host catalog is explicit about the host families and supported
hosted VM series; none is Arm A1/A2/A4:
[Dedicated Virtual Machine Host Shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm#dedicatedvmhost)
and [Dedicated VM Hosts](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/dedicatedvmhosts.htm).

OCI's public Python SDK model exposes `dedicatedVmHostId`, `shapeConfig`, and
`platformConfig` on launch, but not a `nestedVirtualization`, `kvm`, or
Arm-specific nested-virtualization launch property:
[LaunchInstanceDetails](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/launch_instance_details.py).
The generic bare-metal platform config has an
`areVirtualInstructionsEnabled` property, but describes examples as AMD SVM
and Intel VT-x; it is not documented as an Arm VM nested-KVM switch:
[GenericBmLaunchInstancePlatformConfig](https://github.com/oracle/oci-python-sdk/blob/master/src/oci/core/models/generic_bm_launch_instance_platform_config.py).

### Oracle Linux, UEK, and Arm package qualification

Oracle Linux does provide a usable Arm64 KVM software path on bare metal, with
one packaging caveat: the `Virtualization Hypervisor` group is available, but
the combined `Virtualization Host` group is explicitly unavailable on
`aarch64`. The individual package guidance and this limitation are documented
here: [Oracle Linux 9 KVM virtualization packages](https://docs.oracle.com/en/operating-systems/oracle-linux/9/kvm-user/kvm-VirtualizationPackages.html).
Oracle's package-source guide says the Default KVM stack is fully supported
across Oracle Linux kernels; the Oracle KVM Stack is engineered for current UEK
KVM features and requires UEK8U2 (or remains on the UEK7/QEMU 7.2 and libvirt
9.0 stack): [Oracle Linux 9 KVM package sources](https://docs.oracle.com/en/operating-systems/oracle-linux/9/kvm-user/kvm-VirtualizationPackageSources.html).
The exact Oracle Linux image and UEK release must therefore be part of the
qualification identity. The package documentation is software support, not an
OCI promise that a VM exposes hardware virtualization.

Ampere's own public material establishes the server-class Altra/AmpereOne
processor families and discusses container/VM density, but the processor page
and Altra datasheet do not promise that an OCI VM exposes KVM or that nested
virtualization is supported:
[Ampere processor families](https://amperecomputing.com/products/processors)
and [Ampere Altra datasheet (PDF)](https://amperecomputing.com/assets/Altra_Rev_A1_DS_v1_50_20240130_3375c3dec5_1c5d4604fa.pdf).
This is consistent with treating the Arm CPU feature set as necessary but not
sufficient cloud-provider evidence.

Firecracker's own host requirements are unambiguous: it supports Linux
`aarch64`, requires the KVM module, and requires read/write access to
`/dev/kvm`; its production guide says isolation depends on KVM and processor
virtualization features: [Firecracker getting started](https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md)
and [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md).
Cloud Hypervisor likewise runs on KVM, supports AArch64 servers with GICv3,
and documents a recommended Linux host kernel: [Cloud Hypervisor README](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/README.md).
These sources establish the runtime prerequisites; they do not override
Oracle's nested-KVM support boundary.

### Cost and density model (USD list prices, accessed 2026-08-23)

The official OCI price page presents Arm A1, A4, and A4 Ax as separate OCPU
and memory price rows. The values below are the USD `pay-as-you-go` entries in
Oracle's price feed, mapped to the rows in the page:
[OCI Cloud Price List](https://www.oracle.com/cloud/price-list/),
[Compute pricing page](https://www.oracle.com/cloud/compute/pricing/), and
[official price JSON](https://www.oracle.com/a/ocom/docs/pricing/cloud-price-list.json).
These are list-price facts, not a quotation or a negotiated Universal Credits
rate.

| Resource | OCI shape capacity | OCPU list rate | Memory list rate | List compute cost/hour | List compute cost/month (730 h) | List compute cost (744 h) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `BM.Standard.A1.160` | 160 OCPUs, 1,024 GB | $0.0100/OCPU-h | $0.0015/GB-h | **$3.1360** | **$2,289.28** | **$2,333.18** |
| `BM.Standard.A4.48` | 48 OCPUs = 96 cores, 768 GB | $0.0138/OCPU-h | $0.0027/GB-h | **$2.7360** | **$1,997.28** | **$2,035.58** |
| `VM.Standard.A1.Flex` (example 2 OCPU, 12 GB) | Flexible; 1 OCPU minimum, 1 GB minimum subject to shape rules | $0.0100/OCPU-h | $0.0015/GB-h | **$0.0380** | **$27.74** | **$28.27** |

The BM totals are additive OCPU plus memory list prices. Oracle's price page
explicitly says A1 resource-based OCPU and memory SKUs are priced separately
and that the resource amounts are fixed for bare metal; its table also exposes
separate A4 OCPU and memory rows. A4's separate-row presentation is an
observed price-list fact, but the page's explanatory footnote names A1 rather
than A4, so confirm the exact A4 SKU treatment on the first bill before
committing capacity. Additional boot/block volumes, network traffic, and other
services are excluded; OCI says these are billed separately:
[OCI Compute overview](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/computeoverview.htm).

For A1, Oracle's price page and Arm reference advertise the first 3,000
OCPU-hours and 18,000 GB-hours each month as free, shared across the A1
resource usage. If that allowance applies to the paid tenancy, it reduces the
single-node A1 example by at most $57/month, to about **$2,232.28/month**;
control-plane A1 usage consumes the same shared allowance. A separate current
Always Free resource page describes a 1,500 OCPU-hour/9,000 GB-hour monthly
VM allowance and caps an Always-Free-only tenancy at 2 OCPUs/12 GB:
[OCI Arm reference](https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm),
[Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm).
This account-state discrepancy is why production budgets should use the
uncredited list total and treat any A1 free allowance as upside to verify in
the tenancy. A1 capacity may also be limited in some regions:
[Compute shapes and capacity note](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm).

OCI says on-demand Compute is billed by the second, and the shape reference
states flexible resources have a one-minute minimum. The VM A1 Flex minimum is
therefore 1 OCPU and at least 1 GB of memory, billed per second after one
minute. BM A1 and BM A4 retain their full fixed shape resources while running;
the public pages reviewed here do not state a separate BM-specific minimum
charge, so retain the one-minute/per-second behavior as a billing-confirmation
item rather than a design assumption: [Compute overview](https://docs.oracle.com/en-us/iaas/Content/Compute/Concepts/computeoverview.htm)
and [Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm).
OCI's pricing page says its list prices are the same across global regions,
including government regions, Dedicated Region, and Oracle Alloy, but actual
availability/capacity, local-currency display, taxes, commitments, and
negotiated discounts still need regional/account verification:
[OCI pricing](https://www.oracle.com/cloud/pricing/).

For a simple capacity estimate, assume a one-vCPU, 2-GB tenant microVM and
ignore host reservations. A fully packed A1 BM node would hold at most 160
such allocations (CPU-bound), costing about **$0.0196 per occupied
allocation-hour**, **$14.31 per allocation-month** at 730 hours, or **$14.58**
at 744 hours. A4 BM has 96 physical cores and would hold at most 96, costing
about **$0.0285/hour**, **$20.81/month** at 730 hours, or **$21.20** at 744
hours per allocation. These are estimates, not customer prices:
they exclude VMM/guest memory, host-agent/NATS overhead, image cache,
networking, storage, redundancy, spare capacity, and failure/maintenance
headroom. With a conservative 10% host reserve, the corresponding estimates
rise to roughly $15.90 (A1) and $23.12 (A4) per slot-month. A4's node list
total is about 12.8% lower than A1's, but it has 40% fewer physical cores and
25% less RAM; it is cheaper per physical core only because one A4 OCPU is two
cores. Price alone therefore does not make A4 the better microVM node: it is
attractive only if its per-core performance and workload mix offset the lower
node capacity.

The practical break-even rule is to price a BM node as a fixed 24x7 capacity
commitment. A serverless scheduler must keep enough admitted allocations (or
use another tenant pricing model) to cover the full node cost while reserving
VMM and recovery headroom; scale-to-zero cannot power down a shared BM host
without moving workloads. A small A1 VM is economical for control-plane duties
(for example, 2 OCPUs/12 GB is $27.74/month before any A1 allowance), but it
must not be used as a tenant microVM host because nested KVM is unsupported.

### Exact remaining support question and disposable probe

Before production qualification, open an Oracle support request containing the
shape, region, compartment tenancy type, image OCID, kernel/UEK build, and VMM
version, and ask exactly:

> Is KVM-in-guest / nested virtualization officially supported for
> `VM.Standard.A1.Flex`, `VM.Standard.A2.Flex`, `VM.Standard.A4.Flex`, or
> `VM.Standard.A4.Ax.Flex`? Is `/dev/kvm` intentionally exposed, supported by
> Oracle Linux UEK, and covered by OCI support/SLA? For
> `BM.Standard.A1.160` and `BM.Standard.A4.48`, is Oracle Linux KVM with the
> named UEK/image combination supported, including Firecracker and Cloud
> Hypervisor on AArch64?

The disposable probe should be run only in a non-production compartment on
each candidate shape and exact image. Capture `uname -m`, kernel/UEK build,
`/dev/kvm` existence and read/write access, KVM module state, a real
`KVM_GET_API_VERSION`/`KVM_CREATE_VM` ioctl result, and a Firecracker and
Cloud Hypervisor guest boot with the selected Arm64 kernel/rootfs. Then test
guest networking, teardown, host-agent restart, and VMM crash recovery. A
`/proc/cpuinfo` flag or a successful `test -e /dev/kvm` alone is not evidence
of a supported production boundary. Do not silently downgrade a VM lane to
gVisor systrap when the requested capability is `microvm-kvm`.

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

These API/documentation observations do not establish the runtime result for a
bare-metal candidate. For an OCI VM, Oracle's nested-KVM support negative makes
the exact-tree probe diagnostic only; it cannot change the unsupported
production posture unless Oracle's written support position changes. For
`BM.Standard.A1.160` and the A4 bare-metal candidates, the required answer is
an exact-tree, executable probe on the exact image/kernel and shape, followed
by Oracle support's written confirmation of the supported posture. The probe
must test the device and a real guest boot; checking only `/proc/cpuinfo`, a CPU
flag, or a cloud shape name is insufficient.

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
| Firecracker on qualified Arm bare metal | Exact Arm64 KVM access on `BM.Standard.A1.160` or `BM.Standard.A4.48`/`.Ax.48`; verify image/kernel | Small VMM; one process/VM; Linux guest; OCI conversion is needed | Designed for small microVMs; published numbers are workload-specific examples, not a TerraScale SLO | Kernel/rootfs pipeline, jailer, TAP, block backing, VMM lifecycle, snapshots/recovery, and host security updates |
| Cloud Hypervisor on qualified Arm bare metal | KVM, Arm64 server, GICv3; recommended host kernel 5.13; verify exact BM shape | Small VMM with broad Virtio/hotplug features; OCI conversion is needed | Low-footprint objective; actual boot/RSS/density must be measured | Similar to Firecracker, with more device/firmware choices to qualify |
| crosvm on qualified Arm bare metal | Linux KVM access and modern 5.x kernel on a qualified Arm BM host | Strong process-per-device sandbox; OCI adapter is product work | No directly applicable TerraScale density data found | VMM/device policy and host adapter are product-owned |
| Kata on qualified Arm bare metal | Configured hypervisor still needs KVM; Arm64 support is documented | OCI/containerd-compatible VM-backed runtime; sandbox may contain multiple containers | More layers and guest components; likely higher fixed cost; measure one-sandbox-per-allocation | Lowest OCI-runtime integration risk, highest component count |
| Firecracker/Cloud Hypervisor on OCI Arm VM (diagnostic only) | OCI VM nested KVM is unsupported for production planning, even if `/dev/kvm` is observable | Useful for recording provider behavior; cannot establish a supported microVM tier | Any observed density is diagnostic and must not become a capacity promise | Disposable probe only; do not build production dependencies on this lane |
| gVisor systrap on OCI Arm VM | No KVM; ARM64 build and Linux host | Application-kernel sandbox, not a VM; lower compatibility/performance trade-off must be measured | Usually better nested-VM behavior than KVM-in-VM according to gVisor docs; no microVM equivalence | Easier VMM operations, but explicit weaker isolation tier and gVisor compatibility lifecycle |

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
`BM.Standard.A1.160`, followed by the same pair on
`BM.Standard.A4.48`/`BM.Standard.A4.Ax.48`. Keep crosvm and Kata as comparison
lanes. VM probes may document observed behavior and support-negative evidence,
but they are diagnostic only. Do not make a production claim for “microVM per
tenant” until one complete qualified BM A1 or A4 lane proves supported KVM,
boot, network/storage isolation, density, crash recovery, and host-agent
reconciliation. If a product tier can accept non-KVM isolation, offer a clearly
named gVisor-systrap tier; do not silently downgrade the requested boundary.

## Executable spike and benchmark matrix

The spike must use the exact OCI image, Linux kernel, region, shape, IAM policy,
block-volume class, and host-agent build intended for qualification. It must be
run in a disposable, non-production compartment with pre-deployment evidence;
no result from a local x86 VM or a container can qualify OCI Arm/KVM behavior.

| Lane | Inputs | Measurements/evidence | Gate or unresolved question |
| --- | --- | --- | --- |
| OCI bare-metal capability, baseline | `BM.Standard.A1.160`; exact Arm64 Linux image, UEK release, VMM, and host-agent build | `/dev/kvm` existence/permissions, KVM module, KVM ioctl open/create-VM, VMM startup, guest `uname -m`, host/guest kernel logs, support response, replacement time | Does the exact BM A1 image/kernel/VMM pass supported KVM, guest boot, recovery, and host-agent reconciliation? |
| OCI bare-metal capability, A4 candidate | `BM.Standard.A4.48` and `BM.Standard.A4.Ax.48`; same exact-tree inputs and evidence | Repeat the complete capability lane, then record CPU/memory/network topology and failure/replacement behavior | Does A4 pass the same production floor, and does its measured density justify a second supported tier? |
| OCI VM diagnostic, optional | `VM.Standard.A1.Flex`, `VM.Standard.A2.Flex`, `VM.Standard.A4.Flex`, or `VM.Standard.A4.Ax.Flex`; disposable exact Arm64 image | Record `/dev/kvm` observation, KVM module/ioctl behavior, VMM attempt, guest architecture, logs, and OCI support response | Does runtime behavior align with the documented unsupported nested-KVM posture? This lane cannot qualify production. |
| VMM boot | Firecracker and Cloud Hypervisor; crosvm/Kata comparison; 1/2 vCPU and 128/256/512 MiB guest profiles | Time from admission to guest-ready, p50/p95/p99; VMM/guest RSS; CPU at idle and boot; teardown time; boot-failure rate; artifact digests | Which VMM meets the approved boot and fixed-overhead budget? |
| OCI image path | Signed multi-arch OCI image indexes with `arm64` and negative cases | Manifest selection, digest/signature verification, layer unpack time, rootfs correctness, entrypoint/env/UID behavior, rejection of wrong architecture and privileged features | Can arbitrary stateless images run without widening host access? |
| Density | 1, 4, 16, 32, 64, then bounded higher counts per qualified BM A1/A4 host; realistic HTTP/serverless workload | Maximum admitted allocations, host RSS, CPU steal/load, p95/p99 request latency, boot queueing, reclaim/teardown, NATS/agent overhead, disk use | What density is stable under the workspace/production host budget? |
| Network | Per-VM TAP/bridge/NAT design and NATS egress | Tenant-to-tenant isolation, ingress/egress throughput and p99 latency, connection churn, host-network denial, restart/reconnect behavior | Can the host provide isolated networking without one VNIC per microVM? |
| Ephemeral storage | Read-only rootfs plus scratch disk; OCI Block Volume where used | Read/write/fsync latency, image cache amplification, disk-full behavior, teardown cleanup, crash consistency, no host-path exposure | What scratch model is safe and affordable for stateless services? |
| TerraBase integration | Managed TerraBase outside ordinary tenant admission; network clients from VMs | Connection/retry latency, TLS identity, regional outage behavior, backup/restore and volume-expansion workflow | What managed service contract makes TerraBase stateful hosting easy without exposing storage controls? |
| Security | Untrusted test images and adversarial lifecycle requests | Device/namespace/cgroup audit, jailer/seccomp/Minijail policy, no privileged/host mounts/host networking, image escape tests, VMM crash and guest reboot | Does the chosen lane meet the owner-approved tenant isolation floor? |
| Failure/reconciliation | Kill guest, VMM, jailer, host agent, NATS link, and storage path at each lifecycle phase | Recovery time, duplicate command safety, stale-generation fencing, orphan cleanup, no cross-tenant attachment, durable audit evidence | Can regional autonomy repair allocations without losing isolation? |
| Portability | Same OCI manifest and typed allocation on qualified OCI Arm bare metal and a second provider fixture; optionally include OCI VM diagnostics | Provider capability negotiation, deterministic unsupported-feature errors, no cloud-specific image or network assumptions | Is OCI interchangeability real at the contract boundary? |

Record raw measurements and exact artifact/config identities. OCI VM KVM remains
unsupported for production planning; BM A1/A4 remain unqualified until the
exact capability, guest-boot, and recovery lanes pass on the intended
production posture.

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
