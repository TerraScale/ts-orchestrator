# Price-efficient KVM hosts for tenant microVMs

Status: research input, not an architecture decision

Tracking: [TerraScale.Orchestrator#14](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/14)

Accessed: 2026-08-23, America/Sao_Paulo

Target metros: Sao Paulo (`GRU`), Silicon Valley (`SFO`), and Frankfurt (`FRA`)

TerraScale's region IDs name the intended metros. Provider API identifiers
differ: Vultr uses `sao`, `sjc`, and `fra`, while Latitude reports location
names and its own site codes. Adapter catalogs must preserve both identifiers.

## Result

Small x86 bare-metal servers are the best launch fit for TerraScale tenant
compute. They give the host agent direct KVM access, remove an outer provider
CPU quota, accept the broadest set of existing `linux/amd64` OCI images, and
let TerraScale add capacity in small units.

The practical shortlist is:

1. Qualify Latitude.sh `m4.metal.small` as the uniform first provider. The
   current plan has 6 physical AMD cores, 64 GB RAM, two 960 GB NVMe drives,
   20 TB outbound transfer, and catalog locations in Sao Paulo, Silicon Valley,
   and Frankfurt. The displayed monthly prices total **$997/month** for one
   server per target metro or **$1,994/month** for two. Current page data marks
   Brazil stock low, United States stock high, and Germany stock medium. The
   German plan currently reports stock in both `FRA` and `FRA2`.
2. Qualify Vultr as the second bare-metal adapter. Its 6-core, 32 GB
   `vbm-6c-32gb` plan costs **$185/month** and is live in Silicon Valley and
   Frankfurt, but Vultr's live Sao Paulo availability endpoint does not
   currently offer it. A mixed Latitude Sao Paulo plus Vultr Silicon
   Valley/Frankfurt layout costs **$775/month** for one host per metro or
   **$1,550/month** for two, at the price of operating two provider adapters
   and asymmetric host memory.
3. Add OCI Arm bare metal as a later density pool. At 744 hours,
   `BM.Standard.A4.48` is about **$2,035.58 per host-month** and
   `BM.Standard.A1.160` is about **$2,333.18**. Both have far lower unit costs
   once a region can keep a large host busy, but their acquisition unit and
   host-failure impact are too large for an economical launch.

One host per metro is a prototype floor, not a production availability claim.
The initial production budget must assume at least two hosts per metro, enough
unallocated capacity to drain one host, and proof that the provider places the
hosts in independent failure domains. Two servers in one rack protect against a
server failure, not a site or rack failure.

No provider resource was created, reserved, or purchased for this research.

## Why bare metal is better for this workload

A shared VPS may expose a vCPU backed by a hardware thread, a provider CPU
quota, or an oversubscribed pool. A vCPU is not universally one eighth of a
physical core, so TerraScale must not make that assumption without a provider
contract. A VPS is also unusable for the production microVM tier unless the
provider explicitly supports KVM nested virtualization.

Bare metal gives TerraScale the complete physical host budget. The host agent
should still apply cgroup CPU, memory, and I/O controls around each Firecracker
process. Those controls become an explicit tenant plan and noisy-neighbor
policy instead of a hidden provider limitation. A tenant may buy a fraction of
a core, but TerraScale controls and meters that fraction.

The economic catch is utilization. A whole server running one small allocation
is wasteful. The scheduler must pool many stateless allocations, reserve VMM
and host overhead, retain drain capacity, and measure the stable overcommit
ratio. Published Firecracker examples are not TerraScale density evidence.

## Current target-metro cost floors

Prices are USD list prices before tax, paid support, public ingress, extra IPs,
bandwidth overages, remote backups, and TerraBase storage. Fixed monthly plan
prices are shown as published. Hourly OCI estimates use 744 hours so the
comparison covers a 31-day month.

| Layout | Sao Paulo | Silicon Valley | Frankfurt | One host/metro | Two hosts/metro | Main constraint |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Latitude `m4.metal.small` | $405 | $296 | $296 | **$997** | **$1,994** | Brazil stock is marked low; monthly commitment wording conflicts with the embedded FAQ |
| Latitude/Vultr mix | Latitude $405 | Vultr $185 | Vultr $185 | **$775** | **$1,550** | Two provider adapters; US/EU hosts have 32 GB rather than 64 GB |
| Vultr, current smallest live shape per metro | 24-core/384 GB $825 | 6-core/32 GB $185 | 6-core/32 GB $185 | **$1,195** | **$2,390** | Highly asymmetric capacity |
| Vultr, uniform 24-core/384 GB | $825 | $825 | $825 | **$2,475** | **$4,950** | Larger launch unit than needed |
| OCI `BM.Standard.A4.48` | $2,035.58 | $2,035.58 | $2,035.58 | **$6,106.75** | **$12,213.50** | 96 cores and 768 GB per host; exact regional capacity unproven |
| OCI `BM.Standard.A1.160` | $2,333.18 | $2,333.18 | $2,333.18 | **$6,999.55** | **$13,999.10** | 160 cores and 1,024 GB per host; exact regional capacity unproven |

The Latitude monthly figures come from the plan's current region data. That
same page advertises monthly and yearly discounts, while its embedded FAQ
describes different discount percentages and commitment categories. Treat the
displayed prices as planning figures only. Obtain a written quote that states
the upfront payment, cancellation rule, renewal price, and stock reservation
before using them in a launch budget.

Vultr exposes two different facts. The plans API lists the regions where a plan
can exist. The regional availability API lists what can be deployed now. The
6-core plan's catalog includes `sao`, `sjc`, and `fra`, but its current live
availability includes `sjc` and `fra`, not `sao`. Capacity code must preserve
this distinction and fail admission before promising a region.

## Provider comparison

| Provider | Supported KVM path | Geographic fit | Price and capacity result | Decision |
| --- | --- | --- | --- | --- |
| Latitude.sh | Direct KVM qualification on x86 bare metal | Exact Sao Paulo, Silicon Valley, and Frankfurt catalog locations | `m4.metal.small`: 6 cores, 64 GB, 2 x 960 GB NVMe, 20 TB outbound; $405 BR and $296 US/DE displayed monthly | **Qualify first** for a uniform small-host launch, after written stock and failure-domain confirmation |
| Vultr | Direct KVM qualification on x86 bare metal | The low-end plan catalog has 23 locations including all three targets; live low-end availability currently misses Sao Paulo | `vbm-6c-32gb`: 6 cores/12 threads, 32 GB, 2 x 960 GB, 5,120 GB transfer, $185/month. Current Sao Paulo bare metal starts with the 24-core/384 GB $825 plan | **Qualify second** and use live availability rather than catalog coverage |
| OCI | Oracle Linux supports KVM on Arm64 bare metal; nested KVM on OCI VMs is unsupported | OCI has the intended cloud regions, but exact A1/A4 capacity must be checked | A4 about $2,036 and A1 about $2,333 per 744-hour month, excluding storage/network | **Scale pool**, not launch floor |
| AWS EC2 | AWS explicitly supports KVM nested virtualization on C8i/M8i/R8i, their listed `id` and `flex` variants, X8i, C7i/M7i/R7i and their listed `flex` variants, and I7i; bare-metal EC2 also exposes the host | Broad cloud-region coverage, including the three intended geographic areas, subject to instance-family availability | Region-specific on-demand pricing and egress are materially higher than low-cost small bare metal; no extra fee for nested virtualization | **Overflow/portability lane**. Benchmark nested overhead before production use |
| Google Compute Engine | Google explicitly supports Linux KVM as the L1 hypervisor on eligible x86 VMs; it also offers large bare-metal machine types | Broad VM coverage. Bare-metal shapes vary sharply by region; Sao Paulo currently lists only a large Z3 metal option in the published table | Nested VMs avoid a large bare-metal floor, but Google warns of at least 10% loss for CPU-bound work and potentially more for I/O | **Overflow/portability lane**, not the preferred host |
| Microsoft Azure | Microsoft supports nested Hyper-V scenarios, but says non-Microsoft virtualization such as KVM in a Hyper-V VM is unsupported | Broad regions do not fix the KVM support gap | A VM price is irrelevant when the required production KVM path is unsupported | **Reject for the Firecracker/KVM tier** unless Microsoft publishes a supported KVM path or suitable generic bare metal |
| Equinix Metal | Was direct bare metal | Formerly broad metro coverage | Equinix shut Metal down on June 30, 2026; APIs and resource management are unavailable | **Reject** |
| Hetzner dedicated | Direct KVM qualification on dedicated x86 or Arm hardware | Excellent low-cost European capacity, but dedicated locations do not cover the three target metros | Attractive European unit cost; setup fees, auction inventory, and location limits prevent a uniform launch layout | **Later regional cost lane** |
| OVHcloud dedicated | Direct KVM qualification on dedicated x86 hardware | Wide European and North American footprint, but no verified uniform Sao Paulo/Silicon Valley/Frankfurt plan was found | Monthly commitments and regional catalogs vary | **Later comparison**, not the current three-metro answer |
| Scaleway Elastic Metal/Dedibox | Direct KVM qualification on dedicated hardware | Primarily Paris, Amsterdam, and Warsaw for Elastic Metal; does not meet the target map | Low European prices cannot compensate for the geographic mismatch | **Reject for initial regions** |
| IBM Cloud bare metal | Direct KVM qualification on bare metal | Broad data-center catalog includes relevant countries/metros, subject to current server inventory | Configuration pricing and provisioning commitments need a target-specific quote | **Fallback requiring quote**, behind Latitude/Vultr |

AWS and Google are not silently downgraded sandboxes. Their cited documents
explicitly support KVM nested virtualization on eligible VM families. They can
therefore form a real microVM portability lane, but the extra hypervisor layer,
performance loss, shared host economics, and egress pricing make them a worse
default than small bare metal for TerraScale.

Azure is different. Microsoft documents nested Hyper-V for supported
scenarios, then explicitly says non-Microsoft virtualization applications in a
Hyper-V VM are unsupported. Firecracker needs KVM, so Azure VMs do not meet the
current production contract.

## Architecture and workload compatibility

Arbitrary OCI workload support makes `linux/amd64` the safe launch default.
Many existing images still publish no `linux/arm64` manifest. Admission must
resolve the requested platform from the signed image index and reject an image
when no qualified host architecture exists. It must never emulate amd64 on Arm
and call that ordinary support.

The public workload contract should remain independent of provider and VMM.
The host inventory needs typed capabilities for at least:

- region, site, rack or failure domain, and live capacity state;
- `amd64` or `arm64`, physical cores, hardware threads, and NUMA layout;
- supported `kvm` plus qualified VMM, host kernel, guest kernel, and rootfs
  digests;
- allocatable memory after host/VMM reserve;
- local scratch layout, image-cache capacity, and discard behavior;
- public/private bandwidth, included transfer, overage price, and DDoS/ingress
  capability;
- billing class, minimum term, replacement SLO, and drain deadline.

Provider catalog entries are observations, not admission capacity. A regional
adapter must report live deployability and a reservation or stock identity.
The scheduler must stop admission before regional drain capacity is consumed.

## Launch and scale policy

Use these defaults until benchmarks replace them:

1. Prototype with one small x86 bare-metal host per metro only after the exact
   KVM, kernel, VMM, network, and image pipeline passes.
2. Before a production tenant claim, run at least two hosts per metro and prove
   that all allocations can drain from one failed host. Ask the provider for
   rack/site anti-affinity in writing.
3. Keep at least one host's measured allocation capacity free per metro. A
   percentage-only reserve is insufficient when the pool has two hosts.
4. Make Latitude the first uniform adapter. Add Vultr when its cheaper live
   inventory or provider diversity repays the extra operational work.
5. Add OCI A4/A1 only after measured regional demand can amortize the full host
   and the region has replacement capacity. Recalculate the crossover with
   bandwidth, storage, support, and actual microVM density, not CPU list price
   alone.
6. Keep AWS or Google supported nested KVM as an overflow lane when bare-metal
   stock is exhausted. Never move an allocation to Azure KVM or gVisor without
   changing its declared isolation capability.

TerraBase remains outside ordinary tenant admission. Its dedicated hosts,
durable volumes, replication, backup, restore, expansion, and recovery budget
need a separate provider comparison. Local tenant-compute NVMe is scratch
storage and must not become TerraBase durability by accident.

## Qualification gates before purchase

- Obtain written stock for two hosts in each target metro and documented
  rack/site separation.
- Confirm the CPU model and virtualization extensions for every delivered
  hardware generation.
- Boot the exact Firecracker and Cloud Hypervisor builds and exercise
  `KVM_GET_API_VERSION` and `KVM_CREATE_VM`.
- Measure guest-ready p50/p95/p99, steady host and guest RSS, CPU steal, network
  throughput/latency, image-cache pressure, and teardown under realistic OCI
  images.
- Kill a microVM, VMM, host agent, NATS link, and physical host. Prove fencing,
  orphan cleanup, rescheduling, and no cross-tenant attachment.
- Confirm remote console/rescue access, automated reprovisioning, hardware
  replacement SLO, DDoS behavior, IP/LB availability, bandwidth pooling and
  overages, taxes, support, and cancellation terms.
- Run the same signed `linux/amd64` workload through both shortlisted provider
  adapters. Run a signed `linux/arm64` workload on OCI only after that pool is
  qualified.

## Primary sources

- [Oracle Linux 9 KVM host requirements](https://docs.oracle.com/en/operating-systems/oracle-linux/9/kvm-user/kvm-SystemRequirementsandRecommendations.html)
- [OCI Compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)
- [OCI Compute pricing](https://www.oracle.com/cloud/compute/pricing/)
- [Oracle cloud price-list JSON](https://www.oracle.com/a/ocom/docs/pricing/cloud-price-list.json)
- [Oracle official price feed](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/)
- [Vultr bare-metal plans API](https://api.vultr.com/v2/plans-metal)
- [Vultr regions API](https://api.vultr.com/v2/regions)
- [Vultr Sao Paulo live availability](https://api.vultr.com/v2/regions/sao/availability)
- [Vultr Silicon Valley live availability](https://api.vultr.com/v2/regions/sjc/availability)
- [Vultr Frankfurt live availability](https://api.vultr.com/v2/regions/fra/availability)
- [Latitude.sh pricing and stock data](https://www.latitude.sh/pricing)
- [Latitude.sh bandwidth documentation](https://www.latitude.sh/docs/usage/bandwidth)
- [AWS supported nested virtualization](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html)
- [Google Compute Engine nested virtualization](https://cloud.google.com/compute/docs/instances/nested-virtualization/overview)
- [Google Compute Engine bare-metal instances and regions](https://cloud.google.com/compute/docs/instances/bare-metal-instances)
- [Microsoft nested virtualization support boundary](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization)
- [Equinix Metal shutdown FAQ](https://docs.equinix.com/metal/eos-faq)
- [Hetzner dedicated servers](https://www.hetzner.com/dedicated-rootserver/)
- [Hetzner locations](https://www.hetzner.com/unternehmen/rechenzentrum/)
- [OVHcloud bare-metal pricing](https://www.ovhcloud.com/en/bare-metal/prices/)
- [Scaleway Elastic Metal pricing](https://www.scaleway.com/en/pricing/elastic-metal/)
- [IBM Cloud bare-metal servers](https://www.ibm.com/products/bare-metal-servers)

## Remaining unknowns

- Provider catalog presence does not prove that six servers are simultaneously
  available or physically separated in the target metros.
- Latitude's current page and embedded FAQ disagree on discount and commitment
  terminology.
- Vultr live stock can change between research and purchase.
- No shortlist provider has yet supplied an exact hardware replacement SLO,
  rack-diversity commitment, or TerraScale-specific quote.
- No target host has yet booted the exact TerraScale guest image and VMM.
- Cost per safe tenant allocation remains unknown until density, drain reserve,
  bandwidth, and support are measured.
