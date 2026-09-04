# TerraScale orchestration

This context defines the language used to place and operate trusted TerraScale
containers and customer tenant containers across geographic locations.

## Runtime control

**TerraScale Orchestrator**:
A provider-neutral workload orchestration platform that operates trusted TerraScale containers and customer tenant containers. All workloads run as OCI containers; Kubernetes compatibility is not implied for any workload.
_Avoid_: General-purpose container orchestrator, private Kubernetes, Kubernetes-compatible platform

**First-party workload**:
A service operated by TerraScale as part of the platform or a TerraScale product.
_Avoid_: System workload, built-in application

**Trusted container workload**:
A signed OCI container admitted from TerraScale's closed first-party catalog.
TerraBase and the TerraScale APIs are trusted container workloads.
_Avoid_: Tenant container, arbitrary container, customer image

**Tenant workload**:
A stateless service or serverless handler submitted as a signed,
digest-pinned binary and run under systemd, bound to an admitted TerraScale
interface set. Tenant compute is post-launch.
_Avoid_: Container runtimes, arbitrary customer images, image registries

**Infrastructure provider**:
A supported supplier of compute, network, and storage capacity. Provider choice must not change the workload's product-level identity or desired behavior.
_Avoid_: Cloud-specific workload, OCI workload

**Tenant allocation**:
One active execution-capacity unit for a tenant workload. It may disappear
without durable-local-state recovery.
_Avoid_: Pod, bare cloud instance, arbitrary process

**Tenant container sandbox**:
The capability boundary around a tenant allocation. The workload container
runs without privileges, Linux capabilities, host paths, or devices, and can
use only the versioned interfaces and resources granted by its admitted
contract.
_Avoid_: Virtualized tenant tier, WebAssembly sandbox, unrestricted process

**Project Queue trigger**:
A project-scoped event contract that invokes a tenant workload from a
platform-owned durable queue without giving the workload NATS credentials.
_Avoid_: Raw NATS subscription, customer JetStream consumer

**Stateless service**:
A continuously addressable tenant workload whose allocations keep no durable local state and can be replaced without data recovery.
_Avoid_: Persistent service, stateful container

**Managed TerraBase**:
A trusted stateful container service for tenant applications. The platform
owns its topology, storage, backup, and recovery lifecycle.
_Avoid_: Tenant volume, general stateful workload

**Qualified release digest**:
An immutable artifact identity that has passed the required release checks and may be activated or restored without rebuilding.
_Avoid_: Latest image, rebuilt release

**Regional blue-green deployment**:
A production release that builds a complete candidate generation beside the
unchanged active generation in one Region, qualifies it through real
dependencies and required tests, then switches traffic with one durable routing
generation. Candidate failure removes only the candidate.
_Avoid_: In-place upgrade, shallow health-check rollout, all-Region activation

**Global activation barrier**:
Historical release term superseded by independent regional blue-green
deployment. SFO, FRA, GRU, and later Regions qualify and cut over in bounded
waves while each Region retains its own rollback generation.
_Avoid_: Current release contract

**Global Master**:
The active replica in the three-replica GRU global Orchestrator group. It owns
global control policy and never names a TerraBase role.
_Avoid_: Database leader, global database primary

**Regional Orchestrator**:
One logical three-replica control group and local JetStream R3 domain for one
canonical Region.
_Avoid_: Single controller process, global authority

**RegionSpec**:
An immutable signed generation of global policy admitted for one Regional
Orchestrator.
_Avoid_: Raw NATS message, Git manifest, provider observation

## Regions

**Launch region**:
A Region available to initial users at launch. The launch Regions are `GRU`
in Sao Paulo, `SFO` in San Jose, and `FRA` in Frankfurt.
_Avoid_: Planned region, supported region

**Planned region**:
A proposed location that users cannot select until TerraScale has deployed and qualified it.
_Avoid_: Available region, supported region

**Qualified region**:
A deployed region that has passed its required runtime, isolation, recovery, monitoring, and load checks and has received owner approval for customer use.
_Avoid_: Running region, documented region
