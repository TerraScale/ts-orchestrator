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
A stateless service or serverless handler submitted as an unprivileged,
digest-pinned OCI container and bound to an admitted TerraScale interface set.
_Avoid_: Arbitrary container, customer image, Docker workload

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

**Global activation barrier**:
The release checkpoint that switches every region from the active qualified digest to a prepared qualified candidate only after all regions pass.
_Avoid_: Rolling deployment, simultaneous in-place replacement

## Regions

**Launch region**:
A region available to initial users at launch. The launch regions are Sao Paulo, San Francisco, and Falkenstein.
_Avoid_: Planned region, supported region

**Planned region**:
A proposed location that users cannot select until TerraScale has deployed and qualified it.
_Avoid_: Available region, supported region

**Qualified region**:
A deployed region that has passed its required runtime, isolation, recovery, monitoring, and load checks and has received owner approval for customer use.
_Avoid_: Running region, documented region
