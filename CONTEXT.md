# TerraScale orchestration

This context defines the language used to place and operate container workloads across geographic locations.

## Runtime control

**TerraScale Orchestrator**:
A general-purpose container orchestration platform that places and operates first-party and tenant workloads across supported infrastructure providers. TerraScale services are its first workloads; Kubernetes API compatibility is not implied.
_Avoid_: TerraScale-only orchestrator, private Kubernetes, Kubernetes-compatible platform

**First-party workload**:
A service operated by TerraScale as part of the platform or a TerraScale product.
_Avoid_: System workload, built-in application

**Tenant workload**:
A containerized service or job submitted by an internal or customer tenant and isolated by that tenant's identity, policy, and resource boundaries.
_Avoid_: Customer container, arbitrary process

**Infrastructure provider**:
A supported supplier of compute, network, and storage capacity. Provider choice must not change the workload's product-level identity or desired behavior.
_Avoid_: Cloud-specific workload, OCI workload

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
