# TerraScale orchestration

This context defines the language used to place and operate TerraScale services across geographic locations.

## Runtime control

**TerraScale Orchestrator**:
The product-specific system that deploys and operates TerraScale services without Kubernetes. It manages TerraScale workloads only and does not offer Kubernetes compatibility or general-purpose workload hosting.
_Avoid_: Kubernetes replacement, private Kubernetes, general-purpose cluster manager

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
