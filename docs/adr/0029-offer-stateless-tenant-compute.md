# Offer stateless tenant compute with managed TerraBase

The tenant workload product admits stateless services and serverless compute. It does not expose general persistent volumes or arbitrary stateful services. Tenant applications use managed TerraBase for first-party durable state or explicitly reach an external service through allowed egress. Ephemeral scratch space may exist, but losing an allocation must not require data recovery.

TerraBase remains a privileged first-party workload with a specialized controller for stable member identity, block storage, topology, replication, backup, restore, upgrade, expansion, and recovery. Making TerraBase easy to provision and consume is part of the platform product, not a reason to expose its storage machinery as a generic tenant workload feature.

## Consequences

- The public workload API has no tenant volume claim, stateful-set, arbitrary mount, or durable-local-disk contract.
- Scheduling and autoscaling may replace tenant allocations freely after drain and request-routing gates pass.
- TerraBase provisioning, credentials, endpoints, region selection, readiness, backup policy, and recovery status need a simple tenant-facing contract over the specialized internal lifecycle.
- The exact serverless invocation and scaling contract remains a separate product decision.
