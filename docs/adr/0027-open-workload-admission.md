# Open workload admission beyond TerraScale services

Status: superseded by [ADR 0030](0030-run-customer-workloads-as-wasi-components.md)

TerraScale Orchestrator will become a general-purpose container orchestration platform. It will continue to operate TerraScale's first-party workloads and will add policy-governed admission for arbitrary internal workloads, followed by customer tenant workloads. OCI remains the first infrastructure provider behind provider-neutral contracts. Kubernetes APIs and workload compatibility are not part of this decision.

This supersedes the TerraScale-only workload boundary in `ORCHESTRATOR.md`, the closed role-catalog assumption, and `REQ-O004` where it forbids arbitrary workloads. The architecture review must replace those rules without weakening the separate private control plane, tenant isolation, secret handling, resource ownership, or production evidence gates.

## Consequences

- First-party infrastructure roles retain narrow, privileged descriptors. Tenant workloads cannot request control-plane identities, provider credentials, host paths, privileged execution, or private TerraScale operations merely by supplying an image.
- Workload intent and lifecycle contracts remain provider-neutral. Provider adapters translate approved operations into OCI first and into other providers later.
- The scheduler, runtime, networking, storage, identity, GitOps, observability, API, quotas, and billing models must acquire explicit tenant boundaries before customer self-service opens.
- The existing architecture remains the safety baseline while the design interview and ticket map define the replacement contracts and migration sequence.
