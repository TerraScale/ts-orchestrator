# Isolate tenant workloads with microVMs

Every tenant allocation runs inside a microVM with a dedicated guest kernel. The admitted OCI artifact remains the workload package, while the microVM is the security boundary between customer code, other tenants, and the host. Shared-kernel hardening alone is not sufficient for tenant isolation. Trusted first-party infrastructure may continue to use separately admitted native or container runtimes.

The exact microVM technology remains open until ARM64, OCI host support, boot latency, density, snapshot, networking, observability, and escape-resistance evidence is available. The scheduler and capacity model must account for microVM overhead instead of hiding it as host reserve.

## Consequences

- Tenant workloads receive no host paths, host network namespace, host devices, provider credentials, control-plane identities, or privileged execution.
- The runtime needs crash-safe microVM creation, identity, networking, image staging, health, shutdown, cleanup, and orphan reconciliation.
- Public launch requires adversarial isolation and resource-exhaustion tests against the selected runtime on the real production architecture.
