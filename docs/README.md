# TerraScale Orchestrator documentation

The workspace [`GOAL.md`](../../GOAL.md) defines product scope, repository responsibilities,
and release gates. The living documentation below follows the same boundary: the
orchestrator reconciles OCI and Cloudflare, operates signed binaries under
systemd, and never carries customer data or serves the customer request path.

## Start here

| Document | Purpose |
| --- | --- |
| [`../README.md`](../README.md) | Repository purpose, runtime boundary, and validation commands |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Current control-plane, provider, delivery, and data-path boundaries |
| [`guides/production-readiness.md`](guides/production-readiness.md) | Historical implementation findings, missing inputs, and qualification evidence; not a current source map |
| [`guides/automated-bootstrap.md`](guides/automated-bootstrap.md) | Declarative OCI and Cloudflare bootstrap |
| [`guides/running-locally.md`](guides/running-locally.md) | Historical D-81 Firecracker qualification design and retained command evidence |
| [`guides/qualification-status.md`](guides/qualification-status.md) | Historical qualification record and dated blockers |
| [`guides/terrabase-vm-configuration.md`](guides/terrabase-vm-configuration.md) | Historical TerraBase declaration and guest configuration contract |
| [`adr/0020-provider-actuator-threat-model.md`](adr/0020-provider-actuator-threat-model.md) | Provider mutation fencing and same-operation recovery |
| [`adr/0024-greenfield-bringup.md`](adr/0024-greenfield-bringup.md) | Greenfield bootstrap and residual-resource quarantine |
| [`adr/0025-rollback-on-customer-gate-failure.md`](adr/0025-rollback-on-customer-gate-failure.md) | Release rollback safety boundary |
| [`contracts/controller-membership.md`](contracts/controller-membership.md) | Controller identity, membership, and directory contracts |
| [`contracts/durable-work-inventory.md`](contracts/durable-work-inventory.md) | Durable `ts.orch.v1` control streams and consumers |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | NATS capabilities admitted by the control plane |
| [`contracts/nats-monitoring-snapshot.md`](contracts/nats-monitoring-snapshot.md) | Bounded monitoring instruments and fail-closed observation |
| [`runbooks/nats-monitoring.md`](runbooks/nats-monitoring.md) | NATS alert interpretation and remediation |

Retired architecture and decision records are not current design inputs.
Historical ADRs and dated evidence remain available until their retention or
deletion is explicitly decided.

The current executable and command surface are documented in the repository
[README](../README.md) and [design map](../DESIGN.md). The readiness,
qualification-status, running-locally, and TerraBase VM guides retain findings
from the pre-C# implementation and its Firecracker qualification work. Their
Go and Make command examples are historical evidence, not instructions for the
current .NET runtime.
