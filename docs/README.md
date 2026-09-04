# TerraScale Orchestrator documentation

The workspace [`GOAL.md`](../../GOAL.md) is the product authority. The
repository [`GOAL.md`](../GOAL.md) applies those decisions to this Go control
plane. The living documentation below follows the same boundary: the
orchestrator reconciles OCI and Cloudflare, operates signed binaries under
systemd, and never carries customer data or serves the customer request path.

## Start here

| Document | Purpose |
| --- | --- |
| [`../README.md`](../README.md) | Repository purpose, runtime boundary, and validation commands |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Current control-plane, provider, delivery, and data-path boundaries |
| [`guides/production-readiness.md`](guides/production-readiness.md) | Code findings, refactoring sequence, missing inputs, and qualification evidence |
| [`guides/automated-bootstrap.md`](guides/automated-bootstrap.md) | Declarative OCI and Cloudflare bootstrap |
| [`guides/running-locally.md`](guides/running-locally.md) | D-81 Firecracker qualification on real systemd guests |
| [`adr/0020-provider-actuator-threat-model.md`](adr/0020-provider-actuator-threat-model.md) | Provider mutation fencing and same-operation recovery |
| [`adr/0024-greenfield-bringup.md`](adr/0024-greenfield-bringup.md) | Greenfield bootstrap and residual-resource quarantine |
| [`adr/0025-rollback-on-customer-gate-failure.md`](adr/0025-rollback-on-customer-gate-failure.md) | Release rollback safety boundary |
| [`contracts/controller-membership.md`](contracts/controller-membership.md) | Controller identity, membership, and directory contracts |
| [`contracts/durable-work-inventory.md`](contracts/durable-work-inventory.md) | Durable `ts.orch.v2` control streams and consumers |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | NATS capabilities admitted by the control plane |
| [`contracts/nats-monitoring-snapshot.md`](contracts/nats-monitoring-snapshot.md) | Bounded monitoring instruments and fail-closed observation |
| [`runbooks/nats-monitoring.md`](runbooks/nats-monitoring.md) | NATS alert interpretation and remediation |

Retired architecture and decision records are deleted; they are not current
design inputs.
