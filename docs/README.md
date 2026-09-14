# TerraScale Orchestrator documentation

The workspace [`GOAL.md`](../../GOAL.md) is the architecture and delivery
authority. The repository [`GOAL.md`](../GOAL.md) points back to it.

These documents describe the current system:

| Document | Purpose |
| --- | --- |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Product, data-path, control-plane, and delivery boundaries |
| [`adr/0033-gru-global-authority-and-regional-autonomy.md`](adr/0033-gru-global-authority-and-regional-autonomy.md) | GRU global authority, regional autonomy, and JetStream R3 |
| [`architecture/podman-rootless-hosting-and-autoscaling.md`](architecture/podman-rootless-hosting-and-autoscaling.md) | Rootless Podman hosting, stateful drain safety, and autoscaling |
| [`guides/running-locally.md`](guides/running-locally.md) | Local host-agent and autoscaler operation |
| [`contracts/durable-work-inventory.md`](contracts/durable-work-inventory.md) | Durable `ts.orch.v2` streams and consumers |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | NATS capabilities admitted by the control plane |
| [`contracts/controller-membership.md`](contracts/controller-membership.md) | Regional controller membership and the global cell directory |
| [`contracts/deploy-orchestrator-handoff.md`](contracts/deploy-orchestrator-handoff.md) | Lean candidate handoff and authority separation |
| [`runbooks/nats-gateway-operations.md`](runbooks/nats-gateway-operations.md) | Gateway rotation and failure handling |
| [`runbooks/nats-monitoring.md`](runbooks/nats-monitoring.md) | NATS alert interpretation and remediation |

Deleted documents remain available through Git history when an old decision
must be inspected.
