# TerraScale Orchestrator documentation

The workspace [`GOAL.md`](../../GOAL.md) is the architecture and delivery
authority. The repository [`GOAL.md`](../GOAL.md) points back to it.

These documents describe the current system:

| Document | Purpose |
| --- | --- |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Product, data-path, control-plane, and delivery boundaries |
| [`adr/0033-gru-global-authority-and-regional-autonomy.md`](adr/0033-gru-global-authority-and-regional-autonomy.md) | GRU global authority, regional autonomy, and JetStream R3 |
| [`adr/0034-autoforming-cells-and-leaderless-host-convergence.md`](adr/0034-autoforming-cells-and-leaderless-host-convergence.md) | Auto-forming cells, NATS artifact store, leaderless host convergence, operator deploy |
| [`contracts/durable-work-inventory.md`](contracts/durable-work-inventory.md) | Durable `ts.orch.v2` streams and consumers |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | NATS capabilities admitted by the control plane |
| [`contracts/controller-membership.md`](contracts/controller-membership.md) | Regional controller membership and the global cell directory |
| [`contracts/deploy-orchestrator-handoff.md`](contracts/deploy-orchestrator-handoff.md) | Lean candidate handoff and authority separation |
| [`runbooks/nats-gateway-operations.md`](runbooks/nats-gateway-operations.md) | Gateway rotation and failure handling |
| [`runbooks/nats-monitoring.md`](runbooks/nats-monitoring.md) | NATS alert interpretation and remediation |
| [`operations/control-bootstrap.md`](operations/control-bootstrap.md) | OCI first boot and seed ownership handoff contract |
| [`operations/oci-vault-bootstrap.md`](operations/oci-vault-bootstrap.md) | Pinned Instance Principal credential delivery and identity boundaries |
| [`operations/oci-founding-peers.md`](operations/oci-founding-peers.md) | Offline signing and bounded creation of the first two GRU peers |
| [`operations/oci-member-readiness.md`](operations/oci-member-readiness.md) | Enrollment readiness, service health, and remaining storage/drain contracts |
| [`evidence/oci-readiness-2026-09-20.md`](evidence/oci-readiness-2026-09-20.md) | Local verification evidence and remaining deployment gates |

Deleted documents remain available through Git history when an old decision
must be inspected.
