# TerraScale.Orchestrator documentation

The repository [`GOAL.md`](../GOAL.md) is the current Orchestrator architecture
and release contract. The workspace [`GOAL.md`](../../GOAL.md) controls
cross-repository product decisions. The repository goal cannot weaken it.
Git history retains the superseded architecture and phase records.

## Start here

| Document | Purpose |
| --- | --- |
| [`../GOAL.md`](../GOAL.md) | Current authority, topology, NATS, OCI, scheduling, delivery, failure, and GA contract |
| [`adr/0033-gru-global-authority-and-regional-autonomy.md`](adr/0033-gru-global-authority-and-regional-autonomy.md) | Accepted authority, regional autonomy, blue-green cutover, and production artifact boundary |
| [`../README.md`](../README.md) | Repository purpose, current implementation gap, validation, and current adapter commands |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Short current architecture summary |
| [`adr/`](adr/) | Architecture records with explicit current or superseded status |

## Current implementation records

These contracts describe the checked-in v2 control plane:

| Document | Scope |
| --- | --- |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | Frozen `ts.orch.v2` adapter contract; never a database dependency |
| [`contracts/nats-monitoring-snapshot.md`](contracts/nats-monitoring-snapshot.md) | Current monitoring instruments, alerts, and fail-closed observation behavior |

Deleted architecture and evidence packets remain available through Git history.
