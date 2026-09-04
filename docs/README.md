# TerraScale.Orchestrator documentation

The repository [`GOAL.md`](../GOAL.md) is the current Orchestrator architecture
and release contract. The workspace [`GOAL.md`](../../GOAL.md) controls
cross-repository product decisions. The repository goal cannot weaken it.
`architecture/orchestrator.md` and the old topology ADRs are superseded records
retained for historical machine-validated evidence. They cannot select the
current control topology, delivery strategy, or local test backend.

## Start here

| Document | Purpose |
| --- | --- |
| [`../GOAL.md`](../GOAL.md) | Current repository contract, including the required Firecracker qualification stack |
| [`../../GOAL.md`](../../GOAL.md) | Sole product authority and cross-repository decisions, including D-81 |
| [`guides/running-locally.md`](guides/running-locally.md) | Required Firecracker host, guest, topology, fault, command, and cleanup contracts |
| [`adr/0033-gru-global-authority-and-regional-autonomy.md`](adr/0033-gru-global-authority-and-regional-autonomy.md) | Superseded control-topology and delivery record |
| [`architecture/orchestrator.md`](architecture/orchestrator.md) | Superseded architecture record |
| [`../README.md`](../README.md) | Repository purpose, current implementation gap, validation, and current adapter commands |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Short current architecture and test-boundary summary |
| [`runbooks/direct-delivery.md`](runbooks/direct-delivery.md) | Current direct-delivery failure procedures |
| [`adr/`](adr/) | Architecture records with explicit current or superseded status |
| [`decisions/`](decisions/) | Machine-validated 2026-07 owner decision packet, superseded where it conflicts with the current goal |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | Current `ts.orch.v2` adapter contract; never a database dependency |

Do not rewrite evidence to make it appear current. Add a correction or
supersession notice and preserve what the old run actually proved.

## Machine-validated artifacts

Repository tooling consumes these files:

```text
docs/adr/readiness-index.yaml
docs/decisions/owner-decision-packet.json
```

They record the earlier architecture and must not be used as current product
authority. Their validators still protect the integrity of that historical
record.

```bash
go run ./tools/orchestrator-tooling adr-readiness
go run ./tools/orchestrator-tooling owner-decisions
go run ./tools/orchestrator-tooling test
```
