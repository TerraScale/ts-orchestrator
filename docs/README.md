# TerraScale.Orchestrator documentation

The repository [`GOAL.md`](../GOAL.md) is the current Orchestrator architecture
and release contract. The workspace [`GOAL.md`](../../GOAL.md) controls
cross-repository product decisions. The repository goal cannot weaken it.
`architecture/orchestrator.md` is a superseded record retained for historical
machine-validated evidence; its development-topology sections were removed on
2026-08-29 by the GOAL P0 repository-purity sweep.

## Start here

| Document | Purpose |
| --- | --- |
| [`../GOAL.md`](../GOAL.md) | Current authority, topology, NATS, OCI, scheduling, delivery, failure, and GA contract |
| [`adr/0033-gru-global-authority-and-regional-autonomy.md`](adr/0033-gru-global-authority-and-regional-autonomy.md) | Accepted authority, regional autonomy, blue-green cutover, and production artifact boundary |
| [`architecture/orchestrator.md`](architecture/orchestrator.md) | Superseded architecture record |
| [`../README.md`](../README.md) | Repository purpose, current implementation gap, validation, and current adapter commands |
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Short current architecture summary |
| [`runbooks/direct-delivery.md`](runbooks/direct-delivery.md) | Current direct-delivery failure procedures |
| [`adr/`](adr/) | Architecture records with explicit current or superseded status |
| [`archive/`](archive/) | Compressed full-fidelity historical material |

## Current implementation records

The following documents remain useful for understanding checked-in code. They
are not the target product architecture:

| Document | Scope |
| --- | --- |
| [`guides/phase0-evidence.md`](guides/phase0-evidence.md) | Historical Phase 0 evidence and gaps |
| [`guides/phase1-contracts.md`](guides/phase1-contracts.md) | Historical pure-contract inventory |
| [`guides/production-readiness-audit-2026-08-04.md`](guides/production-readiness-audit-2026-08-04.md) | Dated audit of the old architecture |
| [`guides/public-alpha-release.md`](guides/public-alpha-release.md) | Historical public-alpha decision coverage |
| [`guides/public-alpha-program-map.md`](guides/public-alpha-program-map.md) | Historical cross-repository issue map |
| [`guides/work-stream-catalog.md`](guides/work-stream-catalog.md) | Historical work-package index |
| [`decisions/`](decisions/) | Machine-validated 2026-07 owner decision packet, superseded where it conflicts with the current goal |
| [`contracts/nats-capability-matrix.md`](contracts/nats-capability-matrix.md) | Frozen v1 adapter contract, superseded for the v2 target and never a database dependency |

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
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- owner-decisions
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

## Archives

The compressed archive preserves older audits, handoffs, fixtures, pins, and
work packages.

```bash
tar -tJf docs/archive/docs-historical-full.tar.xz | head
tar -xJf docs/archive/docs-historical-full.tar.xz -C /tmp/orch-docs-historical
```

Archive content is evidence, not active instruction.
