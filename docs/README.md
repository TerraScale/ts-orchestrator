# TerraScale.Orchestrator documentation

Living documentation for the production control plane. Normative architecture is still **[`ORCHESTRATOR.md`](../ORCHESTRATOR.md)** at the repository root. This tree is the navigable, consolidated view of Phase 0 evidence, Phase 1 pure contracts, ADRs, and owner decisions.

Owner choices **1A–10A** are accepted (reliability first). Measurable cost, storage, RPO, and RTO targets remain deployment-qualification inputs.

## Start here

| Document | Purpose |
|---|---|
| [`guides/architecture-boundaries.md`](guides/architecture-boundaries.md) | Condensed invariants, control-plane shape, ADR boundaries, mTLS |
| [`guides/phase0-evidence.md`](guides/phase0-evidence.md) | Consolidated Phase 0 readiness, pins posture, honest gaps |
| [`guides/phase1-contracts.md`](guides/phase1-contracts.md) | Domain-by-domain pure-contract map + live source inventory |
| [`guides/production-readiness-audit-2026-08-04.md`](guides/production-readiness-audit-2026-08-04.md) | Evidence-backed current implementation audit and production-adapter gap map |
| [`guides/public-alpha-release.md`](guides/public-alpha-release.md) | Local Public Alpha decision coverage, qualification blockers, and draft incident runbooks |
| [`guides/public-alpha-program-map.md`](guides/public-alpha-program-map.md) | 52-child cross-repository coverage and Orchestrator responsibility boundary |
| [`guides/work-stream-catalog.md`](guides/work-stream-catalog.md) | Index of every historical work package / handoff |
| [`runbooks/direct-delivery.md`](runbooks/direct-delivery.md) | Operator procedures for direct-delivery failures: mutation, rollback, stale evidence, journal outage, stuck reconciliation |
| [`decisions/`](decisions/) | Machine-validated owner decision packet |
| [`adr/`](adr/) | ADR readiness index + draft ADRs 0004, 0013, 0018, 0020 |
| [`archive/`](archive/) | Compressed full-fidelity historical docs |

## Machine-validated artifacts

These paths are required by repository tooling and must stay valid:

```text
docs/adr/readiness-index.yaml
docs/decisions/owner-decision-packet.json
```

Validate:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- owner-decisions
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

## What moved into archives

Phase 0 sprawl (per-lane work packages, handoffs, audit markdown/JSON, retirement ledger, phase0 tools/pins) was **consolidated** on 2026-07-17:

- Substance is rewritten into the guides above with current owner-decision and live-source context.
- Exact original trees are preserved as compressed archives under [`archive/`](archive/) (tar.xz + a searchable markdown bundle).
- Empty `docs/work-packages/**`, `docs/audits/**`, and `docs/retirement/**` are no longer the live navigation surface.

Unpack an archive when you need a verbatim historical path (for example an old handoff SHA or audit JSON fixture):

```bash
tar -tJf docs/archive/docs-historical-full.tar.xz | head
tar -xJf docs/archive/docs-historical-full.tar.xz -C /tmp/orch-docs-historical
```

## Related repository docs

| Path | Role |
|---|---|
| [`../ORCHESTRATOR.md`](../ORCHESTRATOR.md) | Full architecture and implementation plan |
| [`../README.md`](../README.md) | Operator runbook, local validation, Infisical/OTel |
| [`../AGENTS.md`](../AGENTS.md) | Agent safety and ownership rules |

## Documentation layout

```text
docs/
  README.md                 # this index
  guides/                   # consolidated human docs
  adr/                      # readiness index + draft ADRs
  decisions/                # owner decision packet + fixtures
  archive/                  # compressed historical material
```
