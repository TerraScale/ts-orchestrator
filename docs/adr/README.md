# ADR readiness index

This directory records architecture decision readiness for the 24-item backlog in `docs/architecture/orchestrator.md`.

Owner choices **1A–10A were accepted on 2026-07-16** with reliability first. Measurable cost, storage, RPO, and RTO targets remain deployment-qualification inputs rather than silent architecture defaults.

`readiness-index.yaml` is JSON-compatible YAML validated by the dependency-free C# tooling executable. It is the canonical Phase 0/1 map of backlog items 1–24.

## Draft ADRs in this directory

| ADR | Title | Status |
|---|---|---|
| [0004](0004-pulumi-provider-ownership.md) | Pulumi and regional provider ownership | Proposed / draft-ready |
| [0013](0013-native-gitops.md) | Native GitOps and complete Flux removal | Proposed / draft-ready |
| [0018](0018-placement-boundary.md) | Project placement versus host scheduling | Proposed / draft-ready |
| [0020](0020-provider-actuator-threat-model.md) | Provider actuator crash-stop fencing | Proposed / draft-ready |

Condensed boundaries for these decisions: [`../guides/architecture-boundaries.md`](../guides/architecture-boundaries.md).

## Status rules

- `draft-ready`: the proposed contract and checked-in evidence are sufficient to write a choice-preserving draft. It does not mean accepted.
- `owner-input-required`: a numbered owner choice **or** an owner-approved SLO can still materially change the decision. A draft may compare alternatives but cannot select one.
- `evidence-required`: the decision is not controlled by an open numbered owner choice, but a measurement, inventory, threat-model result, product-contract reconciliation, or primary implementation source is still missing.
- `accepted`: requires an explicit owner/architecture approval record plus every exit-evidence item. No ADR is accepted solely because questions 1–10 closed.

Only the exact canonical owner lane names from `docs/architecture/orchestrator.md`'s exclusive-workstream table are valid: `Integration/contract steward`, `Core`, `Messaging/security`, `Runtime`, `Cloud`, `Storage`, `TerraBase`, `Delivery`, `Operations`, `Cross-repository cleanup`, and `Verification`.

## Validation

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

The validator proves IDs 1 through 24 occur exactly once, fields are populated, lanes and statuses are canonical, and every local evidence anchor resolves to an existing file with in-bounds line numbers.
