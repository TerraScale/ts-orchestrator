# ADR readiness index

This directory records Phase 0 decision readiness. Owner choices 1A–10A were accepted on 2026-07-16 with reliability first; measurable cost, storage, RPO, and RTO targets remain deployment-qualification inputs rather than blockers for pure contract work.

`readiness-index.yaml` is JSON-compatible YAML validated by the dependency-free C# tooling executable. It is the canonical Phase 0 map of the 24 items in `ORCHESTRATOR.md`'s initial ADR backlog.

## Status rules

- `draft-ready`: the proposed contract and checked-in evidence are sufficient to write a choice-preserving draft. It does not mean accepted.
- `owner-input-required`: a numbered owner choice or owner-approved SLO can materially change the decision. A draft may compare alternatives but cannot select one.
- `evidence-required`: the decision is not controlled by an open owner choice, but a measurement, inventory, threat-model result, product-contract reconciliation, or primary implementation source is still missing.
- `accepted`: requires an explicit owner/architecture approval record plus every exit-evidence item. Phase 0 has no accepted ADRs.

Only the exact canonical owner lane names from `ORCHESTRATOR.md`'s exclusive-workstream table are valid: `Integration/contract steward`, `Core`, `Messaging/security`, `Runtime`, `Cloud`, `Storage`, `TerraBase`, `Delivery`, `Operations`, `Cross-repository cleanup`, and `Verification`.

Run `dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness` and `dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test` after any update. The validator proves IDs 1 through 24 occur exactly once, fields are populated, lanes and statuses are canonical, `accepted` is absent while owner inputs remain open, every local evidence anchor resolves to nonblank in-bounds lines, and every `draft-ready` record has both a precise specification anchor and a checked-in audit/ledger anchor.
