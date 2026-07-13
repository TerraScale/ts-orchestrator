# ADR readiness index

This directory records Phase 0 decision readiness without accepting any architecture decision. The architecture remains proposed and the owner questions and measurable cost, storage, RPO, and RTO targets remain open.

`readiness-index.yaml` is JSON-compatible YAML so it can be checked with the Python standard library. It is the canonical Phase 0 map of the 24 items in `ORCHESTRATOR.md`'s initial ADR backlog.

## Status rules

- `draft-ready`: the proposed contract and checked-in evidence are sufficient to write a choice-preserving draft. It does not mean accepted.
- `owner-input-required`: a numbered owner choice or owner-approved SLO can materially change the decision. A draft may compare alternatives but cannot select one.
- `evidence-required`: the decision is not controlled by an open owner choice, but a measurement, inventory, threat-model result, product-contract reconciliation, or primary implementation source is still missing.
- `accepted`: requires an explicit owner/architecture approval record plus every exit-evidence item. Phase 0 has no accepted ADRs.

Only these canonical owner lanes from `ORCHESTRATOR.md`'s exclusive-workstream table are valid: `integration`, `core`, `messaging-security`, `runtime`, `cloud`, `storage`, `terrabase`, `delivery`, `operations`, `cross-repository-cleanup`, and `verification`.

Run `python3 docs/adr/validate_readiness.py` after any update. The validator proves IDs 1 through 24 occur exactly once, fields are populated, lanes and statuses are canonical, `accepted` is absent while owner inputs remain open, and every `draft-ready` record cites local or primary-source evidence.
