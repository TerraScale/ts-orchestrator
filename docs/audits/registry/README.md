# Phase 0 semantic registry coverage audit

The draft registry is not ready to serve as the Phase 1 traceability contract.

The audit found 43 registered IDs: all 23 owner requirements, all 18 numbered invariants, one error, and one security rule. All 43 are classified `id-only`, not semantically complete, because the canonical entries carry no normative statement, source anchor, implementation intent, or evidence target. Five entries also use owner names outside the ten exclusive lanes defined by `ORCHESTRATOR.md`.

The machine-readable audit proposes 43 missing IDs grouped as:

- 8 explicit arrow-defined state machines;
- 10 externally meaningful rejects/holds;
- 8 independently testable security rules;
- 17 gate families covering the hard pre-deployment gate, evidence floors, layer authority, performance/correctness, Phase 0–9 exits, and the three production acceptance sections.

The gate-family IDs are deliberately umbrella findings for steward review. Before contract freeze, each bullet or threshold that can fail independently should receive its own stable evidence target beneath the applicable family. Treating an entire production section as one test would repeat the semantic under-specification this audit identifies.

## Deterministic verification

Run from the repository root:

```bash
python3 docs/audits/registry/check_registry_audit.py \
  --negative-fixtures docs/audits/registry/fixtures/negative-cases.json
```

The checker uses only the Python standard library. It validates seeded-ID presence, proposed-ID uniqueness, the canonical owner/layer vocabularies, exact line bounds and citation text against `ORCHESTRATOR.md`, summary counts, and six negative fixtures. The fixtures prove detection of duplicate proposed IDs, a missing registered ID, a noncanonical owner, an invalid layer, a stale citation, and a duplicated finding.

## Steward actions

1. Extend the canonical schema so an entry cannot omit its normative statement/source anchor and intended evidence.
2. Add the proposed SM/ERR/SEC/gate IDs after reviewing naming and the per-assertion gate split.
3. Normalize `REQ-O011`, `REQ-O015`, `INV-002`, `INV-004`, and `INV-005` to canonical owner lanes; use co-review metadata where one primary owner is insufficient.
4. Keep contract status draft while questions 1–10 and cost, storage, RPO, and RTO targets remain unresolved.
5. Make the checker (or its steward-integrated successor) a Phase 0 CI input before generating code/test/evidence traceability.
