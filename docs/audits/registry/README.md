# Phase 0 semantic registry coverage audit

The draft registry now binds every seeded entry to a normative source range and digest, a canonical owner, and explicit missing evidence targets. It is still not a frozen Phase 1 traceability contract: the proposed state-machine/error/security/gate families require steward review, and all acceptance evidence remains missing.

The audit found 43 registered IDs: all 23 owner requirements, all 18 numbered invariants, one error, and one security rule. All 43 are classified `id-only`, not semantically complete, because the canonical entries carry no normative statement, source anchor, implementation intent, or evidence target. All 43 owner values are aliases rather than the exact 11 exclusive lane names defined by `ORCHESTRATOR.md`; the checked `owner-mapping.json` makes their intended normalization explicit and leaves zero aliases unmapped.

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

The checker uses only the Python standard library. It parses both inline and normal block-style registry entries, fails closed on incomplete or skipped list items, validates seeded-ID presence, proposed-ID uniqueness, exact canonical owner names, acceptance layers, normative source ranges/digests, explicit evidence state/targets, exact citations against `ORCHESTRATOR.md`, and summary counts. Ten negative fixtures additionally prove detection of semantic digest drift and a false verified-evidence default.

## Steward actions

1. Preserve the schema-v2 normative statement/source digest and evidence-target checks as entries evolve.
2. Add the proposed SM/ERR/SEC/gate IDs after reviewing naming and the per-assertion gate split.
3. Review co-review metadata for cross-lane entries, especially the former `control-plane`, `cloud-storage`, and `delivery-security` aliases.
4. Keep contract status draft while questions 1–10 and cost, storage, RPO, and RTO targets remain unresolved.
5. Make the checker (or its steward-integrated successor) a Phase 0 CI input before generating code/test/evidence traceability.
