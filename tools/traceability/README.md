# Structured traceability foundation

`validate_traceability.py` validates `requirements/trace-links.yaml`, a strict
JSON-compatible YAML manifest. Every canonical registry ID must occur exactly
once with the registry owner and ordered acceptance layers copied exactly. An
entry is either an explicit `gap` with no links, or `linked` with bounded,
unique production-symbol, test-identifier, and typed evidence links.

Linked paths must be canonical repository-relative regular files. Traversal,
absolute paths, symbolic links, missing files, ambiguous identifiers, comment-
or string-only C# occurrences, evidence kind/layer substitutions, partial link
sets, unknown fields, and acceptance claims fail closed. The canonical report
always has `claimsAcceptanceEvidence: false` and `acceptanceSatisfied: 0` in
this tranche; structured links are trace associations, not acceptance proof.
Report generation/checking is confined to one regular JSON file directly below
`docs/audits/traceability`; existing symlinked parents or outputs are rejected.

Generate and verify the structured report:

```text
python3 tools/traceability/validate_traceability.py
python3 tools/traceability/validate_traceability.py --check
python3 -m unittest tools/traceability/test_validate_traceability.py
```

`generate_traceability.py` remains available solely as a lexical gap-discovery
aid. Its `linked`, `test-only`, and similar labels describe text occurrence and
must never promote a structured entry or acceptance state:

```text
python3 tools/traceability/generate_traceability.py
python3 tools/traceability/generate_traceability.py --check
python3 -m unittest tools/traceability/test_generate_traceability.py
```

The checked manifest intentionally begins with all 43 entries as first-class
gaps. Existing comments and requirement-ID strings were not converted into
links because they do not establish a complete typed production/test/evidence
chain.
