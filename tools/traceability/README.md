# Draft lexical traceability

`generate_traceability.py` deterministically maps canonical registry IDs to exact
C# production and test locations. The generated report is a gap inventory only: it
sets `claimsAcceptanceEvidence` to false, preserves registry evidence state, and
does not imply that a lexical reference proves behavior or an acceptance layer.

Generate and verify:

```text
python3 tools/traceability/generate_traceability.py
python3 tools/traceability/generate_traceability.py --check
python3 -m unittest tools/traceability/test_generate_traceability.py
```

References to IDs absent from `requirements/registry.yaml` fail generation. A later
evidence tranche must replace lexical links with structured code/test/evidence
manifests before the registry can freeze.
