# Phase 0 work package: provider/TCO and OCI region qualification schema

- Scope: fail-closed data contracts and current primary-source evidence map for the normalized provider TCO/storage benchmark and >=20-row OCI eligibility requirement.
- Allowed paths: `docs/audits/provider/**`, `tools/phase0/provider-qualification/**`, `testlab/pins/provider-*.json`, and a lane handoff.
- Prohibited paths: cloud login/calls, price or region qualification without complete evidence, owner cost/SLO selection, canonical registry, shared build files, and production code.
- Deliverable: schema/blank dataset that requires every cost and regional qualification field named by ORCHESTRATOR.md; current official source catalog for OCI/AWS/GCP/Azure; deterministic validator/adversarial fixtures that reject partial rows, stale evidence, currency/unit ambiguity, false >=20 claims, or a cheapest-provider claim without normalized results.
- Verification: official primary sources only; no credentialed API or resource mutation; all unknown values remain null/not-qualified.

