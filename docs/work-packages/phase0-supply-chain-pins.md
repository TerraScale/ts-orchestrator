# Phase 0 work package: supply-chain and verification tool pins

- Scope: evidence-backed candidate pins and gaps for build, test, signing, attestation, SBOM, scanning, and OCI image tooling.
- Allowed paths: `docs/audits/supply-chain/**`, `testlab/pins/supply-chain-*.json`, lane-owned validation scripts/tests under `tools/phase0/supply-chain/**`, and a handoff under `docs/work-packages/handoffs/**`.
- Prohibited paths: central build/package files, canonical registry, ADR readiness index, `ORCHESTRATOR.md`, production code, sibling repositories, credentials, and external mutation.
- Deliverable: distinguish locally observed tools from reviewed candidate pins; use primary-source provenance for every proposed version; record architecture/platform support, integrity/provenance status, mirror/signing requirements, license, and the exact evidence still needed before selection. Artifact/evidence signing remains unset.
- Verification: deterministic schema/fixture validation, negative cases, exact citations, and no claim that tool presence or a proposed version qualifies production.

