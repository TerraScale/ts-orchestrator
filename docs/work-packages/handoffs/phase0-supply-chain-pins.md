# Phase 0 supply-chain candidate-pin handoff

- Branch: `docs/phase0-supply-chain-pins`
- Work package: `docs/work-packages/phase0-supply-chain-pins.md`
- Scope changed: supply-chain audit, candidate manifest, lane-owned validator/tests/fixtures, and this handoff only
- External mutation: none
- Candidate download/install/restore/import/execution: none
- Signing or attestation selection: none

## Result

Created a fail-closed candidate evidence set for build, runtime, property, coverage, fuzz, mutation, signing, OCI artifact, SBOM, and vulnerability tooling:

- `docs/audits/supply-chain/phase0-candidate-pins.md`
- `testlab/pins/supply-chain-candidates.json`
- `tools/phase0/supply-chain/validate_supply_chain_pins.py`
- `tools/phase0/supply-chain/test_validate_supply_chain_pins.py`
- `tools/phase0/supply-chain/fixtures/negative-cases.json`
- `tools/phase0/supply-chain/README.md`

The manifest records 13 version-specific official candidates/alternatives and 6 unresolved capability gaps. Every candidate is unselected, unmirrored, locally unexecuted, and not production-qualified. Artifact signing, evidence signing, and attestation tool selections remain explicitly `null`; Cosign and Notation remain peer candidates.

Following review, the manifest also binds the existing checked-in baseline: SDK `10.0.301` with `latestFeature` roll-forward, TUnit `1.56.18`, transitive Microsoft.Testing.Platform `2.2.3`, their lock content hashes, and SHA-256 provenance for every checked-in lock file. It explicitly records that `latestFeature` permits a higher installed feature band, so the SDK is not an exact closure pending a steward decision. No central package/build file was edited.

Current technical/version claims use only owning-project GitHub release pages or official NuGet package pages. Trivy is a reviewed alternative rather than a recommendation because the owning project published an official March 2026 supply-chain advisory; the audit does not claim its later candidate version is compromised.

## Deterministic validation

Commands:

```text
python3 -m json.tool testlab/pins/supply-chain-candidates.json
python3 tools/phase0/supply-chain/validate_supply_chain_pins.py
python3 -m unittest discover -s tools/phase0/supply-chain -p 'test_*.py' -v
git diff --check
```

The standard-library validator checks exact schema keys, stable/unique IDs, category completeness, version-specific HTTPS sources on official hosts, version/source agreement, license/platform/integrity metadata, Linux x64/ARM64 availability for binary distributions, missing mirrors, explicit qualification gaps, and fail-closed null selections. It also compares the baseline record to `global.json`, the central TUnit declaration, test lock resolutions/content hashes, and the complete recomputed lock-file SHA-256 set. The data-driven adversarial corpus covers 21 negative cases, including floating/wrong versions, false qualification/mirror claims, missing ARM64, erased gaps, duplicate IDs, secret-bearing fields, signing-selection collapse, SDK/package drift, false SDK closure, and lock provenance drift.

## Remaining gates

- The integration steward must decide whether to replace `latestFeature` with exact SDK closure semantics; this lane only records and validates the current checked-in baseline.
- New central package/build-file pins must be made later by the integration steward after selections; this lane changed none.
- Model/state-space plus systematic-concurrency tooling remains unselected pending a .NET 10 deterministic replay spike.
- Secret scanning, license-policy evaluation, and exact NuGet dependency/advisory/lock enforcement remain open.
- Artifact/evidence signing format, tool, identity, KMS/isolated-CI custody, trust roots, offline verification, revocation, and recovery require the future owner-approved ADR.
- Every selected package/binary/plugin/scanner database needs exact digests, upstream verification receipts, a content-addressed internal mirror, TerraScale signatures, and compromise/rollback drills.
- Candidate compatibility and deterministic output need L0; containerd/runc need L1R and ARM64 L4; BuildKit needs isolated worker/cache/credential evidence; signing/OCI tools need Forgejo/OCIR conformance.

No candidate presence, upstream release, schema-valid record, or green validator is production qualification or permission to issue deployment credentials.
