# Phase 0 supply-chain candidate pins

- Audit date: 2026-07-13
- Status: candidate review only; no tool or signing technology selected
- Scope: official primary-source review plus checked-in deterministic metadata validation
- Execution: no candidate binary/package was downloaded, installed, restored, imported, or executed

## Outcome

The machine-readable candidate set is [`testlab/pins/supply-chain-candidates.json`](../../../testlab/pins/supply-chain-candidates.json). It records 13 version-specific candidates/alternatives and 6 explicit capability gaps. Every entry remains unselected, requires an internal mirror, and is marked not production-qualified. The manifest deliberately keeps artifact signing, evidence signing, and attestation-tool selections `null`.

The same manifest binds the already checked-in baseline without changing central files: .NET SDK `10.0.301`, `rollForward: latestFeature`, TUnit `1.56.18`, Microsoft.Testing.Platform `2.2.3`, and the SHA-256 of every checked-in NuGet lock file. This is observed repository state, not a new selection or qualification.

This distinction is necessary because the existing host audit observed BuildKit, containerd/runc, cosign, Notation, ORAS, Syft, Trivy, and Grype as absent; local presence would not have qualified them anyway ([local audit, lines 8-29](../toolchain/local-toolchain-audit.md#L8-L29)). The specification requires reproducible signed dual-architecture artifacts with SBOM/provenance ([ORCHESTRATOR.md, lines 351-365](../../../ORCHESTRATOR.md#L351-L365)), a broad deterministic verification stack ([ORCHESTRATOR.md, lines 1139-1150](../../../ORCHESTRATOR.md#L1139-L1150)), and exact-tree evidence signing before deployment credentials ([ORCHESTRATOR.md, lines 1175-1179](../../../ORCHESTRATOR.md#L1175-L1179)). A reviewed upstream version is therefore only an input to later selection and qualification.

## Existing checked-in baseline and closure gap

The baseline evidence comes from the checked-in [`global.json`](../../../global.json), [`Directory.Packages.props`](../../../Directory.Packages.props), and test [`packages.lock.json`](../../../tests/TerraScale.Orchestrator.ContractTests/packages.lock.json). The central package declaration pins TUnit `1.56.18`; the test lock resolves that version with its NuGet content hash and resolves the transitive Microsoft.Testing.Platform dependency to `2.2.3` with its content hash. The manifest also records the exact relative path and SHA-256 for every checked-in `packages.lock.json`, so adding, removing, or changing a lock file fails validation until the evidence is deliberately refreshed.

The SDK is **not an exact closure**. Although `global.json` names `10.0.301`, `rollForward: latestFeature` permits selection of the highest installed feature band and patch within the requested major/minor, as specified by the [official .NET `global.json` documentation](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json). The manifest therefore sets `exactClosure` to `false` and makes the unresolved steward decision explicit. The validator rejects an exact-closure claim while these semantics remain checked in.

## Candidate evidence

All current version claims below point to the owning project's official release page or the official NuGet registry. “Candidate” does not mean “chosen,” “safe,” “mirrored,” or “compatible.”

| Capability | Candidate | Primary version evidence | Integrity/provenance observed upstream | Still required |
|---|---|---|---|---|
| Property testing | FsCheck 3.3.3 | [official NuGet package](https://www.nuget.org/packages/FsCheck/3.3.3) | Registry package metadata only in this audit | TUnit adapter, deterministic seeds/replay, locked content hash, mirror, .NET 10 proof |
| Coverage | Microsoft.CodeCoverage 18.7.0 | [official NuGet package](https://www.nuget.org/packages/Microsoft.CodeCoverage/18.7.0) | Registry package metadata only | Test-platform integration, branch denominator/exclusions, normalized deterministic output, content hash/mirror |
| Fuzzing | SharpFuzz 2.3.0 | [official NuGet package](https://www.nuget.org/packages/SharpFuzz/2.3.0) | Registry package metadata only | Native engine pin, ARM64 instrumentation, bounded corpus/replay, content hash/mirror |
| Mutation | dotnet-stryker 4.16.0 | [official NuGet package](https://www.nuget.org/packages/dotnet-stryker/4.16.0) | Registry package metadata only | TUnit/.NET 10 compatibility, stable denominator, safety-mutant policy, content hash/mirror |
| OCI builds | BuildKit 0.30.0 | [official release](https://github.com/moby/buildkit/releases/tag/v0.30.0) | Per-platform release assets advertise digests, SBOM, provenance, and Sigstore material | Exact hashes, independent verification/mirror, rootless/no-Docker-socket profile, cache/credential isolation, ARM64 reproducibility |
| Container daemon | containerd 2.3.3 | [official release](https://github.com/containerd/containerd/releases/tag/v2.3.3) | Official release and integrity assets; dynamic and static distributions differ | Artifact variant/hash, internal signature/mirror, gRPC window, L1R cgroup/seccomp/lifecycle, ARM64 |
| OCI runtime | runc 1.5.0 | [official release](https://github.com/opencontainers/runc/releases/tag/v1.5.0) | Official checksum/signature materials are not yet captured locally | Exact binary/build tags/hash, signature procedure/mirror, containerd matrix, L1R/L4 isolation behavior |
| Signing candidate | cosign 3.1.1 | [official release](https://github.com/sigstore/cosign/releases/tag/v3.1.1) | Official release verification bundles/checksums; not verified here | Owner selection, identity/KMS/trust-root model, offline verification, revocation/DR, Forgejo/OCIR proof, mirror |
| Signing candidate | Notation 1.3.2 | [official release](https://github.com/notaryproject/notation/releases/tag/v1.3.2) | Official signed release and release assets; not verified here | Owner selection, plugin/KMS/trust policy, revocation, Forgejo/OCIR proof, mirror |
| OCI artifact transport | ORAS CLI 1.3.2 | [official release](https://github.com/oras-project/oras/releases/tag/v1.3.2) | Official release assets; exact hashes not recorded here | Mirror/signature, referrer/media-type round trips in Forgejo/OCIR, digest immutability, regional replication |
| SBOM | Syft 1.46.0 | [official immutable release](https://github.com/anchore/syft/releases/tag/v1.46.0) | Checksums plus certificate/signature and SBOM materials | Exact hashes/mirror, SPDX/CycloneDX selection, reproducible normalization, .NET single-file/OCI coverage, license policy |
| Vulnerability | Grype 0.115.0 | [official immutable release](https://github.com/anchore/grype/releases/tag/v0.115.0) | Signed release/checksum/SBOM materials; release notes align its Syft dependency with 1.46.0 | Exact hashes/mirror, offline DB digest/freshness, SBOM fixture, severity/fix/VEX/risk policy |
| Reviewed alternative | Trivy 0.72.0 | [official release](https://github.com/aquasecurity/trivy/releases/tag/v0.72.0) | Later immutable release materials exist, but the project disclosed a 2026 release-pipeline compromise | Independent rebuild/verification and incident-control review before candidacy, mirror, database pin, overlap decision |

The Trivy caution is not inference from third-party reporting. The project's [official GHSA](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) states that compromised credentials published malicious Trivy binaries/images and rewrote action tags in March 2026. This audit does not claim 0.72.0 is compromised; it records why normal tag/version trust is insufficient and why the tool remains an alternative pending stronger provenance review.

## Architecture and integrity interpretation

Binary candidates list `linux-x64` and `linux-arm64` only where the official release distribution exposes those platform families. This is distribution availability, not TerraScale qualification. Exact archive/binary hashes have intentionally not been copied from a partial web rendering, and no artifact was downloaded to compute them. Selection must bind exact hashes for both architectures, upstream verification material, licenses, scanner databases, plugins/build tags, and the internally mirrored copies.

NuGet candidates list `any-dotnet` because they are managed packages/tools rather than a claim of native ARM64 qualification. Their official pages show compatible target frameworks, but TerraScale still needs a locked content hash, .NET 10/TUnit execution, deterministic result normalization, and ordinary-Linux/ARM64 evidence.

License fields are candidate metadata, not legal approval. Every license source is version-specific and official; transitive dependency licenses, generated SBOM assertions, unknown licenses, dual licensing, exceptions, and an owner-approved allow/deny policy remain `GAP-LICENSE-POLICY`.

## Explicit non-selections and gaps

No candidate is proposed yet for deterministic model/state-space exploration and systematic concurrency. A plausible library that cannot meet the specification's fixed schedule counts, virtual-clock injection, deterministic schedule replay, .NET 10, and ARM64 runner constraints would be a false pin. The same fail-closed posture leaves secret scanning, license-policy evaluation, and the exact NuGet advisory/deprecation/lock gate open.

Cosign and Notation are deliberately peers in the candidate set. Neither is selected for artifacts or evidence. ORAS is artifact transport and does not make a signing choice. DSSE/in-toto-style evidence is a required architectural shape, but the envelope implementation, signing identity, KMS/isolated-CI custody, roots, connected/offline verification, revocation, recovery, and Forgejo/OCIR compatibility require the future supply-chain ADR. The Phase 0 plan explicitly requires that selection rather than allowing this audit to make it ([ORCHESTRATOR.md, lines 1488-1492](../../../ORCHESTRATOR.md#L1488-L1492)).

Every selected external input also requires a content-addressed internal mirror and TerraScale verification/signature receipt. None exists from this package. Scanner databases are independently mutable inputs and need their own digest, freshness, offline-replay, rollback, and compromise policy; pinning only the scanner executable is insufficient.

## Validator and adversarial fixtures

[`validate_supply_chain_pins.py`](../../../tools/phase0/supply-chain/validate_supply_chain_pins.py) uses only the Python standard library. It validates exact object keys, stable unique IDs, complete capability categories, version-specific official HTTPS sources, non-floating versions, license and platform metadata, mandatory x64/ARM64 distribution coverage, missing-mirror state, explicit gaps, and the absence of any selection/qualification claim. It also rejects secret-bearing fields. For the existing baseline it reads the checked-in SDK/package/lock sources, compares the recorded SDK roll-forward and package versions/content hashes, enumerates every lock file, and recomputes each SHA-256.

The data-driven [negative fixtures](../../../tools/phase0/supply-chain/fixtures/negative-cases.json) cover signing selection, floating version, `latest` URL, non-primary source, production qualification, false mirror readiness, missing ARM64, erased gaps, duplicate IDs, a synthetic secret-named field, selected status, unknown category, removal of the second signing candidate, SDK version/roll-forward drift, false SDK closure, TUnit/Microsoft.Testing.Platform drift, and lock path/digest drift.

Run:

```text
python3 -m json.tool testlab/pins/supply-chain-candidates.json
python3 tools/phase0/supply-chain/validate_supply_chain_pins.py
python3 -m unittest discover -s tools/phase0/supply-chain -p 'test_*.py' -v
```

These checks validate the evidence document, not the candidate tools. They do not satisfy L0, L1R, L3S, L4, signing, mirroring, reproducibility, or production qualification. The hard pre-deployment gate remains unchanged ([ORCHESTRATOR.md, lines 1114-1120](../../../ORCHESTRATOR.md#L1114-L1120)).
