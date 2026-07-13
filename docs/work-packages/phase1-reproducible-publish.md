# Phase 1 reproducible dual-architecture publish

## Predecessor

- Contract steward commit: `4a36bc4`.
- ARM64 runtime qualification, host image, glibc/kernel, signing profile, package mirror, and release approval remain external or owner-controlled evidence.

## Goal

Implement and verify locked, deterministic, self-contained single-file publishes for linux-x64 and linux-arm64 as required by `ORCHESTRATOR.md:1114-1180,1496-1510`. This is build reproducibility evidence only; it never executes or qualifies the ARM64 artifact.

## Allowed paths

- `tools/reproducible-publish/**`
- `tests/TerraScale.Orchestrator.ContractTests/ReproduciblePublish*.cs`
- `tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj`
- `src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj`
- `Directory.Build.props`
- `docs/work-packages/handoffs/phase1-reproducible-publish.md`

## Required behavior

- One reviewed non-shell .NET tool accepts explicit source root, already-restored locked tree, configuration, two isolated output roots, and expected RIDs. It performs no restore, network, Git, signing, credential, deployment, or source mutation.
- Publish linux-x64 and linux-arm64 twice from byte-identical inputs into distinct clean roots using deterministic/CI/path-map/source-date settings and self-contained single-file configuration. Reject an unexpected RID, missing/extra primary executable, multi-file payload where single-file is required, symbolic link, non-regular output, or output escaping its root.
- Verify both outputs are ELF and bind the correct machine type (x86-64 versus AArch64), are not scripts/text, and have distinct architecture artifact digests. Do not execute the cross-architecture artifact.
- Produce a canonical in-memory result with exact tree-input digest supplied by the caller, RID, byte length, SHA-256, repeat SHA-256, reproducibility status, and closed failure codes. Optional checked-in output is not authorized; callers may serialize elsewhere.
- Byte-identical repeat output is required. If .NET apphost/single-file tooling is not reproducible under the pinned toolchain, fail with exact evidence and fix deterministic inputs/configuration; never normalize or rewrite the produced binary after publish.
- Paths are canonicalized and confined beneath the supplied source/output roots. Reject traversal, aliases that collapse the two repeat roots, output inside source, source inside output, and pre-existing nonempty output roots.
- Tool subprocess invocation uses argument lists, fixed environment allowlist/overrides, explicit timeout/cancellation, captured bounded diagnostics represented only as closed codes/counts, and exact exit handling. No arbitrary command text or shell.
- Contract tests cover argument/path validation, symlink/escape, ELF parser truncation/class/endianness/machine, digest stability, output enumeration, timeout/nonzero exit classification, secret-safe results, and public-construction barriers where applicable. A slow opt-in or checked tool invocation performs the real two-RID double publish and reports actual digests; ordinary unit tests use deterministic fake process/file observations without weakening production logic.
- The handoff must distinguish cross-publish evidence from ARM64 execution, L4 qualification, signature, and pre-deployment attestation. Do not claim reproducibility unless the real double-publish command ran successfully for both RIDs.

## Verification

- `dotnet test tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj`
- documented real locked double-publish command from the tool handoff
