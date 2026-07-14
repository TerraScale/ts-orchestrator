# Phase 1 reproducible-publish provenance audit 3

## Boundary

- Audit the reproducible-publish tool's successful result construction and public API surface.
- Preserve the existing CLI arguments, canonical output, exit codes, deterministic/offline publish behavior, and
  public request and observation DTO compatibility.
- Perform no restore, publish, network, registry, signing, credential, deployment, VM, or cloud operation.

## Proven counterexample

`ReproduciblePublishResult` and `PublishArtifactResult` had nonpublic constructors, but the public
`PublishObservationVerifier.Evaluate` method was an alternate public result factory. A caller could construct public
request and observation DTOs containing invented successful process state, ELF headers, modes, lengths, and digests,
then receive a result whose `Successful` property was true without copying an input tree, invoking `dotnet publish`,
or observing an artifact.

The pure verifier correctly evaluates trusted observations produced inside the execution path. The defect was its
exported position at the artifact-evidence boundary, not its deterministic evaluation rules.

## Required correction

- Keep the pure observation verifier internal to the reproducible-publish assembly.
- Grant internal access only to the exact ContractTests assembly so offline fake coverage remains exhaustive.
- Keep observation DTOs public for compatibility, but expose no public synchronous or alternate factory returning a
  successful publish result.
- Make `ReproduciblePublisher.RunAsync` the only exported originating result factory; retain its exact asynchronous
  signature and the exact public `Program.Main` and `Program.TryParse` signatures. The sealed record's compiler
  clone is non-originating: it requires an already constructed result and cannot change any result property.
- Preserve failure precedence, catalogs, artifact validation, deterministic inputs, CLI behavior, and canonical
  serialization.

## Evidence

- Enumerate every declared public static and instance method, including property accessors, on every exported type
  and unwrap `Task<T>` return types.
- Require exactly one originating public `ReproduciblePublishResult` route: `ReproduciblePublisher.RunAsync`.
- Permit only the exact parameterless instance clone declared by the sealed result record as a non-originating
  return path, and prove that no result property has a public setter or init route.
- Prove there is no public synchronous or alternate originating result factory and no exported observation verifier.
- Pin nonpublic result constructors, public observation DTO compatibility, the single exact friend assembly, and the
  unchanged CLI/publisher signatures.
- Retain the existing offline pure-verifier matrix for paths, RIDs, ELF validation, output shape, process failures,
  digest replay, input copies, diagnostics, enumeration bounds, and symlink roots.

## Nonclaims

Internal caller-authored observations are trusted test/execution seams, not artifact evidence. A successful public
result proves only what `RunAsync` actually observed during its copied-tree and double-publish execution. It does not
establish ARM64 execution, signing, attestation, registry publication, deployment, L4 qualification, toolchain
provenance beyond the retained contract, or release approval.
