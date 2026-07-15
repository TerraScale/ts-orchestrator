# Phase 1 reproducible-publish provenance audit 3 handoff

## Proven defect and resolution

The public pure observation verifier could mint a successful `ReproduciblePublishResult` from entirely
caller-authored process and file observations. Nonpublic result constructors therefore did not provide the claimed
construction closure: an external caller could report successful fake ELF digests without running the publisher or
reading an artifact.

`PublishObservationVerifier` and its `Evaluate` method are now internal. Only the exact
`TerraScale.Orchestrator.ContractTests` assembly receives friend access, preserving deterministic offline verifier
coverage without exporting an evidence factory. Public request and observation DTOs remain unchanged for
compatibility. `ReproduciblePublisher.RunAsync` remains the sole exported originating factory whose return type
wraps `ReproduciblePublishResult`. The sealed record's compiler-generated clone is explicitly non-originating: it
requires an existing result and no result property exposes a public setter or init route.

## Deterministic evidence

- Reflection enumerates every declared public static and instance method, including property accessors, on all
  exported types and correctly inspects `Task<ReproduciblePublishResult>`.
- It proves one asynchronous originating result route; permits only the exact non-originating sealed-record clone;
  and proves no public result setter/init route, synchronous or alternate originating factory, or exported verifier.
- It also pins nonpublic result constructors, public observation DTOs, and one exact friend assembly.
- It pins the unchanged public signatures of `ReproduciblePublisher.RunAsync`, `Program.Main`, and
  `Program.TryParse`.
- Existing tests continue to exercise the internal verifier with synthetic observations across success, output
  shape, RID/root replay, ELF, process, digest, diagnostic, enumerable, and symlink cases.
- No failure code, precedence, CLI argument, canonical output field, publish invocation, environment, input digest,
  or artifact verification behavior changed.

## Evidence boundary and nonclaims

Internal observations are trusted execution/test seams; they are not independently usable artifact evidence.
Successful public output proves only the copied-tree and double-publish observations made by `RunAsync`.

This audit performed no restore, publish, network, registry, signing, credential, deployment, VM, or cloud action.
It does not prove ARM64 runtime behavior, signing or pre-deployment attestation, registry state, deployment safety,
L4 qualification, release approval, or broader toolchain provenance. The earlier cross-publish handoff retains its
explicitly bounded and stale-tree evidence statement.

## Validation

- Offline Release build using existing locked restore artifacts: 0 warnings and 0 errors.
- Focused construction-closure and signature regressions: passed.
- Full ContractTests executable and exact cross-publish test shard: passed.
- `git diff --check`: passed.
