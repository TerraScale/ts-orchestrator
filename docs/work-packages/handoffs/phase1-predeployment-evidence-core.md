# Phase 1 pre-deployment evidence core handoff

## Delivered

- Bounded, immutable identities and defensive-copy SHA-256/signature values for the source tree, dependency lock, generated schema, test binaries, architecture artifacts, suites, requirement trace, fuzz/model corpora, L0C result, approver, signing profile/identity, signature, and manifest. Caller enumerables are consumed only through a maximum-plus-one bounded snapshot and iterator failures become invalid evidence.
- A canonical, permutation-stable subject binds every declared digest and metric: exact x64/arm64 artifacts, suite test/property/model/seed/flake counts, trace counts, coverage and mutation results, fuzz duration/cases/corpus, model corpus, opaque L0C result, static/dependency/vulnerability/license/secret-scan outcomes, pinned toolchain, exclusions, execution kind, and approver.
- Caller-supplied feature/full policies define required domains and architectures, cold-run/reuse rules, every quantitative floor, and permitted exclusions. The evaluator always rejects safety/authorization/durability/deletion and other correctness-critical exclusions, surviving safety mutants, failed checks, missing/duplicate domains, architecture substitution, bounds violations, and checked arithmetic overflow.
- Content-addressed reuse proof is itself bound into reused subjects and compares source, transitive-contract, test, corpus, dependency, generator, schema, and toolchain digests exactly. Shared-contract, security, toolchain, and first-candidate changes force full execution.
- Signed envelopes bind the canonical payload digest, profile, signing identity, signature identity, generation, and expiry sequence. An injected typed opaque verifier is the only signature-verification boundary; invalid, unknown, exceptional, stale, future, and expired results fail closed.
- Construction-closed decisions expose only a closed action/code, exact payload-digest subject, and numeric trace. Feature evidence may allow dependency conformance but can never authorize L1S credential release; only an exact, policy-complete full manifest with verified envelope can do so.
- Adversarial tests cover defensive copying, bounded and throwing enumerators, duplicate identities, malformed/default enums, culture/permutation/replay, every subject field family, every policy threshold, digest and architecture substitution, missing/duplicate domains, forbidden exclusions, safety mutants, reuse fingerprint substitution, overflow, stale/future/expired envelopes, verifier ordering plus invalid/unknown/exception outcomes, secret-safe formatting, and every public output-forgery barrier.

## Boundary and non-claims

This is only the pure manifest, caller-policy, content-addressed-reuse, opaque-verification, and deployment-gate decision core. It performs no process, filesystem, network, environment, clock, CI, provider, signer, KMS, credential, or deployment mutation operation.

It does **not** claim that an L0 or L0C lane has actually executed, that a production signer or KMS/CI identity has been qualified, that either architecture artifact is reproducible, or that any manifest/envelope is a deployable production attestation. All evidence values and policy thresholds remain caller inputs; adapters and protected environments must obtain and enforce real evidence later.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (260/260).
