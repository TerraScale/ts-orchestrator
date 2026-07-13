# Phase 1 pre-deployment evidence core

## Predecessor

- Contract steward commit: `b9d493c` plus the reviewed observability pure-core commit.
- Production signing technology, CI identity/KMS custody, approval authority, coverage tooling, mutation tooling, NATS pin, and release thresholds beyond the frozen specification remain unresolved selections and must stay explicit inputs.

## Goal

Implement the canonical evidence manifest, exact-subject invalidation, policy decision, opaque-signature verification boundary, and deployment-gate verifier required by `ORCHESTRATOR.md:1114-1180`. This lane cannot mint production acceptance evidence or credentials.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Evidence/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Evidence*.cs`
- `docs/work-packages/handoffs/phase1-predeployment-evidence-core.md`

## Required behavior

- Immutable bounded tree/dependency-lock/schema/test-binary/architecture-artifact/trace/coverage/mutation/fuzz/model/corpus/L0C/analyzer/approver/signing-profile/signing-identity/evidence identities and canonical SHA-256 values; checked counts, percentages, durations, schedules, generations, and sequence values; closed lane/result/error/action catalogs.
- One canonical evidence subject binds the exact Git tree, dependency lock, generated schema digest, every test binary digest, linux-x64 and linux-arm64 single-file artifact digests, per-suite test counts, requirement trace digest/counts, branch coverage, mutation results, fuzz target/corpus/results, model schedules/seeds/corpus, NATS conformance result, analyzer/dependency/vulnerability/license/secret-scan results, pinned toolchain digest, and approver identity. No field can be omitted or substituted.
- Caller-supplied policy encodes feature/full lane, required domains, cold-run requirement, minimum test/branch/mutation/property/model/fuzz/flake thresholds, permitted exclusions, required architectures, and whether reuse is allowed. No threshold/default is invented. Safety/authorization/durability/deletion exclusions and surviving safety mutants are always rejected regardless of caller policy.
- Content-addressed shard reuse is accepted only when source, transitive contracts, tests, corpus, dependencies, generators, schemas, and toolchain digests are byte-identical and the policy permits reuse. Shared-contract/security/toolchain or cold-first-candidate changes force full execution.
- A signed envelope binds a canonical payload digest, signing profile, signing identity, signature identity, generation, and expiry sequence. Verification uses an injected opaque verifier outcome only; the core never accepts private keys, credentials, arbitrary signature algorithms, callback delegates, or self-attesting booleans. Verification failure/exception/unknown outcome is a typed hold/reject and never emits deployment authority.
- Exact-subject verification returns a closed allow-dependency-conformance / allow-L1S-credential-release / hold decision. Any source/dependency/schema/test/binary/evidence/signature/expiry mismatch invalidates it. L1S authority additionally requires a complete full deployment-bound lane and a verified signature; a feature shard can never release deployment credentials.
- Outputs expose only closed codes, numeric trace, exact digest subjects, and construction-closed decisions/intents. No report text, JSON blob, command, environment, process, filesystem, network, clock, CI/provider SDK, key material, credential, or deployment mutation.
- Defensive bounded copies; culture/permutation/replay; every field substitution; missing/duplicate domain; arithmetic overflow; threshold boundary; forbidden exclusion; surviving safety mutant; insufficient fuzz/model/property/flake evidence; invalid shard reuse; stale/future/expired envelope; verifier exception/unknown; x64/arm64 substitution; secret-safe and public-forgery tests.
- The handoff must state clearly that this is the pure manifest/policy/verification core. It does not claim an executed full L0/L0C run, production signer/KMS qualification, dual-architecture reproducibility result, or a deployable attestation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
