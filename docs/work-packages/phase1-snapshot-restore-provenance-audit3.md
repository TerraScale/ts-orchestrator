# Phase 1 snapshot restore provenance audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `9a5f2e2fe73dfbb613144e03ebc96971fa9e4919` after the required final rebase.
- Allowed paths: snapshot restore contracts, snapshot decision tests, and this work package.
- Pure deterministic decision work only; no snapshot serializer, persistence store, journal, NATS, filesystem, network, process, signing service, cloud/provider, VM, container, or deployment action.

## Executable defect

Two valid signed snapshots with different authorities, streams, schemas, signing keys, and signatures could produce the same complete public restore-plan projection when their snapshot ID, generation, epoch, stream position, and state digest matched:

```text
snapshot-42|3|7|102|73746174652D6469676573742D736563726574
```

The accepted output therefore erased the exact signed envelope that passed scope, schema, digest, freshness, and signature validation. A persisted plan could be relabeled across accepted authorities, streams, schemas, keys, or signatures without detection from the plan itself.

## Correction

`SnapshotRestorePlan` is now assembled internally only from the exact `SignedSnapshot` that passed validation plus its computed replay-start sequence. `AcceptedSnapshot` retains that immutable envelope. Existing snapshot ID, generation, expected epoch, and expected digest getters derive from its signed material, so independently mixed provenance cannot be constructed inside the planner.

The snapshot material, digest, and signature types already copy or retain immutable values. Tests prove exact snapshot/material/signature identity retention, source-buffer mutation safety, and a length-delimited complete test fingerprint over all nine authenticated material fields, the signature, and replay start. Each signed field and the signature is independently sensitive. Semantically identical replay is fingerprint-equal under multiple cultures; nominal snapshot objects are not claimed to have structural equality.

Every validation rejection and replay-start overflow retains `Plan = null`. Both accepted schema cases exercised by the pure contract—same current schema and a distinct schema classified `Compatible`—retain the exact envelope. Equal accepted generation at a later stream position remains valid. The plan exposes no public constructor, setter, deconstructor, clone, or forgeable plan-returning factory.

## Compatibility and precedence

No input DTO, enumeration, numeric value, validation error, plan error, validation result, or validation precedence changed. Existing plan projection getters remain source-compatible. Validation still checks context, snapshot shape, authority, stream, signing key, schema outcome, epoch, stream sequence, generation, digest, and signature in the existing order; replay-start overflow remains a post-validation planning error.

## Evidence boundary

The retained envelope proves only which caller-supplied immutable snapshot value the pure planner accepted under that invocation. It is not proof of snapshot content availability, digest computation, canonical serialization, signature authenticity, key custody, schema migration safety, durable accepted baselines, atomic persistence, restore execution, or journal replay correctness.

The validation context is deliberately not retained. In particular, the current accepted epoch/stream/generation baselines, expected digest, current schema, compatibility evaluator identity and policy, and signature-verifier identity and policy remain caller-owned authorization provenance that must be persisted separately when required. The plan also does not retain rejected candidates. This audit makes no cryptographic, persistence, NATS conformance, L0/L0C, recovery, deployment-readiness, or production-qualification claim.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded after the final rebase: Release solution build passed with zero warnings and errors; focused snapshot tests passed 46/46; all five executables passed 803/803 (ControlPlane 594, Contract 24, Model 38, Protocol 70, Scheduler 77).
