# Phase 1 adversarial model accepted-event provenance audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `da6ee0d0251acf106456323e2ab9cacfae02caa6` after the required final rebase.
- Allowed paths: deterministic model simulation contracts/reducer, model tests, and this work package.
- Pure deterministic L0 model work only; no adapter, NATS server, filesystem, process, network, systemd, container, VM, cloud/provider, credential, or deployment action.

## Executable defect

Two accepted authorization events with the same event ID and authorization subject but different replay coordinates produced equal accepted evidence, equal canonical state, and equal state digest:

```text
E1: Sequence=1, ObservationSequence=1
E2: Sequence=9, ObservationSequence=99
```

The reducer validated all eleven event fields before acceptance, but `AcceptedActionEvidence` retained only selected operation and authority facts. Once the event left the queue, its sequence, due tick, kind, and observation sequence were absent from accepted evidence; the delivered-ID set preserved only its ID. A saved final digest therefore could not identify the complete event that the model had accepted.

## Correction

`AcceptedActionEvidence` now retains the exact immutable `ModelEvent` passed to the reducer's single evidence helper. Every event-derived compatibility projection—including action kind, operation, node, generation, idempotency key, resource, and event epoch—is derived from that retained event rather than independently supplied. There is no compatibility constructor or factory that can synthesize accepted evidence without a complete event.

The canonical state projection uses the existing complete, length-delimited `ModelState.EventCanonical` helper for retained accepted events. It therefore binds sequence, due tick, event ID, model-event kind, node, operation, generation, epoch, idempotency key, resource, and observation sequence without maintaining a second manual event serializer. The same reducer helper serves every currently reachable accepted kind: authorization, create, and mutation. The termination branch also calls that helper if a future valid model state makes its existing acceptance path reachable.

Tests separately prove exact event reference retention and record-value replay semantics. Every individual event-field mutation changes accepted evidence, canonical state, and digest; equivalent reconstructed events remain value-equal and digest-equal across cultures. Existing authority-evidence mutants now replace the retained event fields, preserving their independent invariant checks.

`ModelState` validates the retained event before accessing any derived projection. A missing event and an otherwise valid event kind that maps to no accepted action both fail deterministically at the state boundary with `ArgumentException`; neither can be accidentally accepted or surface a null dereference.

## Compatibility and behavior

No event, failure, invariant, provider-outcome, accepted-action, or failure-code enumeration or numeric value changed. No reducer gate, scheduling rule, result/error precedence, queue ordering, exploration bound, invariant rule, corpus schema/version/content address, or saved expectation changed. This correction changes only accepted evidence and the state digest that intentionally commits to it.

## Evidence boundary

The retained value proves which caller-supplied immutable model event the in-process reducer recorded as accepted. It does not prove that an observation sequence was fresh or authentic, that a provider/delivery action occurred, that an external verifier or policy was correct, or that the current bounded model covers every production interleaving. Event identity, ordering coordinates, and acceptance-time authority facts remain modeled inputs, not external attestations.

This work does not claim the Phase 1 million-schedule deployment-bound budget, mutation/fuzz thresholds, complete requirement trace, real NATS L0C, snapshot/persistence correctness, adapter correctness, VM/cloud qualification, or deployment readiness.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded after the final rebase: Release solution build passed with zero warnings and errors; focused audit tests passed 6/6; Model tests passed 44/44; all five executables passed 817/817 (ControlPlane 597, Contract 29, Model 44, Protocol 70, Scheduler 77).
