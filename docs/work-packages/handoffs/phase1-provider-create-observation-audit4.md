# Phase 1 provider create-observation audit 4 handoff

## Proven gap and correction

The same exact absent `ProviderCreateObservation` authorized independent create operations in different cells and compartments. Create evidence retained its key, generation, state, and resolved resource but no regional authority scope, so exact local authority and call evidence could not detect replay of the observation itself.

Create observations now require immutable cell and compartment values. The create authorization branch requires both to equal the operation context before its existing generation/state gate can pass. Same-key observations whose scope differs are conflicting as well as duplicate evidence and remain held without intent. Resolved-create intents retain the exact scope objects from the observation, preventing accepted output from discarding the new provenance.

The regression shard covers cross-cell and same-cell/cross-compartment replay, exact absent and resolved acceptance, rejected trace/no-intent/no-durable output, null scope rejection, defensive request snapshots, exact resolved-intent reference retention, and conflicting multi-observation evidence. A 1,000-case property alternates absent/resolved evidence and both scope-replay dimensions while preserving all existing action-path coverage.

## Fingerprint and replay boundary

There is no provider ownership replay corpus or separate canonical projection containing `ProviderCreateObservation`. `ProviderOperationContext.Fingerprint` intentionally excludes current observations: it identifies the persisted authorized operation and binds call evidence and durable resume, while ownership/create observations are fresh evidence re-evaluated on every authorization request. Adding observation scope to that operation fingerprint would incorrectly turn a current evidence snapshot into operation identity. Every actual representation of the create observation itself—its immutable model, conflict projection, authorization comparison, and resolved-create output—now retains or checks both scope fields.

## Honest evidence boundary

This correction does not claim a create key is globally unique or bind an observation to an operation ID. It does not prove provider observation authenticity, adapter or journal provenance, provider SDK behavior, OCI/cloud behavior, filesystem/network/runtime behavior, deployment, L4, or production acceptance. No external provider or deployment side effect occurred.
