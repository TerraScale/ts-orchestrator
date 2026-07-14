# Phase 1 delivery stage output audit 4 handoff

## Proven gap and correction

Two otherwise identical accepted staging requests with different valid rollout strategies produced structurally identical `StageReleaseIntent` values. The stage intent flattened artifact identity fields and discarded the validated strategy, rollback policy, ordered-cell policy, and exact selected availability evidence.

Initial staging now retains the exact validated `ReleaseSpec` and the exact `CellArtifactAvailability` selected for the expected cell. All existing compatibility getters derive from those two immutable inputs, including `Cell` from the selected availability. Construction remains internal and `DeliveryEngine.DecideRollout` remains the single public decision route.

Tests pin exact reference retention, existing getter equivalence, defensive ordered-cell snapshot behavior, every release and availability field in an independent length-delimited fingerprint sensitivity matrix, ordered-cell count/order/element sensitivity, all four valid strategies, both rollback policies, 1,000 semantic replays across cultures, hold-only denial paths, and assembly-wide construction closure. The existing 1,000-case Delivery policy suite now compares complete staged provenance. No persisted corpus encoded staged intents, so no replay corpus or checksum changed.

## Honest boundary

This correction retains caller policy and selected in-memory evidence; it does not execute or prove a rollout strategy. It does not prove artifact presence outside the submitted availability record, cryptographic signature validity, registry state, deployment success, health, or external enforcement. Advance and rollback accepted-output shapes are unchanged. No runtime adapter, wire format, deployment, external I/O, or side effect was added.
