# Phase 1 storage create output audit 4 handoff

## Proven gap and correction

Two fully valid provider-volume creation requests differing only in encryption-key reference produced equal accepted `Create` decisions. Equivalent collisions existed for placement, storage domain, and mount purpose. `StorageVolumeRecord` validated those fields, but `Trace` omitted them when constructing `StorageIntentScope`.

`StorageIntentScope` now retains the exact `StorageDomain`, `EncryptionKeyReference`, `StoragePlacementId`, and `StorageMountPurpose` already present on the validated volume. All trace-produced accepted and held decisions share that complete structural subject. Existing projections and planner decisions are unchanged.

Tests independently distinguish every corrected field, pin exact key and placement references, check the complete subject across 1,000 cases for create, format, reattachment, expansion, deletion, and hold paths, and retain culture-stable semantic replay and opaque rendering. Assembly-wide reflection inventories every public declared method and accessor: the five Storage planners remain the only decision origins, while trace/scope exposure is limited to existing getters and immutable equal-but-distinct record copies.

The checked-in JSON replay corpus contains planner inputs and expected action/target/code outcomes, none of which changed. Its complete accepted-trace fingerprint and expected assertion were updated to include the four corrected fields; the historical JSON bytes and checksum therefore remain unchanged by design.

## Honest boundary

This closes only pure accepted-output provenance. It does not prove that the referenced key exists or is authorized, that a provider honors encryption or placement, that storage is formatted or mounted correctly, or that TerraBase is safe. It adds no adapter, schema, external I/O, destructive operation, lab qualification, or deployment evidence.
