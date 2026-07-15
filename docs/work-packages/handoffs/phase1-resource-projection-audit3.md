# Phase 1 resource projection audit 3 handoff

## Proven gap and correction

Two accepted built-in metrics descriptors selecting different catalog entries had distinct C# canonical identities but could only be described as the same enum-only `MetricsStore` role in the generated read-only descriptor projection. The projection also lost the selected domain and had `additionalProperties: false`, so the missing provenance could not be added by a consumer.

The generator now builds one closed admitted-role shape for both the standalone admitted-role schema and the descriptor's nested role. The nested form omits only the redundant API version. It requires exact domain and catalog-entry provenance for metrics, regional telemetry, and VPN selections; it forbids implementation data for ordinary roles and retains closed unknown-kind/unknown-field rejection. The standalone admitted-role artifact remains byte-for-byte unchanged.

Contract tests interpret the generated constraints and cover distinct catalog identifiers, every sealed role case, all three exact domain mappings, missing or mismatched implementation data, ordinary-role implementation rejection, unknown kinds and fields, shared standalone/nested semantics, and checked-in generator artifact equality. Re-running the generator produces an identical descriptor-schema digest.

## Honest evidence boundary

This is a breaking correction only to the draft internal read-only documentation projection. It does not freeze or implement a serializer or runtime wire contract, admit a manifest, prove that a catalog entry received owner approval, choose a concrete metrics/telemetry/VPN product, execute a runtime, or provide deployment evidence. The C# contracts and enum numerics are unchanged.
