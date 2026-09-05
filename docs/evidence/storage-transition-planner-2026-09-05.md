# Storage-transition planner verification

The owner CLI now accepts `plan-storage-transition --config <absolute-path>`.
It produces exact signed plan bytes after verifying source and destination
bootstrap bindings, the source capture signer and dates, the signed preliminary
scope, and both candidate receipts. The original owner's public key verifies
all bootstrap and scope signatures and the resulting transition plan. The
command makes no network or host-state calls.

The package test constructs fresh P-256 keys, signed original bootstrap grants,
a signed capture request and receipt, a signed scope and signed SFO/FRA receipt
claims. The successful output is independently checked by
`controltransition.VerifyPlan`. Rejection cases cover source store, source
manifest and account changes, destination and receipt reordering, a missing
receipt, scope substitution, an expired plan, and a foreign private signing key.
They require no signed output on failure. Additional checks cover cancellation,
a short output write, duplicate/case-aliased/unknown JSON names, trailing JSON,
a null plan, broad input permissions and symlink input.

`TestControlCandidateDispatch` includes the new command and verifies strict
argument handling and that command errors do not fall through into ordinary
runtime composition. Focused race logs and the portable check log accompany
this record.

These fixtures test cryptographic attribution and binding; they do not contain
real restored snapshots. Real isolated candidate restoration has separate
[evidence](transition-candidate-evidence-2026-09-05.md). Neither record proves
current host health, real OCI ownership, final inventory/configuration equality,
source stop/seal, host delivery, phase recovery, or production R3 promotion.
