# Preliminary candidate evidence for the storage transition

The owner-signed storage plan now requires the canonical preliminary-transfer
scope digest. `candidatesync.VerifyTransitionCandidates` checks both SFO and FRA
receipts against that scope and the plan. It returns immutable bindings to the
exact signed receipts while the plan remains live.

`VerifyScopedReceipt` selects the candidate key from the verified owner scope,
then checks host/region, preparation and bootstrap grants, prepared manifest,
source receipt, historical epoch, capture/completion times, complete ordered
object mappings, and canonical restore-evidence hashes. The existing candidate
worker now uses this verifier when reopening a completed receipt, before its
existing comparison with freshly observed restore state.

The transition check additionally binds the owner, source admission/profile,
account and stream inventory, target host/server/manifest identities, election
floor, and byte budgets. Aggregate transfer bytes include all three regional
object mappings. This is a preliminary synchronization prerequisite, not the
complete preparation barrier or permission to stop the source.

The integration fixture captures real embedded-NATS streams in both source
accounts, publishes the same signed scope, and performs separate SFO and FRA
reference/target restores. Both receipts pass the transition check. The test
also proves that their authoritative destination directories remain absent.
Object reads and bucket observations use in-process provider fixtures; no real
OCI or guest readiness is claimed.

Negative cases include missing, reversed, duplicate, and extra receipts; a
different scope, transition, source profile, prepared manifest, host, server,
account or stream; a regressed election floor; and an insufficient restore
budget. The receipt tests re-sign false or incomplete claims using the correct
candidate key, verify that attribution succeeds, and require scoped validation
to reject them. They also verify unchanged successful replay.

An initial negative fixture assigned the existing bootstrap hash to itself.
After correcting it to a different digest, the focused race suite passed for
`candidatesync`, `controltransition`, and `nodeauthority`. Output is retained in
`transition-candidates-focused-2026-09-05.txt`.

The sandbox-tagged race checks passed for `candidatesync`, `initialcontrol`, and
`vmqualruntime`; output is in `transition-candidates-tagged-2026-09-05.txt`.
These tests do not boot Firecracker guests.

`make check` passed formatting, vet, build, and the full portable race suite.
Output is in `transition-candidates-portable-2026-09-05.txt`.

The verifier authenticates restore-evidence references; it does not fetch the
referenced bytes or independently compare final configurations and consumer
state. Durable host preparation receipts, current health checks, independent
receipt delivery, source retirement/sealing, and the later phase journal remain
required. The engine membership blocker is unchanged.
