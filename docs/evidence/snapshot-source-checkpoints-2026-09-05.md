# Source checkpoints in snapshot version 3

The prior envelope retained consumer identity but not its source checkpoint.
Candidate verification compared two restores of the same archive. Agreement
between those restores could not establish that the archive preserved the
source's delivered and acknowledged positions.

Implementation commit `6c960477` introduces version 3. It retains each
file-backed consumer's configuration digest, delivered
and acknowledgement-floor consumer/stream sequences, acknowledgement-pending
count, undelivered count and redelivered-message count. Source observations
before and after transfer must agree. Missing or invalid checkpoint fields
refuse capture. Memory-backed ephemeral watchers retain identity only and must
not claim a persisted checkpoint.

`RestorePreliminarySnapshot` now compares the restored consumer directly with
the source checkpoint in the validated envelope. Candidate synchronization uses
this check for both its reference restore and retained target before signing a
receipt. A changed target is retained and rejected, never deleted for retry.
Versions 1 and 2 are rejected because they lack required evidence. Existing
immutable captures need a new authorized scope to be recaptured.

The configuration digest preserves the NATS SDK's JSON duration/omission
semantics and deterministic metadata ordering. The helper uses JSON v2 with
the explicit v1 options for this existing SDK wire type. Go 1.27.1 and the
Modern Go Guidelines CLI were used.

Verification includes:

- Source checkpoint changes across capture and missing source fields are
  rejected before publication.
- Old envelope versions, missing file-backed checkpoints, malformed digests,
  impossible acknowledgement floors and memory-backed checkpoint claims fail.
- A real archive with altered but structurally valid source checkpoint claims
  fails public restore verification.
- Stable independent restores and retries succeed; changed target
  acknowledgements fail against the original source envelope.
- Existing empty/purged allocator, full-record transfer, candidate restart and
  retained-store conflict cases remain covered.

The [tagged race tests](snapshot-v3-tagged-2026-09-05.txt) and the
[full-profile snapshot/R3 recovery regression](snapshot-v3-profile-2026-09-05.txt)
passed. The final [portable `make check`](snapshot-v3-portable-2026-09-05.txt)
also passed. The first portable run caught the integration fixture's old version-2
expectation; the fixture now expects version 3 while retaining its independent
content, checkpoint, R3 and restart checks.

The [full VM attempt](vm-test-snapshot-v3-2026-09-05.json) ran from 21:51:37Z to
21:54:20Z on September 5. Its [sanitized diagnostics](vm-test-snapshot-v3-2026-09-05.txt)
show ts-node and orchestrator running on the first GRU guest, with TerraBase
exiting at `membership-source-missing`. No guest became ready and no scenario
ran. Automatic cleanup left no recorded provider paths or reachable fixture
listeners. Explicit `make vm-clean` exited 0, and diagnostic credentials were
removed after use.

This change verifies the recorded consumer configuration and checkpoint values.
It does not decode every pending-message entry in the archive, establish an
atomic cut across streams, fence writers, retire the source R1, restore the
complete final cut, or wire the engine membership source. PR-03 and production
acceptance remain open. The pinned NATS consumer creation-time defect is also
unchanged.
