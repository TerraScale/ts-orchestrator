# Source record evidence in snapshot version 4

Implementation commit `c124421b` closes a gap in version 3: the envelope bound
source consumer checkpoint values, but record hashes came only from restores.
Two matching restores could not by themselves prove that the archive preserved
the source records.

Version 4 adds `recordsSha256`. After archive transfer, capture reads every
retained source record using exact-stream `STREAM.MSG.GET` permission. The hash
includes subject, headers, data, timestamp and sequence using deterministic SDK
record encoding. Sequence numbers bind gaps without requesting each deleted
sequence. Empty streams retain the SHA-256 of an empty record sequence.

The source's state and configuration must match the snapshot response before
the read and remain unchanged afterward. Stream creation identity must remain
stable across the read. Consumer inventory and checkpoint values are checked
again after record verification. The cumulative encoded records are bounded to
eight times the configured snapshot limit and are hashed incrementally. Raw
record contents never enter error messages or evidence output.

Public restore verification now requires the restored record hash to match the
source hash. Candidate synchronization applies that check to both fresh
reference restores and retained target stores. Versions 1 through 3 are
rejected; immutable earlier captures require a new authorized capture scope.

The [focused real-broker race tests](snapshot-v4-focused-2026-09-05.txt) and
[tagged race tests](snapshot-v4-tagged-2026-09-05.txt) passed. They cover:

- source publication, deletion and configuration changes during the read;
- encoded-record size limits;
- missing/malformed digests and older envelope versions;
- a structurally valid envelope claiming a record digest different from its
  archive, rejected by public restore;
- existing full-record/header/timestamp, deleted-gap, empty/purged allocator,
  checkpoint and retained-candidate recovery cases;
- source-owned capture/publication and full-profile snapshot/R3 recovery.

Go 1.27.1 and the Modern Go Guidelines CLI were used. The hashing helper uses
JSON v2 with explicit v1 options to preserve the NATS SDK record encoding,
including deterministic header ordering and its nil-header representation.

The first portable run exposed a reconnect-test race: a later reconciliation
pass held the lifecycle mutation lock while the test requested status. The
host correctly returned busy. The reconnect fixture now waits for its real
initial installation and schedules later reconciliation outside the transport
test interval. Production behavior is unchanged. All
[ten repeated reconnect race tests](host-reconnect-repeat-2026-09-05.txt) passed.
The final [portable `make check`](snapshot-v4-portable-2026-09-05.txt) also passed.

The [VM report](vm-test-snapshot-v4-2026-09-05.json) covers 22:05:19Z through
22:08:04Z on September 5. [Service diagnostics](vm-test-snapshot-v4-2026-09-05.txt)
show ts-node and orchestrator active on the first GRU guest. TerraBase exited
with `membership-source-missing`. No guest became ready and no scenario ran.
Automatic cleanup left no recorded provider paths or reachable fixture
listeners; explicit `make vm-clean` exited 0. Diagnostic credentials were
removed after use.

These checks bind source and restored records for each stream; they do not
fence writers, establish an atomic multi-stream cut, decode every consumer
pending-acknowledgement entry, retire source R1, or wire engine membership.
PR-03, full VM qualification and production acceptance remain open.
