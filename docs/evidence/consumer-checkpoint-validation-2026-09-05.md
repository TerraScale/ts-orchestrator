# Archived consumer checkpoint validation

Commit `e840310f` validates the content of every archived `obs/<consumer>/o.dat`
before publication or public restore. The previous check established only
presence and nonzero length. NATS v2.14.6's internal decoder allocates from
encoded counts and does not require complete input consumption.

The new validator reads the pinned format-2 encoding with canonical varints.
It requires the stored delivered and acknowledgement-floor sequences and
pending/redelivery collection counts to match the envelope's source checkpoint.
It bounds each file to 64 MiB and each collection to 1,048,576 entries, with
additional bounds derived from remaining bytes before map allocation. It rejects
unsupported headers, truncation, noncanonical varints, duplicate stream keys,
invalid sequence ranges, arithmetic overflow and trailing bytes. Snapshot
envelope version 4 is unchanged.

Verification passed with Go 1.27.1 and the Modern Go Guidelines CLI:

- [Portable `make check`](consumer-state-portable-2026-09-05.txt)
- [Tagged snapshot, candidate, initial-control and VM-runtime race tests](consumer-state-tagged-2026-09-05.txt)
- [Focused malformed-state and pending-recovery regressions](consumer-state-regression-2026-09-05.txt)
- [Ten-second fuzz run, 50,109 executions](consumer-state-fuzz-2026-09-05.txt)

The real-broker recovery fixture delivers three records, acknowledges the second
and redelivers the first. Capture and restore retain two outstanding
acknowledgements and one redelivered-message entry. After verifying unchanged
restore evidence, the fixture shortens the retry timer and proves that records
one and three are redelivered while acknowledged record two is not. It then
acknowledges both and verifies the committed floor.

Another fixture appends a byte to a real `o.dat`, rebuilds the enclosing archive
and its digest, and verifies rejection before the destination stream exists.
The parser tests cover truncation at every byte boundary, duplicate entries,
counter changes, oversized counts, noncanonical varints and overflow. The
corruption fixture initially omitted the context deadline required by NATS
flush; that fixture was corrected before the passing checks above.

These checks validate every encoded entry structurally and compare aggregate
checkpoint values with source observations. The public NATS API does not expose
the live source's complete per-message maps or timers for independent comparison.
The fixture's delivery proof is limited to its tested state. Final source
fencing/retirement, atomic multi-stream capture, complete R3 transition and
engine membership integration remain unfinished. Production acceptance remains
open.

The [full VM attempt](vm-test-consumer-state-2026-09-05.json) booted the first GRU
guest. Its [sanitized service diagnostics](vm-test-consumer-state-2026-09-05.txt)
show ts-node and orchestrator running, while TerraBase exited with status 1 at
`membership-source-missing`. No guest became ready and no scenario ran.
Automatic cleanup left no recorded provider paths or reachable fixture
listeners. Explicit `make vm-clean` exited 0; temporary diagnostic credentials
were removed afterward. This result does not qualify the changed recovery path
in the complete VM suite.
