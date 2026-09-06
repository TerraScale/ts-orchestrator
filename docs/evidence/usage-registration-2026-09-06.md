# Usage registration delivery

Database activation delivers the accepted signed placement to all scope members,
then atomically allocates the lifecycle streams and registers their committed
partitions before recording completion. The
planner covers retained databases as well as the new database, because the
placement epoch changes across the cluster. It requires the exact owner,
selected Regions, residency, epoch and active lifecycle partition. Both regional
seats receive the same stream. Retries retain the signed proof and operation ID.

The existing authenticated host NATS subject carries a strict usage envelope.
The local orchestrator verifies host identity and forwards the registration over
the UID-checked Unix connection. Successful receipts must repeat every field.
Requests and receipts are bounded to 16 KiB; redirects and unknown receipt fields
are rejected. The shared subject retains the larger existing install limit.

Durably deleted scopes remain in placement history and receive no fresh usage
registration. Member deletion fences must retain maintenance access across an
epoch change without reopening origin writes.

Verified transport tests include authenticated NATS through the host listener to
a Unix HTTP fake engine, exact success, changed tuples, wrong state, unknown
fields, oversized responses and redirect refusal. Usage-focused race tests pass.
Transition tests verify usage failure blocks completion and retries reuse the
same issued proof. The full `make check` passed, including formatting, vet, build,
and the repository-wide race test suite. Planner and effect regressions cover
missing or ambiguous streams, changed lifecycle authority, retained deletion,
and stopping a partially delivered batch on authority loss.

The GRU authority now allocates streams inside the same fenced journal used by
admission. A batch covers every live scope in the accepted merged proposal.
Random canonical ULID partitions are retained by deterministic lifecycle events;
retries reuse those events, including retries after later epochs. A different
proof cannot reuse an allocated epoch. Initial streams cover immutable resource
creation; successor streams close the previous active interval while preserving
closed history. Strictly deleted resources receive no new allocation.

The allocator rejects mismatched durable records, owner/environment/Region
changes, and conflicting epochs. Any failure rolls back the entire batch.
Runtime authority is checked before allocation and usage delivery; usage delivery
re-reads committed lifecycle data and refuses changes during a batch. The empty
cluster bootstrap is the only no-database allocation case.

Committed wrapped keys now retain their actual reserved size because their
payloads cannot change. Maximum key sizes remain reserved for unfinished
purposes. This fixes the permanent reservation that prevented a second database
from entering the journal, without reducing protection for pending effects.

Focused tests passed (`3871`), covering initial inventory closure, unchanged
retries, merged successors, historical retries, rollback after an earlier scope
mutation, and real NATS restart with stale authority rejection. An integrated
transition test (`43060`) verifies registrations match the actual committed
partitions. Independent review found and resolved same-epoch proof reuse and
historical retry defects; final review found no material issues in these fixes
or the key reservation change. Full repository verification is pending for this
allocation continuation. These checks do not qualify the Rust daemon entrypoint
or establish production billing readiness.

The private database admission payload now transmits the original journal
`CreatedAt` as integer Unix milliseconds for install, branch capture, and restore.
Rust requires the matching positive `created_at`, persists it immutably, and
returns it in public metadata. Exact propagation and zero rejection tests pass.
Independent producer/consumer review found no material mismatch. Full
orchestrator `make check` passed again, including race tests (`98145`, exit 0).
