# Usage registration delivery

Database activation delivers the accepted signed placement to all scope members,
then registers the persisted billing streams before recording completion. The
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
same issued proof.

Normal creation still does not allocate authoritative lifecycle streams. Missing
streams keep activation pending. This delivery work does not invent partitions,
qualify the real Rust daemon entrypoint, or establish production billing readiness.
