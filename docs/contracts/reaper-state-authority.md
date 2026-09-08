# Reaper state authority

Production reaper construction requires `NATSStateStoreConfig` and an effect
admission callback. There is no production file or memory checkpoint fallback.
The generic engine retains its store interface for isolated domain tests.

The state session pins the actual GRU global candidate, global epoch, and LeaseID.
Same-identity renewal is accepted; takeover requires a new session. The authenticated
TLS 1.3 NKey connection must verify both peers and disable reconnect and buffering.
State, the global lease, and read barriers share file-backed R3
`KV_ORCH_LEADERS`, using these exact subjects:

- `$KV.ORCH_LEADERS.authority.global`
- `$KV.ORCH_LEADERS.reaper.state`
- `$KV.ORCH_LEADERS.reaper.barrier`

Reads route through ordinary `STREAM.MSG.GET`. Successful Load and Save, including
identical retries, require a new stream-wide expected-last-sequence commit and
readback of its server timestamp within the issuing lease. A local replica's read
alone cannot authorize work. State sessions reject stale loaded revisions. A lost
acknowledgement can be resolved by an identical retry that proves a fresh barrier.

Each state envelope contains the complete proposed and prior state, prior revision,
and issuing lease. A server commit after lease expiry restores the prior state,
including prior absence, without relying on a history record that may be gone.
Malformed state fails closed. Duplicate or unknown JSON fields are rejected.

State validation preserves database entries, operation and audit receipts, request
time, lifecycle cycles, and committed timestamps. An operation starts durably before
its receipt; retries increment attempts and retain prior completed operations.
Pause, notices, purge, key destruction, and data deletion follow their durable
prerequisites. Reactivation increments the cycle after its saved completion and
clears only that cycle's pause/notice timestamps. Version gaps from failed save
attempts are accepted; changed state cannot reuse or regress a version.

Each executor, mail, and audit call checks the required effect admission callback.
Snapshot creation rechecks after placement verification. Failure audits check the
callback even when their caller detached cancellation. These are method-entry
checks. Actual provider adapters must check at every transport retry and mutation
boundary; journal fencing does not revoke an external request already admitted.
The catalog, database, DEK, and mail production implementations remain required.

The authenticated Dashboard lifecycle response includes required
`coverage.uncoveredStorage` (`null` or `{startedAt, deadline}`), alongside card-loss
and unpaid-invoice coverage, and an explicit `idleNoticeAccepted` boolean.
An eligible billing observation must select a concrete due `deletionReasons[0]`
whose coverage deadline equals `billingGraceDeadline`. The measured-storage reason
is exactly `uncovered-storage`; missing conditions, mismatched deadlines, unknown
fields and stale lifecycle observations fail closed.

An observation does not authorize destruction. The automatic deletion claim calls
the Dashboard authority again, which refreshes exact pooled storage through the
request time and transactionally checks the current relevant billing policy,
active grace and accepted notice. Historical byte-seconds cannot establish current
coverage. The accepted claim fingerprints the measurement and policy evidence;
its receipt must match the requested policy revision, scope and reason, with
acceptance at or after the deadline. Missing fresh measurement or restored
coverage refuses the claim. A previously accepted claim remains a durable
operation-recovery receipt; replay does not invent a new acceptance timestamp.

## Capacity and retention limit

The stream must have exactly 8 MiB capacity, file storage, three replicas, discard
new behavior, no TTL, mirror, or sources, and one through five records per subject.
Canonical configuration uses history five. The complete reaper checkpoint is at
most 56 KiB and its proposed/prior envelope at most 128 KiB. Limits also include
128 database entries, 128 operations and 256 audits per entry, 255-byte database
IDs, 1,024-byte cursors, 600-byte operation keys, 620-byte audit keys, and 160-byte
error classifications. Stored errors accept a Go named-type spelling, never raw
provider error text. All limits apply together; the byte bound may be reached first.

At history five, maximum payload reservations are 1,536,000 bytes for rotation,
5,242,880 for restore, and 655,360 for reaper, totaling 7,434,240 bytes. That leaves
954,368 bytes for lease and barrier histories, other subjects, and message metadata.
This is a payload budget, not a guarantee that every shared workload fits. Server
capacity errors refuse progress; no receipt or pending obligation is trimmed.

Entries and completed operations cannot be removed. Consequently the limits bound
lifetime database population and reactivation history, not just concurrent work.
The scanner inserts observed databases before eligibility checks, so active,
paid and exempt databases also consume that lifetime capacity.
This checkpoint is not launch-scale capacity. Sharding and a proven retention or
archival scheme remain necessary before an unbounded production lifecycle can run.
They must preserve global fencing, complete recovery, and immutable obligations.

Real three-server tests cover file restart, stale same-lease writers, retained
receipts/cursors, lost acknowledgements, exact LeaseID replacement, minority Load
and identical Save refusal, expired writes with history one, and prior absence
recovery. Production lifecycle tests exercise day 30/60/90 and reactivation using
the concrete store. Capacity rejection is tested before any provider or mail call.
An actual restricted R3 session also exercises Load/Save, intent and receipt
recovery, identical-save barriers and LeaseID replacement under the production
global authority ACL. It rejects stream/consumer provisioning, deletion, purge
and foreign-key writes. The infrastructure owner provisions the store separately.
