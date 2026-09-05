# Bootstrap NATS mutation admission

A `ControlStoreCheck` for a mirror or replica mutation target must include
`AuthorityCandidateID` and `AuthorityLeaseID` alongside `AuthorityTerm`. These
are the exact admitted election candidate, LeaseID and term. They are distinct
from the topology epochs on the action. The candidate must be an admitted member
assigned to a checked stream. Global application authority is restricted to GRU;
SFO/FRA replica placement does not confer that authority. Read-only declarations may omit the new fields.

For example, these fields belong inside an action's existing `Checks` entry:

```json
{
  "AuthorityID": "global",
  "LeaseKey": "authority.global",
  "AuthorityTerm": 7,
  "AuthorityCandidateID": "global-controller-gru-one",
  "AuthorityLeaseID": "lease-original"
}
```

Old mutating declarations that omit either field fail
`ValidateControlRuntimeDeclarations`, called by CLI configuration loading before
provisioning. Direct `NewNATSControlRuntime` construction repeats validation; the
CLI factory calls that constructor after resolving OCI member receipts. The command's existing decoder, region-stage projection,
and constructor carry the fields unchanged. Its persisted declaration digest binds
them to the admission generation. A reconstructed runtime uses the same declared
identity; it never adopts a live replacement lease because the term still matches.
Same-identity renewal remains valid. A replacement requires a newly admitted action,
not a retry that silently edits its identity.

Every actual mirror create and replica update reads the target's authority through
ordinary leader-routed `STREAM.MSG.GET` immediately before and after the API call.
Each stream in a multi-stream replica update receives its own checks. An identical
retry also checks authority, even when the desired stream already exists. Final
store evidence respects declared candidate and LeaseID pins too.

Stream administration offers no expected-lease CAS. These checks provide request
admission and fail closed on changed or expired identity; they cannot revoke a
request NATS already accepted. The promotion workflow must still serialize its
admitted actions and prove removal of old administrative credentials.

New candidate mirrors inherit the source stream's finite `MaxBytes`, `MaxMsgs`,
`MaxMsgsPerSubject`, `MaxMsgSize`, `MaxAge`, and discard policy. Sources must be
file-backed limits-retention streams with positive finite byte capacity, without
mirrors or sources of their own. Existing mirrors must match those bounds on replay
and evidence readback. An old unbounded mirror is rejected, not silently changed.
Mirror validation also pins the complete `StreamSource`: start sequence/time,
filters, subject transforms, domain, consumer configuration and external delivery
redirection are not admitted. Stream-level transformation, republication, custom
first sequence, sealing, TTL/marker/counter/scheduling behavior and other inventory
mutation options are refused. The candidate disk/account reservation must accommodate the complete retained
source inventory; this change does not allocate candidate storage or form a cluster.

Focused tests use real TLS/NKey three-node NATS. They cover same-term replacement
across runtime reconstruction, renewal, expiry after the first actual replica
update, refusal of the next update/retry, finite mirror creation/readback, and
unbounded or fenced mirror rejection. CLI tests preserve the fields through
projection and reject same-generation declaration changes.

## Durable consumer promotion

Each `ReplicaUpdates` entry declares `Consumers`, containing the stream name
and complete target `jetstream.ConsumerConfig`. Targets must be durable pull
consumers with explicit acknowledgements and three file-backed replicas.
Declarations are capped at 64 streams and 64 consumers per update. Promoted
`GLOBAL_SPEC`, `CELL_SPEC` and `CELL_EVENTS` streams require consumer declarations.

Before any stream mutation, a bounded `CONSUMER.LIST` read compares the actual
inventory with the declared names and profiles. Missing or extra consumers stop
the action. Listing verifies the declaration; it never supplies mutation targets.
The bootstrap administrative identity needs that read permission on the declared
streams. Ordinary runtime credentials gain no new permissions.

The existing consumer is updated in place, changing only its replica count.
Authority checks surround each update and readback, including retries. Completion
requires the exact admitted leader/replica server set, current replicas, unchanged
consumer creation identity and non-regressing delivery/acknowledgement checkpoints.
During election, a response may retain the correct profile and creation identity
while reporting a provisional zero checkpoint. The bounded read loop continues
until the exact admitted replicas are current before comparing checkpoints.
A regressed checkpoint from that current group still fails the action. Every
observation attempt rechecks the original authority lease; no update is replayed
to repair an incomplete observation.
Mirrors and sourced streams cannot enter this replica-promotion path.

The [storage experiment](../evidence/nats-snapshot-promotion-audit-2026-09-05.md)
found that promoting streams alone leaves the three initial consumers at R1.
Real broker tests now verify consumer promotion, preserved acknowledgement state
and pending-message delivery after the original hosting server stops. This does
not complete the signed host cutover or its post-transition snapshot requirement.

For consumers restored from snapshots, the pinned server has a separate
[creation-metadata persistence defect](../evidence/nats-snapshot-promotion-limits-2026-09-05.md).
The immediate API checks above can pass while a later restart exposes a changed
consumer creation timestamp. They do not qualify unchanged original creation
identity across restore, promotion and restart. Exact checkpoint/content recovery
has separate coverage; production restoration identity remains an open gate.
