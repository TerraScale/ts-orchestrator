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
