# Restricted host convergence cycles

Host convergence records each install/rollback cycle through a signed controller
request. Retry state is durable across controller and host restarts. TerraBase
and `ts-auth` have separate state, including when admitted on the same host.
This protocol is bookkeeping: a cycle receipt does **not** grant execution,
regional replacement exclusivity, or storage writer authority.

## Requests and durable state

`RegionalHostCycleRequest` signs an independent `terrascale-regional-host-cycle-v1`
domain with the enrolled NATS user key. It binds enrollment, process session,
epoch, role, desired digest, operation, stable attempt ID, nonce and UTC time.
An outcome additionally binds the controller-issued cycle ID and monotonic fence.
Requests and replies use the existing exact hashed host observation/command
subjects. No private KV or object-store permission is added to host identities.

The controller checks current session authority before and after storage access.
Begin also requires the current desired digest for the enrolled environment and
role, confirmed through the desired reader's revision check. An outcome can
finish an older desired digest only while its exact cycle/session/fence remains
current. Replaced cycles reject old outcomes.

One record per `(cell, node, environment, role)` lives under `host.cycle.<hash>`
in controller-private `ORCH_DELIVERY`. The required store is R3, file-backed,
non-expiring, history two, 256 MiB, 16 KiB maximum value, with `Discard.New` and
no TTL, mirror or sources. Cycle records themselves are bounded to 4 KiB.
Conditional writes include unchanged confirmations; stale replica reads cannot
overwrite newer outcomes. Creation uses expected revision zero rather than
the SDK's tombstone-recreating create fallback. Tombstones and corrupt records
fail closed. Clearing failures never deletes the fence record.

| Begin result | Meaning |
| --- | --- |
| `Active` | This stable attempt has a recorded cycle; separate execution authority is still required |
| `Backoff` | The same digest is delayed by a recorded failure |
| `Busy` | This process session already has a different unfinished attempt |
| `Settled` | This exact attempt already finished; its replay cannot start work |

An acknowledged failed cycle increases the counter once and sets a deadline of
30, 60, 120, 240, 480, then 900 seconds. Further failures retain the 900-second
cap. Outcome retries preserve the counter and original deadline. A new process
discovering an unfinished same-digest cycle counts abandonment once; later
retries do not extend it. A newly desired digest starts a new fence with no
previous failure count. Successful completion clears the count. Target revisions
cannot move backward, and counter/fence overflow cannot wrap into a new cycle.

Session revocation, target changes or expiry can race a durable write. A later
check denies the response even if bookkeeping already committed. This is why
the cycle record cannot serve as an execution lease.

## Caller behavior and bounds

`NatsHostCycleCoordinator` retains one pending attempt/outcome per catalogued
role. Ambiguous exchanges use a fresh signed nonce but preserve operation identity.
A receipt already handed to a caller cannot begin another concurrent execution
through that coordinator. The selected outcome is retained even when the caller
has already cancelled; conflicting outcomes are rejected. A pending outcome
must flush before another cycle begins, including before healthy-marker or
withdrawn-target early returns. Enrollment/session/epoch changes require a new
coordinator and recovered process; pending state cannot migrate to a new identity.

Core convergence records the outcome before publishing status or writing its
local current marker. Failure to publish a success report cannot change that
successful cycle into a failure. Unexpected work errors attempt to record a
failed outcome with an independent bounded exchange. Process loss leaves an
unfinished cycle for subsequent abandonment accounting.

Requests are at most 16 KiB; responses are at most 4 KiB and require exact request
binding, valid disposition fields and unexpired UTC receipts. Exchanges have a
five-second deadline. The controller service has its own queue of 16, a
three-second storage budget, a separate one-second reply budget and at most one
unfinished storage operation. Reply queues hold one message. Overflow drops
requests, leaving hosts to retry. Even synchronously stalled storage cannot block
the separate session-renewal service or create an unbounded number of tasks.

The finite delivery bucket rejects writes at capacity rather than evicting retry
state. Fenced retired-node reclamation remains required; this protocol does not
automatically delete historical node records.

## Status and qualification

Controller startup starts, monitors and disposes this service alongside regional
host sessions. Authenticated operator status exposes `host-cycle` as `recording`,
`listening` or `retrying`, with `host-cycle:retry-request` on storage/reply failure.
The 0/100 action progress describes local service activity, not rollout completion.
Pending failures are tracked separately for up to 1,024 node/role pairs, with
sticky overflow. Another role's successful request cannot hide a pending failure.
These process-local indicators reset on controller restart; the retry record is
durable and is consulted on the next request.

Metrics use only bounded cell and result labels:

- `terrascale.orchestrator.host.cycle.requests`: active/backoff/busy/settled/rejected/failed responses.
- `terrascale.orchestrator.host.cycle.retry_pending` and `.in_flight`.

The [qualification receipt](../evidence/host-cycle-local-2026-09-21.json) records
source and log hashes and the exact test scope. Real restricted JWT/mTLS R3
tests cover concurrent controllers, replay, dropped replies, abandoned sessions,
stale reads/tombstones, target/session changes after a write, stalled storage,
role isolation and malformed data. Core convergence and actual controller status
are exercised separately. These tests do not qualify OCI or native ARM64 services.

Regional replacement leases remain the final direct runtime-KV dependency in
`HostConvergenceRuntime`. Production host startup must still recover local work
before broker/session acquisition and compose native quiescence, writer fencing
and exact drain receipts. See the [deployment readiness record](../evidence/oci-readiness-2026-09-20.md)
for first-boot, region ownership and OCI authentication gates.
