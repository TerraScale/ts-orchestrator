# Host workload shutdown

`HostWorkloadLifetime` is the execution boundary used by
`HostConvergenceRuntime` when admission supplies an `IHostExecutionLease`.
It tracks canonical allocation plans before dispatch and serializes operations
for each allocation. TerraBase and authentication have separate slots, so one
blocked or failed stop cannot prevent cleanup of the other role.

Admission loss or disposal closes the inventory to new operations and starts
cleanup independently of reconciliation. Cleanup needs no desired-state read,
report acknowledgement, artifact download or NATS connection. It uses fresh
tokens, rather than the cancelled execution token. A host whose runtime report
is blocked before the installation marker is written still has its plan in
this process-local inventory.

Each stop passes through the existing native adapter's ownership checks. If an
upgrade failed, cleanup can try the exact previously tracked plan. A foreign
allocation never becomes owned merely because it occupies the expected name.
A successful stop command alone is insufficient: the adapter must subsequently
observe `Absent` or `Stopped` with no main PID. `Running`, `Stopping`, `Failed`,
an inspection error or a remaining PID produce no successful shutdown claim.
These observations are not an independent cgroup-empty or storage-writer fence.

## Deadlines and late operations

Cancellation bounds the caller's wait but never releases an allocation slot
while the underlying native operation remains in flight. Cleanup stays queued
behind that operation, including when it ignores cancellation or blocks before
returning a task. A late start is therefore followed by cleanup within this
still-running process; it cannot race a previously reported successful stop.

The original shutdown result has a five-second budget, matching the execution
lease's reserved cleanup time. The result stays `unconfirmed` if that budget
expires. Cleanup that was waiting for a native operation continues after the
operation finishes, with its own bounded stop attempt. A later snapshot may
show the tracked allocation stopped; it never changes the original missed
deadline receipt into an on-time success. A paused OS or terminated supervisor
cannot be made safe by this cooperative component alone.

## Status and qualification limits

The local snapshot contains state, need, allocation count, stopped count and a
bounded list of per-allocation states. The bounded completion receipt belongs
to the original cleanup attempt. Both are available from core convergence.
They are not yet exposed by a dedicated host endpoint or admitted as a
controller drain acknowledgement. `stopped` describes the tracked inventory,
not every process that might exist on the guest.

Local tests cover missing desired state, a withheld report acknowledgement,
late synchronous/asynchronous starts, independently failed roles, native stop
errors, misleading stop observations and exact container ownership. The real
restricted JWT/mTLS R3 test also revokes an active session and observes an owned
child process exit through the lease and cleanup boundary. The child-process
test does not launch production TerraBase, auth, systemd units or containerd.

Before OCI deployment, the dedicated host must acquire exclusive local
execution ownership, recover a durable inventory written before each possible
start, and stop or safely adopt existing allocations before new work. Crash
recovery must cover a start whose response or install marker was never written.
The regional replacement lease still serializes stateful replacements across
hosts; this per-allocation local serialization does not replace it. Drain must
bind positive stop evidence to the exact node, allocation, artifact, session
generation and epoch before volume detach, retirement or replacement. Disk
ownership, cgroup/process absence and storage writer fencing remain separate
deployment gates in the [OCI readiness record](../evidence/oci-readiness-2026-09-20.md).
