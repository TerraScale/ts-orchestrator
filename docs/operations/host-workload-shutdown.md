# Host workload ownership, recovery and shutdown

`HostWorkloadLifetime` is the execution boundary used by
`HostConvergenceRuntime` when admission supplies an `IHostExecutionLease`.
Lease-backed convergence requires an exclusive `HostWorkloadInventory` bound
to the exact cell, node and environment, plus native inventory discovery.
It cannot fall back to process-local tracking. TerraBase and authentication
have separate operation slots. Slots are keyed by runtime driver and allocation,
so even a TerraBase systemd unit and container with the same logical allocation
remain independently explainable and recoverable.

## Durable ownership before dispatch

The supervisor opens an existing Linux directory owned by its service user with
mode 0700. `owner.lock` and `workloads.json` require regular, single-link,
service-owned 0600 files. Symlink traversal, FIFOs, sockets, unexpected ownership
or permissions, a missing initialized document and mismatched host identities
fail closed. The lock inode is never unlinked. Its exclusive descriptor stays
open until all underlying recovery and native operations have settled.

The schema-1 inventory records complete canonical plans and their fingerprints.
A write flushes a private temporary file, atomically renames it, and fsyncs the
directory before native dispatch. Directory-open flags are selected for the
actual Linux x64 or ARM64 ABI; other ABIs fail closed. Unconfirmed writes poison the current
inventory and close execution; only restart recovery can resolve the durable
outcome. The supervisor checks pinned directory/lock identities, ownership
marker and document digest before another dispatch. This assumes the service
owner and root protect the directory; it is not a defense against a compromised
owner or arbitrary rollback of the whole disk.

Every recorded and dispatched plan is a detached reconstruction from the closed
role catalog. Systemd fingerprints bind the unit, executable, arguments and
properties, including custom artifact/state roots. Both adapters require exact
plan ownership before stopping an existing native object. A replacement or
failed upgrade tries its recorded previous plans; an allocation name alone
never authorizes a stop. There is no adoption of older incomplete systemd
fingerprints.

## Recovery without a broker

Recovery starts immediately, independently of desired-state reads, report
acknowledgements, artifacts or NATS. Discovery inspects every native address in
the closed role catalog for this host: systemd unit names and containerd names
in the `terrascale` namespace. Both driver scans must be complete. Every found
object must match a recorded plan; unexpected fingerprints, actual container
image/platform drift, ambiguous identities or incomplete scans block readiness.
This scan does not enumerate unrelated workloads outside those host addresses.

The supervisor stops recorded, discovered work and scans again before allowing
new reconciliation or a ready admission report. A stopped unit that still
exists retains its durable plan. Only confirmed absence retires evidence, and
absence in one driver cannot retire the other driver's plans. Recovery has a
30-second public deadline. A failed or timed-out recovery is terminal for this
supervisor and reports a blocked state and need; it never starts new work.

## Shutdown deadlines and late operations

Admission loss or disposal closes execution and starts independent cleanup with
fresh tokens. A workload whose start response or runtime report was lost still
has a durable pre-dispatch plan. Cleanup tries the exact recorded owners and
requires an `Absent` or `Stopped` observation with no main PID. A stop command
alone, `Running`, `Stopping`, `Failed`, an inspection error or a remaining PID
cannot prove shutdown.

Cancellation bounds the caller's wait but never releases an operation slot
while its underlying native call remains in flight. Cleanup stays queued behind
late starts. Late stops and recovery probes also retain exclusive supervisor
ownership, preventing a replacement supervisor from acquiring the same lock
while those operations can still affect its workloads.

The original shutdown receipt has a five-second budget, matching the execution
lease reserve. A missed deadline remains `unconfirmed` even if cleanup finishes
later. `OwnershipReleased` separately signals actual operation settlement and
lock release; it is not a claim that an unconfirmed workload stopped. The next
supervisor must always recover again. Disposal returns within the public
shutdown budget while unfinished cleanup retains ownership.

## Status and qualification limits

Recovery snapshots expose state, need, discovered count and stopped count.
Shutdown snapshots expose state, need and per-driver/allocation progress.
Core convergence exposes these snapshots and ownership release. They are not
yet exported by a dedicated host endpoint or accepted as controller drain
receipts.

Local qualification includes interrupted inventory writes, restart with damaged
or foreign state, exact ownership, both drivers, withheld desired reads/report
ACKs, and late operations. A test supervisor is killed after starting a real
child process but before returning its start response; the next supervisor
recovers and stops that surviving process without NATS or an installation
marker. The restricted JWT/mTLS R3 test composes durable ownership with actual
session revocation and owned-child shutdown. These tests do not launch
production TerraBase, auth, systemd units or containerd.

The production host entry remains disabled. It must start local recovery before
attempting broker/session acquisition, so failed authentication cannot skip
cleanup. Before enabling it, prove that the old supervisor's external command
cgroup is empty before recovery: an external
`systemd-run` surviving a killed supervisor could otherwise create a workload
after the scan. Native daemon jobs must also be drained or fenced to the exact
runtime generation; CLI process exit alone does not prove a queued job cannot
act later. Existing units use `Restart=always`; service-manager ownership
and shutdown behavior need native qualification. An advisory inventory lock
and main-PID observation do not establish complete cgroup or storage-writer
fencing. Controller drain evidence must bind node, allocation, artifact,
session generation and epoch before volume detach or retirement. The regional
replacement lease remains separately required across hosts. See the
[OCI readiness record](../evidence/oci-readiness-2026-09-20.md).
