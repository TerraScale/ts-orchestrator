# Runtime priority qualification

`qualify.py` has two read-only/profile-staging commands. It does not start
load generators, restart systemd units, or write to a live target. Each
`qualify --role` invocation inspects one guest. Controller and host units
require systemd 255 or newer; the host keeps
`Delegate=yes` and `DelegateSubgroup=supervisor` so the native runner can
isolate workload cgroups.

`deploy/image/build-offline.sh` calls the renderer while assembling the image,
before it uploads or enables the controller and host units. The builder
requires an explicit profile ID, system reserve, and all six memory floors;
it has no memory-floor defaults. Prefer values measured with the exact base
image, kernel, and service configuration. If selected values are used before
measurements exist, record them as allocations rather than measured results.
For the selected 1 OCPU/6 GiB preview placement, use the managed-host profile's
1 GiB `SystemReserveBytes`. The builder writes the reserve into a root-owned
`/etc/terrascale-orchestrator/runtime-priority.json` profile and packages the
renderer at
`/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py`. The host
checks that its current signed placement reserve matches the baked value
before launching a workload. The reserve and the separate host, controller,
and slice floors are configured allocations. The D15 target probe records
actual use; pressure qualification determines whether this exact profile
survives the tested workload.

## Render memory protection drop-ins

The OCI image/profile preparer supplies page-aligned floor allocations and
the selected reserve. Do not label selected allocations or fixture values as
measured usage. The service minimum must be positive, no greater than its
low value, and the service low value must fit within `SystemReserveBytes`.
The controller must be measured separately on a controller guest. The image
renderer requires the slice allocation to cover both unit floors. On a
dedicated guest, the live probe checks that the slice covers its active role
and fits the guest's reserve; it does not infer that both units run there.

Run the renderer against an image staging root before packaging the image:

```sh
python3 tests/runtime_priority/qualify.py render-drop-ins \
  --profile-id "$PROFILE_ID" \
  --service-memory-min-bytes "$HOST_SERVICE_MEMORY_MIN_BYTES" \
  --service-memory-low-bytes "$HOST_SERVICE_MEMORY_LOW_BYTES" \
  --controller-memory-min-bytes "$CONTROLLER_MEMORY_MIN_BYTES" \
  --controller-memory-low-bytes "$CONTROLLER_MEMORY_LOW_BYTES" \
  --system-slice-memory-min-bytes "$SYSTEM_SLICE_MEMORY_MIN_BYTES" \
  --system-slice-memory-low-bytes "$SYSTEM_SLICE_MEMORY_LOW_BYTES" \
  --system-reserve-bytes "$SIGNED_SYSTEM_RESERVE_BYTES" \
  --output-root "$IMAGE_STAGING_ROOT"
```

The renderer writes exactly these profile-bound files under the staging root:

- `etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf`
- `etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf`
- `etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf`

The slice values are an aggregate budget for its protected child units. Each
service gets its profile floor. The host service values are copied by the
native host supervisor into its `supervisor` subgroup; the runner and each workload role must retain
`memory.min=0` and `memory.low=0`. The generated files are idempotent and the
renderer refuses to overwrite conflicting files. The image installer must
install all three files before first boot and record their hashes with the
image and profile IDs. It also packages the canonical baked reserve profile at
`/etc/terrascale-orchestrator/runtime-priority.json`. No whole-service `MemoryMax` or
`CPUQuota` is set by these unit files. The host still validates its complete
signed allocatable-plus-reserve budget against physical memory and every
ancestor `memory.max`.

## Verify each target guest

The deployment has three dedicated controller VMs and separate ARM TerraBase
workload VMs. Run the packaged probe on each selected controller and workload
guest with that guest's own reviewed memory profile and exact
OCI instance, image, artifact, configuration, and profile IDs. Controller
and workload evidence must carry distinct instance and boot IDs. The live
manifest pins separate controller floor-source artifacts for the controller
service and its slice. One live manifest witnesses one controller guest; run
separate role probes for the other controller VMs before claiming their unit
settings are qualified.

On a workload guest, run the host probe before and after managed TerraBase
launch. The second run includes the witnessed TerraBase PID and signed role cap:

```sh
/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py qualify \
  --role host \
  --oci-instance-id "$HOST_OCI_INSTANCE_ID" \
  --image-id "$HOST_IMAGE_ID" \
  --artifact-id "$HOST_ARTIFACT_ID" \
  --config-id "$HOST_CONFIG_ID" \
  --profile-id "$HOST_PROFILE_ID" \
  --expected-memory-min-bytes "$HOST_SERVICE_MEMORY_MIN_BYTES" \
  --expected-memory-low-bytes "$HOST_SERVICE_MEMORY_LOW_BYTES" \
  --expected-system-slice-memory-min-bytes "$HOST_SYSTEM_SLICE_MEMORY_MIN_BYTES" \
  --expected-system-slice-memory-low-bytes "$HOST_SYSTEM_SLICE_MEMORY_LOW_BYTES" \
  --system-reserve-bytes "$HOST_SIGNED_SYSTEM_RESERVE_BYTES" \
  --allocatable-memory-bytes "$HOST_SIGNED_ALLOCATABLE_MEMORY_BYTES" \
  --database-pid "$TERRABASE_PID" \
  --database-memory-max-bytes "$SIGNED_TERRABASE_CGROUP_MEMORY_MAX_BYTES" \
  --evidence-dir "$NEW_HOST_EVIDENCE_DIR"
```

Omit only `--database-pid` and `--database-memory-max-bytes` before the
database process starts. On a controller guest, use its own values:

```sh
/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py qualify \
  --role controller \
  --oci-instance-id "$CONTROLLER_OCI_INSTANCE_ID" \
  --image-id "$CONTROLLER_IMAGE_ID" \
  --artifact-id "$CONTROLLER_ARTIFACT_ID" \
  --config-id "$CONTROLLER_CONFIG_ID" \
  --profile-id "$CONTROLLER_PROFILE_ID" \
  --expected-controller-memory-min-bytes "$CONTROLLER_MEMORY_MIN_BYTES" \
  --expected-controller-memory-low-bytes "$CONTROLLER_MEMORY_LOW_BYTES" \
  --expected-system-slice-memory-min-bytes "$CONTROLLER_SYSTEM_SLICE_MEMORY_MIN_BYTES" \
  --expected-system-slice-memory-low-bytes "$CONTROLLER_SYSTEM_SLICE_MEMORY_LOW_BYTES" \
  --system-reserve-bytes "$CONTROLLER_SIGNED_SYSTEM_RESERVE_BYTES" \
  --allocatable-memory-bytes "$CONTROLLER_SIGNED_ALLOCATABLE_MEMORY_BYTES" \
  --evidence-dir "$NEW_CONTROLLER_EVIDENCE_DIR"
```

Each evidence directory must be new. `summary.json` records the guest role,
repository revision when available, packaged probe SHA-256, baked profile
hash, active unit hash, systemd version, unit properties, process priority and
OOM values, cgroup weights and limits, ancestor memory protection, and
physical/ancestor budget. Its `memory_usage_sample` contains the active
service and its `system.slice` on the same guest, with raw
`memory.current`, `memory.peak`, and `memory.stat`, cgroup paths and
inodes, boot and OCI instance IDs, kernel/systemd versions, image/artifact/
config/profile IDs, a UTC window, and a canonical hash. `commands.log`
retains the read-only systemd queries. The host probe also verifies native
runner and role CPU/memory/I/O caps, OOM eligibility, and that TerraBase
runs below the native workload runner.

The `memory_profile` fields are configured effective `MemoryMin`/
`MemoryLow` values. The separate `memory_usage_sample` contains observed
usage. Neither field establishes measured floor adequacy by itself. The D15
runner retains before, during, and after samples from both pinned guests.
Its during observations must complete inside the worker's active pressure
window. The read-only operator `hosts` query also must return fresh admitted
source and peer reports and advances during pressure; this is the controller
management response witness. A controller unit snapshot alone does not prove
that the controller answered management requests.

The probe is a preflight and state snapshot; it does not create pressure.
OCI acceptance must run bounded CPU, memory, and block I/O pressure against
the managed workload while checking host management continuity, controller
response, database progress, and effective cgroup values. Capture the pressure
command, limits, timestamps, and before/during/after evidence under the
actual OCI artifact/configuration IDs. A render or idle snapshot does not
qualify survival under pressure.

The baked profile must be canonical version-1 JSON owned by root with mode
0644 and no extra fields. Its profile ID and system reserve must match that
guest's signed placement. The service unit hash is selected by guest role.
Both units use `ManagedOOMPreference=omit`, which systemd-oomd applies
nonrecursively. On a host guest, the native supervisor also sets
`user.oomd_omit=1`; TerraBase runner and role groups remain eligible with
reset nice, OOM score, and I/O priority. These protections do not cover
kernel or host failure.

## Pressure runner and evidence adapters

`pressure.py` provides the bounded D15 runner and its resource-only pressure
worker. `alpha_runner.py` validates the source-backed HostStatus, service,
ObjectDurable, systemd and kernel evidence. `alpha_adapter.py` supplies the
fixed alpha transport: a pinned read-only `operator hosts --config FILE`
query, strict SSH to the source and peer, and verified HTTPS transactions and
point reads. The adapter does not accept arbitrary commands from a manifest.
The raw `HostStatus.verified` value is retained and must be `false`, as emitted
by the controller's read-only reader. That output is controller-admitted data;
it is not represented as a portable signature.

The identity preflight compares source and peer controller-admitted host
registrations with their pinned SSH targets, and checks source, peer, and
controller `uname` architecture. Through the verified source and controller
SSH connections, it reads only OCI
metadata v2 `id`, `image`, `regionInfo/regionIdentifier`, and `shape` fields.
It matches both live instance and imported image IDs to their separate
manifest pins and checks that the controller is in the source cell's OCI
region. It uses the
fixed `169.254.169.254` endpoint, `Authorization: Bearer Oracle`, no proxy or
redirect handling, and bounded direct HTTP requests. The raw metadata response
and user data are never retained. Field names and the v2 header follow
[Oracle's instance metadata guide](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm).

Use the checked-in manifest only to check the offline contract:

```sh
python3 tests/runtime_priority/pressure.py dry-run \
  --manifest tests/runtime_priority/example-dry-run.json
```

It has valid v4 structure and reserved example identities and paths. It has no
live authorization, available floor-source artifacts, credential or pin files,
or frozen contract source, so it reports `UNQUALIFIED` without
starting a command or creating evidence. Replace every example value from the
real deployment handoff before considering a live run. In particular, pin the
actual source-host and controller OCI instance, image, artifact, configuration
and signed profile; both members and their scoped authorities; the read-only
operator configuration; source, peer, and controller SSH targets, identity
files and known-hosts files; HTTPS origins, private API
tokens and CA bundle; remote tool paths and hashes; and floor-source artifacts.
The SSH account must have noninteractive `sudo` for the fixed
systemd, journal and cgroup actions. The harness never deploys product files.

The pressure helper is launched in a run-named transient systemd scope on the
same host, under the exact pre-existing workload slice named by the manifest.
The adapter verifies systemd's `Slice`, control group, quota, memory cap and I/O
weight against cgroupfs before and during the run. Both systemd properties and
cgroup files must report `MemoryMin=0`, `MemoryLow=0`, `memory.min=0` and
`memory.low=0`. It also records the scratch filesystem's full block backing
chain. The scope is a sibling outside TerraBase's native role tree; this
qualification makes no claim that it is a native direct child. The worker
checks its own placement and never writes `cgroup.procs` or moves a process.

Before pressure, the runner pins the exact source/peer host reports, process
start identities, manager snapshots, and a fresh database operation. The write
must return an ObjectDurable receipt with its actual scoped event origin and
sequence. The peer point read must contain the exact value/schema under that
event. Source and peer ServingProof v1 frontiers must cover the same event.
Across phases, reports must remain fresh and advance, the source/peer desired
identity must remain stable, and the write/read operation must finish within
the frozen deadline. The `commit_sequence` receipt field remains separate from
the event sequence.

Failure modes have different evidence:

- `terrabase_process` SIGKILLs only the current witnessed native role process;
  management services must keep their process identities and restart counters.
- `terrabase_oom` temporarily lowers `memory.max` on only the exact native
  TerraBase role cgroup. The role must contain only the witnessed process, no
  child cgroups, and current usage above the requested cap. A kernel journald
  OOM record must name that PID and cgroup after the pre-pressure cursor. The
  adapter restores the signed cap in a `finally` path and verifies the same
  cgroup descriptor/inode or a recreated role before returning. No SIGKILL or
  sibling worker is used to simulate this OOM case. Before the mutation, the
  exact target, cgroup inode, signed cap, and temporary cap are fsynced into the
  run evidence. Final cleanup checks that obligation even when the OOM action
  reply or restoration receipt is missing. It restores only the unchanged
  target cgroup when its cap is still the requested temporary value; an
  unknown cap or changed cgroup identity leaves an explicit unresolved cleanup
  failure without modifying a replacement cgroup.
- `host_manager_sigkill` SIGKILLs the witnessed host-manager MainPID. Its
  systemd restart count and PID/start identity must advance while the
  controller remains stable; the managed report and database operation must
  recover afterward.

No live pressure or fault is authorized by the example manifest. Do not run a
live fault until the owner supplies the frozen contract and the exact target
handoff. A live invocation, after that handoff, is:

```sh
python3 tests/runtime_priority/pressure.py run \
  --manifest "$D15_MANIFEST" \
  --evidence-dir "$NEW_EVIDENCE_DIR"
```

The evidence directory must be new. Each adapter request, exact pinned
interpreter command, stdout, stderr, parsed response and observation is
retained with checksums. Run evidence is capped at 64 MiB, with 16 MiB reserved
for cleanup and final observations. Each adapter's combined output is capped
at 1 MiB. Pressure is bounded to 900 seconds, 64 CPU workers, 32 I/O workers,
16 GiB memory payload plus headroom, 2 GiB per I/O file, 4 GiB scratch, 64 GiB
written bytes and 128 MiB/s. The finite write budget must cover the configured
rate for the entire run.

The runner always attempts to stop the exact run-named scope and remove its
run-specific scratch path, including when startup or a fault fails. Cleanup
must prove that no scope process, child cgroup, or scratch path remains. The
final summary is `PASS` only after baseline, during-pressure, and final
role-bound source-host and controller usage samples validate, and both
during-pressure samples complete in the active worker interval; all workers
complete the requested
duration; the selected failure and recovery evidence match the named
scenario; the ObjectDurable event remains peer-visible; and cleanup is
verified. Floor origin remains labelled `allocation` or `measured`; actual
pressure and recovery results establish behavior only for the tested
configuration. Missing owner authorization, frozen pins, floor-source files,
or identity-bound samples are `UNQUALIFIED`; a failed evidence check is `FAIL`.
Count a D15 `PASS` only after the exact live workload manifest and achieved
pressure are reviewed and pinned for that scenario. A dry-run or smoke run does
not establish D15 qualification.
