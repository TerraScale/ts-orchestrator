# Runtime priority qualification

`qualify.py` has two read-only/profile-staging commands. It does not start
load generators, restart systemd units, or write to a live target. The
controller and host units require systemd 255 or newer; the host keeps
`Delegate=yes` and `DelegateSubgroup=supervisor` so the native runner can
isolate workload cgroups.

`deploy/image/build-offline.sh` calls the renderer while assembling the image,
before it uploads or enables the controller and host units. The builder
requires an explicit profile ID, system reserve, and all six memory floors;
it has no memory-floor defaults. Prefer values measured with the exact base
image, kernel, and service configuration. If selected values are used before
measurements exist, record them as allocations rather than measured results.
For the selected
1 OCPU/6 GiB preview placement, use the signed managed-host profile's
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
the selected signed managed-host reserve. Do not label selected allocations
or fixture values as measured usage.
The service
minimum must be positive, no greater than its low value, and the service low
value must fit within the signed `SystemReserveBytes`. The controller must be
measured separately. The `system.slice` values must cover the aggregate of
the controller and host service floors and fit within the same signed reserve.

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

## Verify a target guest

After image boot and before the managed database role is launched, run the
probe on that target guest with values from its signed placement profile and
the exact artifact/configuration/profile IDs:

```sh
/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py qualify \
  --oci-instance-id "$OCI_INSTANCE_ID" \
  --image-id "$IMAGE_ID" \
  --artifact-id "$ARTIFACT_ID" \
  --config-id "$CONFIG_ID" \
  --profile-id "$PROFILE_ID" \
  --expected-memory-min-bytes "$HOST_SERVICE_MEMORY_MIN_BYTES" \
  --expected-memory-low-bytes "$HOST_SERVICE_MEMORY_LOW_BYTES" \
  --expected-controller-memory-min-bytes "$CONTROLLER_MEMORY_MIN_BYTES" \
  --expected-controller-memory-low-bytes "$CONTROLLER_MEMORY_LOW_BYTES" \
  --expected-system-slice-memory-min-bytes "$SYSTEM_SLICE_MEMORY_MIN_BYTES" \
  --expected-system-slice-memory-low-bytes "$SYSTEM_SLICE_MEMORY_LOW_BYTES" \
  --system-reserve-bytes "$SIGNED_SYSTEM_RESERVE_BYTES" \
  --allocatable-memory-bytes "$SIGNED_ALLOCATABLE_MEMORY_BYTES" \
  --evidence-dir "$NEW_EVIDENCE_DIR"
```

After the managed database role starts, run it again with the observed
TerraBase PID and signed per-role cap:

```sh
/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py qualify \
  --oci-instance-id "$OCI_INSTANCE_ID" \
  --image-id "$IMAGE_ID" \
  --artifact-id "$ARTIFACT_ID" \
  --config-id "$CONFIG_ID" \
  --profile-id "$PROFILE_ID" \
  --expected-memory-min-bytes "$HOST_SERVICE_MEMORY_MIN_BYTES" \
  --expected-memory-low-bytes "$HOST_SERVICE_MEMORY_LOW_BYTES" \
  --expected-controller-memory-min-bytes "$CONTROLLER_MEMORY_MIN_BYTES" \
  --expected-controller-memory-low-bytes "$CONTROLLER_MEMORY_LOW_BYTES" \
  --expected-system-slice-memory-min-bytes "$SYSTEM_SLICE_MEMORY_MIN_BYTES" \
  --expected-system-slice-memory-low-bytes "$SYSTEM_SLICE_MEMORY_LOW_BYTES" \
  --system-reserve-bytes "$SIGNED_SYSTEM_RESERVE_BYTES" \
  --allocatable-memory-bytes "$SIGNED_ALLOCATABLE_MEMORY_BYTES" \
  --database-pid "$TERRABASE_PID" \
  --database-memory-max-bytes "$SIGNED_TERRABASE_CGROUP_MEMORY_MAX_BYTES" \
  --evidence-dir "$NEW_ACTIVE_EVIDENCE_DIR"
```

Each evidence directory must be new. `summary.json` records the repository
revision when available, the packaged probe SHA-256, baked profile hash, unit
hashes, systemd version, systemd properties, process `nice`,
`oom_score_adj` and `ionice`, cgroup weights and limits, ancestor memory
protections and the physical/ancestor memory budget. The summary also captures
raw `memory.current`, `memory.peak`, and `memory.stat` for the host service,
controller service, and aggregate `system.slice`. The sample includes exact
cgroup paths and inodes, system.slice direct children, boot and OCI instance
IDs, kernel/systemd versions, image/artifact/config/profile IDs, a UTC sampling window, and a
canonical content hash. `commands.log` records
the read-only systemd queries. The probe fails on missing or mismatched
settings, a unit or ancestor with insufficient memory protection, inherited
manager process priority, absent delegated controllers, or a role that is not
bounded below the supervisor's CPU/I/O weights. It checks the native runner
and role CPU quota against 75% of the host's effective affinity/ancestor CPU
budget, leaving the rest available to the manager without limiting idle
database burst capacity.

The `memory_profile` fields are configured effective `MemoryMin`/`MemoryLow`
values. The separate `memory_usage_sample` contains observed usage and does
not relabel those allocations as measured floor sizing or infer headroom. The
D15 runner checks its schema, hashes, scope, boot ID, target IDs, and sample
time before retaining it. Each run records a baseline before pressure,
samples during pressure, and a final sample after cleanup/recovery. A
successful result applies only to the exact tested image/profile, configured
limits, workload, and observed scenario; it does not assert a universal
headroom rule.

The probe is a preflight and state snapshot; it does not create pressure.
OCI acceptance must separately run task-owned, bounded CPU, memory, and block
I/O pressure against the managed workload while checking host/controller
session continuity, host control responsiveness, database progress and the
same effective cgroup values. Capture the pressure command, workload limits,
timestamps, and before/during/after probe evidence under the OCI artifact and
configuration IDs. A successful drop-in render or idle snapshot alone does
not qualify survival under pressure.

The target probe requires the baked profile to be canonical version-1 JSON
owned by root with mode 0644 and no extra fields. Its `profile_id` and
`system_reserve_bytes` must match the invocation values supplied from the
signed placement profile. It hashes the installed service units under
`/etc/systemd/system`; when run from the packaged helper path it records no
Git revision and reports its own script hash instead.

The units use `ManagedOOMPreference=omit`. systemd-oomd records this as the
nonrecursive `user.oomd_omit=1` cgroup attribute. The service manager applies
it to each unit cgroup; the native supervisor applies it to its `supervisor`
subgroup. The TerraBase runner and role groups remain eligible for systemd-
oomd and start with `nice=0`, `oom_score_adj=0`, and best-effort I/O priority
4. These settings govern systemd-oomd selection; they do not claim that the
manager cannot be killed by every kernel failure mode.

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

The identity preflight compares each controller registration's OCI instance
ID with its pinned SSH target and checks both targets' `uname` architecture.
Through the already verified source SSH connection, it also reads only OCI
metadata v2 `id`, `image`, `regionInfo/regionIdentifier`, and `shape` fields.
It matches the live instance and imported image IDs to the source pins and
compares the canonical region to the controller registration. It uses the
fixed `169.254.169.254` endpoint, `Authorization: Bearer Oracle`, no proxy or
redirect handling, and bounded direct HTTP requests. The raw metadata response
and user data are never retained. Field names and the v2 header follow
[Oracle's instance metadata guide](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm).

Use the checked-in manifest only to check the offline contract:

```sh
python3 tests/runtime_priority/pressure.py dry-run \
  --manifest tests/runtime_priority/example-dry-run.json
```

It has valid v3 structure and reserved example identities and paths. It has no
live authorization, available floor-source artifacts, credential or pin files,
or frozen contract source, so it reports `UNQUALIFIED` without
starting a command or creating evidence. Replace every example value from the
real deployment handoff before considering a live run. In particular, pin the
actual OCI instance, image, artifact, configuration and signed profile; both
members and their scoped authorities; the read-only operator configuration;
SSH targets, identity files and known-hosts files; HTTPS origins, private API
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
same-guest usage samples validate; all workers complete the requested
duration; the selected failure and recovery evidence match the named
scenario; the ObjectDurable event remains peer-visible; and cleanup is
verified. Floor origin remains labelled `allocation` or `measured`; actual
pressure and recovery results establish behavior only for the tested
configuration. Missing owner authorization, frozen pins, floor-source files,
or identity-bound samples are `UNQUALIFIED`; a failed evidence check is `FAIL`.
Count a D15 `PASS` only after the exact live workload manifest and achieved
pressure are reviewed and pinned for that scenario. A dry-run or smoke run does
not establish D15 qualification.
