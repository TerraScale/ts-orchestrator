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
before launching a workload. The reserve is a selected allocation; the
separate host, controller, and slice floors still require service memory
measurements and pressure qualification.

## Render memory protection drop-ins

The OCI image/profile preparer should measure controller and host-manager
memory under the selected image, kernel, and service configuration. It
supplies page-aligned byte values and the selected signed managed-host
reserve. Do not label selected allocations or fixture values as measurements.
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
protections and the physical/ancestor memory budget. `commands.log` records
the read-only systemd queries. The probe fails on missing or mismatched
settings, a unit or ancestor with insufficient memory protection, inherited
manager process priority, absent delegated controllers, or a role that is not
bounded below the supervisor's CPU/I/O weights. It checks the native runner
and role CPU quota against 75% of the host's effective affinity/ancestor CPU
budget, leaving the rest available to the manager without limiting idle
database burst capacity.

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
