# Capacity usage and benchmarks (TS-761, Slice 4)

## Usage API

`GET /v1/usage?region=gru&from=<RFC3339>&to=<RFC3339>` serves node, service
and individual replica CPU/memory from authenticated host reports. It mounts
on the existing private observability listener and the spec-controlled
NetBird dashboard listener. The listener must have its bearer token configured;
tokenless loopback access to this API is disabled. Existing dashboard sessions
retain their authenticated access. No public port or new controller credential
grant is introduced.

The current authority leader receives host reports. The CLI tries all three
regional controllers and selects a complete answer; otherwise it returns the
best partial answer with `complete: false`. It queries the configured regional
controllers concurrently; a complete answer cancels the remaining requests.
Each request has a fifteen-second timeout within the caller's deadline, so
two unavailable controllers cannot consume the runner's thirty-second usage
deadline before a healthy third is queried. Followers have no host history.
Windows must be increasing RFC3339 timestamps within the last hour. History
is bounded, in memory and rebuilt after a controller restart or leadership
change. Missing registered nodes and active allocations are listed in `missing`.
Expected nodes and allocations come from timestamped committed control-log
history over `[from, to)`, including the state immediately before `from`.
Later admissions do not enter an older window; later withdrawals do not erase
missing replicas from it. Retirement and unretirement are fenced ordered-log
commits with JetStream timestamps. Hosts retired before the window are excluded; retiring
or restoring an identity later cannot rewrite an earlier answer. An idle check
must succeed in the same authority epoch before retirement is committed.
Admission checks and historical inventory read the same retirement records.
Host control rejects obsolete `retired.<cell>.<node>` keys unless an operator
has explicitly pinned an active mark as a permanent identity quarantine.
Cleared, malformed, changed or missing evidence still fails closed. The
[retirement storage upgrade](retirement-storage-upgrade.md) retains the active
KV mark, imports a fenced ordered event, and requires explicit fleet cutover
before ordinary retirement writes resume. It never deletes active safety
marks or re-founds a serving cell. Inventory before the actual import commit
is unavailable; the legacy timestamp is not invented ordered-log history.
A startup baseline reads only the latest state per host subject; a five-second
refresh caches one hour of incremental changes.
Usage queries advance this checkpoint to a pinned log watermark, without
replaying lifetime mutations. Windows preceding startup or an expired baseline
are unavailable. A checkpoint idle for an hour is reseeded from latest state.
Reads have a ten-second deadline; unavailable or oversized inventory returns HTTP 503.
Missing values stay JSON `null`; they never become zero usage or spare capacity.

Each resource contains `usage`, `request`, `limit` and `headroom` statistics:
mean, minimum, maximum, timestamps, sample count and
coverage. CPU units are cores; memory units are bytes. Node memory comes from
`MemTotal - MemAvailable`; service memory is cgroup working set, excluding
inactive file pages. Requests come from the adopted signed workload profiles.
The sampler reads `cpu.max` and resolves the smallest finite `memory.max`
from the role through its cgroup ancestors, bounded by physical RAM. A role
with no finite memory cap in that hierarchy uses physical host capacity.
Unreadable or malformed ancestors leave limits unknown. Limits are caps, not a
reservation of shared ancestor capacity. Node requests include every registered,
non-withdrawn allocation even when its process is stopped or its cgroup cannot
be read. Such replicas retain their signed requests and unknown usage/limits;
they remain listed as missing measurements. Unknown adopted requests leave
node reservation totals unknown.

Raw history retains individual host samples. Queries use `[from, to)` bounds.
Series idle for more than one hour release their slots before new measurements
are admitted, so departed node, environment and role identities cannot consume
the 4,096-series budget for fourteen days.
Node and replica rows summarize samples only during their historical active
intervals; coverage requires at least two samples per active interval, with no
gap larger than one quarter of that interval (bounded to 10–60 seconds).
Service statistics align replica measurements with admission, allocation,
withdrawal and retirement intervals. Samples hold until the next measurement,
for at most the coverage gap; the first sample may extend back to the active
interval's start within the same gap. Inactive replicas contribute zero, so a
1-core replica replaced halfway through a window still yields a 1-core service
mean. Service means integrate aligned totals over the full requested window;
their minimum and maximum describe those aligned totals. JSON additionally
provides `max_upper_bound`, the sum of individual replica maxima, because
replica peaks can occur at different times. Missing active measurements leave
that service statistic `null`, including when an interior gap exceeds the hold
limit; they never become zero contributions. Service timestamps describe the
integration window, while node/replica timestamps describe their first/last
measurements. Inspect `replicas` for individual values.
Truncation or missing usage, requests or limits makes the
window incomplete. Dropped-series coverage is tracked for the queried hour,
conservatively rounded to minutes; healthy later windows recover without a
controller restart. Longer configured telemetry intervals can therefore
produce incomplete benchmark windows.
Service coverage additionally requires a positive overlapping observed range
for each concurrently active group. Sequential replicas are evaluated during
their own lifetimes; known inactive gaps remain complete zero intervals.
Capacity history limits never reject an otherwise accepted autoscaler report;
both consumers record independently.

Hosts default to a fifteen-second telemetry interval; an explicit
`host.load_telemetry_seconds` chooses 5–3600 seconds, and `0` disables reporting.
For short benchmark stages, configure 5–10 second reporting to cover the
measurement window densely. Capacity collection does
not enable autoscaling. Its existing `controller.autoscale.host_telemetry`
gate is preserved. Update the binary in place through the normal release
channel. A serving cell is never re-founded to enable this feature.

```sh
nice -n 19 ts-orch usage --region gru --from 2026-10-08T18:00:00Z --to 2026-10-08T18:10:00Z
nice -n 19 ts-orch usage --region sfo --from 2026-10-08T18:00:00Z --to 2026-10-08T18:10:00Z --format json
```

The default config is `~/.config/ts-orch/benchmark.json`; `--config` selects
another file. Only its regional `usage_urls` and `usage_token` entries are
needed for usage. An explicit `--url` overrides regional discovery. For
read-only automation, `--token-vault` and `--token-name` can select a Vault
secret directly, or `--token-file` can name a private regular token file.
Vault reads use the operator's OCI profile and never print secret values.

The table shows mean used/request/limit and minimum headroom (memory in MiB).
`?` means unknown, `*` means incomplete coverage. JSON includes the full
statistics and replica rows for Slice 1 to attach to its run.

## Benchmark runner

```sh
nice -n 19 ts-orch bench run --region gru --workload point-reads --clients go,dotnet,rust
nice -n 19 ts-orch bench run --region sfo --workload ramp --clients go,dotnet,rust
```

The config points to Slice 1's `ts-benchmark/workloads` directory and to
digest-pinned client images that are already loaded on a dedicated regional
generator. Each selected image's entrypoint is `bench-client`; it accepts the
shared `run --workload /dev/stdin --region ... --out /dev/stdout` CLI.
Credentials are resolved from OCI Vault on the generator using its instance
principal and passed as `TS_BENCH_CLIENT_ID` / `TS_BENCH_CLIENT_SECRET` through
an inherited environment pipe. They never enter argv, logs or files.

Each generator must be an existing non-serving OCI instance tagged
`ts-benchmark=load-generator` and `ts-benchmark-region=gru|sfo`. Cell names,
cell/pool tags and all `terrascale-*` ownership tags are rejected, including
drained serving nodes. The parent verifies the SSH address against the
instance's private VNIC IP. The worker independently verifies its IMDS
identity and OCI tags and refuses a host running TerraBase, ts-auth, NATS or
an orchestrator controller/host role. `mariogk-desktop` is forbidden.
SSH requires an existing trusted host key; it never accepts new keys
automatically. The generator needs Podman and this `ts-orch` binary installed
at `worker_path`. The feature does not launch or enroll serving-cell nodes.

Clients run concurrently in containers with read-only root filesystems,
tmpfs scratch, no capabilities, 1 CPU, 1 GiB memory and 256 processes each.
No images are pulled, named volumes created or credentials written to disk.
Each container has a fresh ULID name and ownership label. Cleanup stops and
removes only these owned containers with a fresh context after cancellation
or malformed output. Clients stop concurrently within a shared 90-second
cleanup deadline, so each receives SIGINT and a 30-second shutdown reserve
for their SDK database cleanup. On cancellation the parent sends a control
message and keeps SSH open to drain results until the worker acknowledges
owned-container cleanup. Missing or failed acknowledgement fails the run;
the parent terminates SSH after a 120-second cleanup reserve. Stdin EOF,
SIGINT, SIGTERM and SIGHUP cancel the remote job, and broken stdout returns
an error without skipping cleanup. Container and remote worker timeouts
bound orphaned execution. Measurement plus warmup is capped at 780 seconds,
leaving 60 seconds for client startup, summary emission and database cleanup
inside the 840-second container lifetime. The end-to-end load deadline is
15 minutes; resource cleanup has a separate bounded reserve. Client database cleanup remains
part of the shared client contract and requires integration validation.

The runner validates client, region, operation, timestamps and percentiles.
Required JSONL fields must be present and non-null, including zero-valued
latency/error fields. Failed initial or final run saves return a failed, ended, unqualified
run with an unknown scaling recommendation in the CLI and local report.
It streams each JSONL record and saves it through the public Go SDK. Validation
and safety checks enqueue results without waiting for storage or operator
output. One consumer preserves order, with a 256-record queue and a 30-second
deadline per save. Queue overflow cancels load and fails the run. Pending results
must drain before usage and final run persistence, within 30 seconds after
generator cleanup. A blocked output writer cannot be forcibly interrupted;
drain timeout fails the CLI run and cancels remaining saves. Output failure or
drain timeout still saves the local report and skips subsequent writes to the
unavailable output. Every
run is a plain ULID. The `benchmark` database has `runs`, `results` and
`usage` collections; results and usage refer to `run_id` and stage number.
Run metadata includes the final capacity verdict, not duplicate raw result
history. Failures retain their run record. Reports append to
`reports/<region>/<date>-<workload>.md`, preserving previous runs that day.

`ramp` doubles concurrency from one up to the workload's configured maximum,
dividing `duration_s` across steps with at least 30 seconds per step. Each
step has its own `warmup_s`; measurement and warmups together must fit within
780 seconds. Clients emit per-second intervals during warmup as well as measurement.
The worker carries each client's first reporting timestamp plus `warmup_s`
in a private measurement-start marker before forwarding its samples. The
runner saves these per-client boundaries in stage metadata, excludes earlier
intervals from qualification, and keeps controls out of shared JSONL results.
Each client's measurement window ends after the stage's configured duration;
samples at or after that boundary leave qualification incomplete.
CPU/memory usage is queried over the common measurement window: the latest
client start through the earliest client end, bounded by stage completion.
Startup, warmup and cleanup stay outside the verdict's usage window. A safety
stop records its cancellation time before persistence/output and truncates
the usage window there. Without a common measured interval, usage and the
capacity verdict remain unknown; no usage query is issued.
OCI/SSH/Vault startup and different container start times cannot shift warmup.
Missing, repeated or contradictory timing markers fail the run. Every run stops immediately
when an emitted operation has error rate above 1% or p99 above twice target.
Safety cancellation precedes enqueueing the triggering result; pending saves
use deadlines independent of load cancellation. Storage, output and cleanup
failures remain failures even when a safety threshold also stopped the run.
A qualified stage needs complete regional usage, at least 30 seconds of
per-client measurements, the configured measurement duration, all client
summaries with exactly the workload's operation keys, successful measurement
interval coverage and successful measurement evidence for every client/operation,
error rate at most 1% and measured p99
at target. Percentiles are
checked per client/operation; they are never averaged. The capacity figure
is the sum of measured client counts divided by the full configured measurement
duration for the highest qualifying stage. Missing intervals consume time in
that denominator; each summary must agree with its measured rate within 5%.
Every client/operation must cover at least 30 measurement intervals and all but
two configured seconds, with no gap above two seconds. Explicit zero-count
intervals preserve coverage; absent records do not. Repeated records inside
one client/operation interval fail the run and cannot inflate counts.
Node or service headroom below 20% identifies CPU or memory pressure; more than 60%
CPU and memory headroom permits a scale-down recommendation only when the
final stage qualifies. An earlier qualifying stage retains its maximum
sustained throughput even when a later ramp stage fails latency. Measured
latency/error pressure recommends up; sufficient headroom otherwise reports ok.
Insufficient duration, missing successful operations or summaries, timestamp
gaps and throughput disagreement leave bottleneck and scale unknown, preserving
any earlier qualifying maximum. An explicit safety stop remains measured
pressure despite its truncated evidence. An incomplete telemetry window or
failed run reports `qualified: false` and `scale: unknown`, never a safe
scale-down. These are recommendations; the benchmark never changes serving
capacity. Generator saturation has not been qualified on live hardware.

## Config shape

All secret entries below are **references**, not secret values. A usage-only
config can omit generator, clients and storage fields. Configure SFO with its
own regional generator and Vault references.

```json
{
  "workloads_directory": "/path/to/ts-benchmark/workloads",
  "regions": {
    "gru": {
      "usage_urls": ["http://ts-gru-1.nb.ts.internal:9463", "http://ts-gru-2.nb.ts.internal:9463", "http://ts-gru-3.nb.ts.internal:9463"],
      "usage_token": {"vault": "<regional-vault-ocid>", "name": "gru-1-orch-dashboard-token"},
      "generator": {"instance_id": "<non-serving-instance-ocid>", "address": "<private-vnic-ip>", "user": "ubuntu", "worker_path": "/usr/local/bin/ts-orch"},
      "images": {"go": "<registry>/bench-go@sha256:<digest>", "dotnet": "<registry>/bench-dotnet@sha256:<digest>", "rust": "<registry>/bench-rust@sha256:<digest>"},
      "client_id": {"vault": "<regional-vault-ocid>", "name": "gru-bench-client-id"},
      "client_secret": {"vault": "<regional-vault-ocid>", "name": "gru-bench-client-secret"},
      "auth_origin": "https://auth.terrascale.tech",
      "auth_tenant": "terrascale",
      "storage_origin": "https://gru.api.terrascale.tech",
      "storage_project": "<plain-ulid>",
      "storage_key": {"vault": "<regional-vault-ocid>", "name": "gru-bench-storage-key"}
    }
  }
}
```

The generator's instance-principal policy should read only its two benchmark
credential secrets and its own instance/VNIC metadata. The operator profile
needs regional dashboard and storage secret reads and generator inspection.
The storage credential is separate from the clients' throwaway-database
identity. Provision a dedicated benchmarking ts-auth client before a live
run; automatic provisioning is not implemented while the public SDK contract
is blocked.

## Current integration blockers and cost

The pinned public Go SDK, `ts-go@e534e7feb91f`, rejects plain ULID project IDs
before any HTTP request. The storage adapter returns `SDK_BLOCKED`; it never
converts IDs to UUIDs or bypasses the SDK. The public SDK's database lifecycle
also needs alignment with the shared JWT client contract. The Rust client's
[Slice 3 draft](https://git.terrascale.tech/TerraScale/ts-benchmark/pulls/12)
records corresponding ULID, database-delete and indexed-query blockers.
Slice 1's shared workloads/images are not published in the observed checkout.
SDK persistence and client database cleanup are therefore not live-qualified;
those contracts must be exercised together before a complete GRU/SFO run.

Read-only OCI inventory on 2026-10-08 found three serving controllers and
`ts-ops` in GRU, and three serving controllers in SFO. There was no dedicated
benchmark generator. No benchmark ran, no temporary instance was created,
no serving cell was changed, and measured throughput/latency are unavailable.
Temporary-instance cost for this work: **USD 0.00**. This implementation uses
existing non-serving hosts; their ongoing host charges are not a temporary
instance charge. Supplying or provisioning dedicated regional capacity and
published client images is required before live validation.
