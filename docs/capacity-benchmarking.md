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
best partial answer with `complete: false`. Followers have no host history.
Windows must be increasing RFC3339 timestamps within the last hour. History
is bounded, in memory and rebuilt after a controller restart or leadership
change. Missing registered nodes and active allocations are listed in `missing`.
Missing values stay JSON `null`; they never become zero usage or spare capacity.

Each resource contains `usage`, `request`, `limit` and `headroom` statistics:
sample mean, minimum, maximum, first/last bucket timestamps, sample count and
coverage. CPU units are cores; memory units are bytes. Node memory comes from
`MemTotal - MemAvailable`; service memory is cgroup working set, excluding
inactive file pages. Requests come from the adopted signed workload profiles.
The sampler reads `cpu.max` and `memory.max`; an unlimited role uses physical
host capacity for effective headroom. Limits are per-role cgroup caps, not a
reservation of shared ancestor capacity. Node requests cover reporting,
currently allocated roles; missing allocations make the answer incomplete.

Raw buckets are five seconds. Coverage requires at least two buckets, with no
gap larger than one quarter of the query window (bounded to 10–60 seconds).
Service totals sum replica means. Their summed maxima are a conservative
upper bound, and summed minimum headroom is a conservative lower bound;
replica peaks need not occur at the same instant. Inspect `replicas` for
individual values. Truncation or missing usage, requests or limits makes the
window incomplete. Longer configured telemetry intervals can therefore
produce incomplete benchmark windows.

Hosts default to a ten-second telemetry interval; an explicit
`host.load_telemetry_seconds` chooses 5–3600 seconds. Capacity collection does
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
or malformed output. Clients receive SIGINT and a 30-second shutdown reserve
for their SDK database cleanup. Container and remote worker timeouts bound
orphaned execution. The end-to-end load deadline is 15 minutes; resource
cleanup has a separate bounded reserve. Client database cleanup remains
part of the shared client contract and requires integration validation.

The runner validates client, region, operation, timestamps and percentiles;
it streams each JSONL record and saves it through the public Go SDK. Every
run is a plain ULID. The `benchmark` database has `runs`, `results` and
`usage` collections; results and usage refer to `run_id` and stage number.
Run metadata includes the final capacity verdict, not duplicate raw result
history. Failures retain their run record. Reports append to
`reports/<region>/<date>-<workload>.md`, preserving previous runs that day.

`ramp` doubles concurrency from one up to the workload's configured maximum,
running the same shared workload at each step. Every run stops immediately
when an emitted operation has error rate above 1% or p99 above twice target.
A qualified stage needs complete regional usage, at least 30 seconds of
per-client measurements, the configured measurement duration, all client
summaries, error rate at most 1% and measured p99 at target. Percentiles are
checked per client/operation; they are never averaged. The capacity figure
is the sum of client summary throughput for the highest qualifying stage.
Node headroom below 20% identifies CPU or memory pressure; more than 60%
CPU and memory headroom permits a scale-down recommendation. Otherwise the
recommendation is up for latency/errors, or ok. An incomplete window or
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
this slice remains draft until those contracts can be exercised together.

Read-only OCI inventory on 2026-10-08 found three serving controllers and
`ts-ops` in GRU, and three serving controllers in SFO. There was no dedicated
benchmark generator. No benchmark ran, no temporary instance was created,
no serving cell was changed, and measured throughput/latency are unavailable.
Temporary-instance cost for this work: **USD 0.00**. This implementation uses
existing non-serving hosts; their ongoing host charges are not a temporary
instance charge. Supplying or provisioning dedicated regional capacity and
published client images is required before live validation.
