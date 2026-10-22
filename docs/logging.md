# Production logs (TS-808)

Status: design for TS-808. It builds on the TS-803
[region registry and subject interface](region-registry.md) and fills the
`errors` section of the TS-805 [global view](dashboard/global-view.md).

Every TerraScale process writes one JSON object per line, with the same keys,
in every region. An operator reading any node of any of 20 regions sees the
same shape, and every region publishes a small summary of what its logs say.
Nothing is configured: no format, level or summary setting exists.

## Record v1

| Key | Content |
| --- | --- |
| `time` | RFC 3339 UTC with fraction |
| `level` | `DEBUG`, `INFO`, `WARN` or `ERROR` |
| `msg` | Constant text: never interpolate values into it |
| `service` | `ts-orchestrator`, `terrabase`, `ts-auth`, ... |
| `region` | Cell token (`gru`, `sjc`), the region registry's name |
| `node` | Host name (`ts-gru-1`, [canonical names](node-names.md)) |
| `process` | ts-orchestrator only: `controller`, `host`, `watchdog`, `netbird-agent`, ... |
| `trace_id` | W3C trace ID (32 lowercase hex) when the record belongs to a request or a loop pass |
| `component` | Feature slice or logger category (`placement`, `nats`, `TerraBase.Replication`) |
| `error` | Error text, when there is one |

Other attributes follow. A key never appears twice in one record.
`cell`, `member` and the process-level `role` are gone: `region`, `node` and
`process` replace them, and `role` is free for a workload role.

### Levels

| Level | Use |
| --- | --- |
| `ERROR` | An operation failed and someone must act. |
| `WARN` | A degraded state that needs attention if it lasts. A retry loop warns once when it starts failing and logs `INFO` when it recovers; each further retry is `DEBUG`. |
| `INFO` | A state change: started, elected, applied, recovered. |
| `DEBUG` | Everything that happens on every pass: probes, health checks, client disconnects, expected cancellation on shutdown, steady-state replication. |

Noise is fixed by lowering its level, never by deleting the record. Production
writes `INFO` and above; `DEBUG` records exist for tests and local runs.

### Where each service gets it

- **ts-orchestrator.** `observability.NewLogger` adds `service`, `region`,
  `node` and `process` to every record and `trace_id` from the context.
  Embedded NATS server output goes through the same handler (`component`
  `nats`), and so do nats.go asynchronous errors (`component`
  `nats-client`, with the subject). Under systemd (`JOURNAL_STREAM` set), each
  line starts with its syslog priority (`<3>` error, `<4>` warning, `<5>`
  notice for `INFO`, `<7>` debug), so the journal's `PRIORITY` matches `level`
  and `journalctl -p warning` works. journald strips the prefix. `INFO` is a
  state change, which is syslog's notice; units that run every few seconds set
  `LogLevelMax=notice` to drop systemd's own per-run lines without losing them.
- **Workloads.** The host agent starts every workload with `TS_SERVICE`
  (its role), `TS_REGION` and `TS_NODE`, outside the signed desired state,
  like `HOME` and `PATH`.
- **.NET services** (TerraBase, ts-auth). `TerraScale.Logging` in ts-libs is
  the one console formatter: record v1 from `TS_*`, `trace_id` from
  `Activity.Current`, single line. Framework categories that log every
  request (`Microsoft.AspNetCore.*`, `System.Net.Http.*`) default to `WARN`.
- **Workers and ts-dashboard** (ts-atlas, ts-status, ts-dashboard). Same
  keys in `console.log(JSON.stringify(...))` or slog; `region` is the
  Cloudflare colo or OCI region, `node` the isolate ID or node name.

## Trace IDs

- A trace starts at an entry point: an HTTP request, a NATS request handler,
  or one pass of a background loop. ts-orchestrator mints the ID from a ULID's
  16 bytes, so IDs sort by time and are valid W3C trace IDs.
- It travels in the W3C `traceparent` header on HTTP and on NATS message
  headers. A receiver continues an incoming trace and starts a new one
  otherwise. .NET continues it natively through `Activity`.
- `slog.InfoContext(ctx, ...)` and the other `Context` variants attach it.
  Code with a context in scope uses them.

## Log summary v1

Each region publishes how many records each service logged per level and
message. It is the dashboard's and the before/after check's single source.

```
node journal --follow--> host agent --1 min--> ts.orch.v1.<cell>.agent.<nkey>.observation.logs
                                                 \-> stream TS_LOG_SUMMARY (25 h) -> every controller's logs.View
logs.View -> ts.orch.v1.<cell>.query.logs.v1 (any region, TS-803 grants)
          -> TS-805 rollup `errors`, `/v1/logs` on the observability listener
```

1. **Read.** Every node's host agent follows its own journal
   (`journalctl --follow -o json`) for `terrascale-*` and `netbird*` units. It
   parses record v1, .NET console, NATS and NetBird lines with one shared
   parser (`internal/logs`), which `ts-orch log-scan` also uses. A class is
   `service`, `level`, `component` and the message with numbers, hex, ULIDs,
   UUIDs and addresses replaced by `N`.
2. **Count.** Per minute, the agent counts records per class at every level,
   keeps one redacted example (512 bytes) per class, and keeps the 128 classes
   with the most records. The rest add up in `dropped`.
3. **Publish.** At each minute boundary the agent publishes one window on its
   own observation subject. The host credential already grants it; the
   subject carries the host's NKey, so a host cannot speak for another node.
   A window is at most 64 KB.
4. **Keep.** `TS_LOG_SUMMARY` captures `ts.orch.v1.<cell>.agent.*.observation.logs`:
   file-backed, the cell's replica count, 25 hours, 256 MiB, discard old.
   It is ts-orchestrator's bootstrap-layer data, like the host metric archive.
5. **View.** Every controller replays the stream and keeps the last 24 hours
   in hourly buckets per class, at most 2,048 classes per region. A window
   whose NKey does not match the node's registration is ignored. Restart and
   leadership changes lose nothing.

Window v1 (JSON):
`{"v":1,"region","node","minute":RFC3339,"boot":ULID,"seq":n,"classes":[{"service","level","component","message","count","example"}],"dropped":n}`.
A new `boot` is an agent restart; a gap in `seq` within one boot is a lost
minute and is reported as such.

### Query `logs.v1`

`ts.orch.v1.<cell>.query.logs.v1`, every controller in queue group `logs`:

- Request: `{"v":1,"window":"1h"|"24h","min_level":"WARN","service":"","limit":50}`,
  decoded strictly. `limit` is at most 500.
- Reply: `{"v":1,"region","from","to","totals":[{"service","level","count"}],"classes":[{"service","level","component","message","count","nodes":[...],"first","last","example"}],"gaps":n,"truncated":bool}`,
  classes sorted by count.

Any region's controller can ask any other region through the TS-803
controller grant `ts.orch.v1.*.query.>`. `GET /v1/logs` on the observability
listener returns the same reply for the local region.

### Global view

TS-805's rollup section `errors` (at most 10) comes from `logs.View.Errors`:
the `ERROR` and `WARN` classes of the last hour by count, each with its last
time, nodes and component. It does no I/O.

## Before and after

`ts-orch log-scan --since 24h` reads every node's journal over NetBird SSH
and prints counts per service, node and level and the top classes. TS-808
posts its output before the fixes and after they reach GRU and SJC.

## Slices

1. This design.
2. Record v1 in ts-orchestrator: logger keys, journal priority, embedded NATS
   and nats.go output, workload `TS_*` environment, and the recurring noise
   found in GRU and SJC.
3. Trace IDs: `traceparent` on HTTP and NATS, loop passes, `Context` calls.
4. Log summary: `internal/logs`, the host follower and windows, the stream,
   `logs.View`, `query.logs.v1`, `/v1/logs` and the `errors` source.
5. `TerraScale.Logging` in ts-libs, then TerraBase and ts-auth adopt it and
   fix their recurring warnings; ts-dashboard, ts-atlas and ts-status follow.
