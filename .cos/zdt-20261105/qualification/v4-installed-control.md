# Installed fleet-stop check — HOLD

No usable **cold TerraBase fleet stop** exists in the installed command path.
`ts-orch service rm terrabase` exists and removes the desired service fleet-wide,
but cannot establish physical exit of the last live node in a region. Do not run
that production command as a substitute for a process-stop barrier.

Read-only SJC readback identified `/usr/local/bin/ts-orch` as clean revision
`2142b1f308b1c1169d25093f93eab3b10c479e1c`, linux/arm64, SHA256
`214b1e2791692bca33e9b6d9b554aab9346aaabba034285606e865d6703c4146`.
Actual `--help`, `service --help` and `member --help` show:

```
ts-orch service apply -f <spec.json> [--hold-after <region>]
ts-orch service resume <name>
ts-orch service ls
ts-orch service rm <name>
ts-orch service ps <name>
ts-orch service logs [-f | --previous] <name>
ts-orch service inspect <name>
ts-orch member ls
ts-orch member leave <hostname>
ts-orch member drain <hostname>
ts-orch member activate <hostname>
```

There is no service scale CLI. `ServiceSpec.SwarmSpec` rejects replicas below 1.
Changing service replicas directly through an invented RPC is not this installed
operator interface and would still use the same task-stop lifecycle.

## Disposable command qualification

Executed only through `ts-heavy-any` on mariogk-dev against **installed revision**
2142b1f, without overlaying the new bootstrap/rollout implementation:

- Actual `runServiceCLI`: help → `apply -f disposable.json` → `ls` → `ps` →
  `rm zdt-cold-disposable` → `ls` and task lifecycle convergence: PASS, 1.595s
  package wall. Real embedded Swarm manager/Raft/scheduler/agent, lifecycle fixture;
  no containerd/TerraBase physical-exit claim.
- Actual `mesh.Remove` called by fleet CLI removal: PASS in the existing real
  three-region NATS/TLS/JetStream integration, 10.169s package wall. The appliers
  are contract fixtures. Removal reached all regions, including ones not targeted
  by the preceding region-specific service declaration.
- Actual `Edge.DrainRegionalNode`: PASS, 0.059s package wall. Last live owner with
  one admitted node refuses `replacement has no admitted regional peer`; with
  two admitted nodes and the other unavailable it refuses `regional prime HTTP
  503`. HTTP-only TerraBase contract fixtures; no engine binary.

`installed-control/` retains the two diagnostic fixture sources and exact runner.
`v4-installed-control.log` is the passing full output; JSON records source/file/log
hashes. Two earlier fixture mistakes (unexpected-prime assertion and an inserted
newline in Go syntax) were corrected before the passing run; they were not
production failures or successful proof. No product behavior was changed by these
fixtures and no tests were added to a Fast suite.

## Why removal is insufficient

At the exact installed source revision:

1. `internal/app/service_cli.go`: `rm` → `mesh.Remove`.
2. `internal/natscell/mesh/cli.go`: new removal generation → every ordered region.
3. `internal/natscell/mesh/run.go`: applier → `RemoveServiceSpec`.
4. `internal/swarmruntime/service.go`: submits Swarm `RemoveService`, then returns;
   acknowledgement is not process exit.
5. `internal/swarmruntime/controller.go`: live regional `stopTask` calls
   `handoff.DrainTask` **before TERM** and retries temporarily on refusal. Mounted
   data `Remove` invokes that same `stopTask` before deleting the runtime task.
6. `internal/edge/regional.go`: drain requires a different admitted, ready writer,
   including a completed source drain and applied-position handoff. It has no cold
   last-node bypass in the installed build.

Even if one removal completes, the last node cannot prove a live surviving peer.
A concurrent fleet removal does not remove that requirement and could invoke the
old handoff/collision path. Member drain/leave schedules the same lifecycle.
The proposed new scoped pinned bypass is not installed, so it cannot bootstrap
its own installation. A disconnected status row is not a PID or shim exit proof.

DECISION: Hold the window and request the prescribed fallback decision. Reason:
installed fleet removal changes intent but cannot safely stop all regional engines.

The user-approved temporary worker SSH fallback would provide the missing exact
systemd/PID, file-inventory/backup and 60-second process-watch access. It is **not
authorized or installed**. No production mutation, service removal, key deletion,
restart, publication, load, workflow enable or new credential occurred.
