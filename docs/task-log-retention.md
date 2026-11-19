# Task logs after a restart or rolling update

Run on a manager as root; the command reads the task-owning node over the
existing authenticated cluster channel, without SSH to the worker:

```sh
sudo ts-orch service logs ts-terrabase --previous
```

Replace `ts-terrabase` with any service name. `--previous` prints stdout then
stderr from the most recently stopped task with retained logs in that cluster.
It skips tasks that were never assigned a node or never started their logger.
A header identifies the selected task, node, replica slot, terminal state and
stop time. It reads a snapshot and cannot be combined with `-f`. Without
`--previous`, the command reads the newest task, including output written while
it is STARTING. `service ps <name>` lists the retained task IDs and their nodes.
A task on another node is always a snapshot: `-f` follows only a task on the
host where the command runs, and refuses a remote task with the node to run it on.

The runtime uses containerd directly, with the same binary acting as its
`binary-v2` logger. There is no Docker `json-file`, `local` or `journald` driver.
Each task has private files at
`/var/lib/ts-orch/runtime-logs/ts-<task-ID>/{stdout,stderr}`. They survive task
exit, rolling replacement, and reopening the executor and SwarmKit manager.

Retention reuses SwarmKit's existing `TaskHistoryRetentionLimit` of **five tasks
per service slot** (including the current task), or per node for a global
service. Each stream is capped at **1 MiB**, so a settled five-task history
uses at most **10 MiB of log content per slot**, plus filesystem metadata.
Cleanup is asynchronous and can temporarily retain more tasks. Each stream
keeps its startup head (up to 128 KiB) and a recent tail when
its next write would exceed the cap, with a visible gap marker between them.
Compaction reduces the file to at most half the cap before appending new bytes.
This is bounded retained output, not a complete historical transcript or a
time-based guarantee.

The logger holds an exclusive `flock` on the stream file while it rewrites it,
and a remote snapshot reads under a shared lock, so it never sees a half-done
rewrite. A logger started by an earlier release keeps running after an agent
upgrade and does not take the lock; its tasks stay readable, and a snapshot
taken during one of its rewrites can show that stream shorter or empty, as a
local read of the same file can.

When SwarmKit reaps a task, it unassigns it and the executor's `Remove` deletes
its container, snapshot, and log directory. Service removal and scale-down
can also remove task history. The command reports an error when no previous
logs remain, names the node when it is unavailable, and ends a stalled remote
read at 30 seconds. A read error does not fall back to an older task. Manager
control-socket access permits cluster task log reads; the network read RPC
requires a manager certificate. The command cannot recover logs already removed
before this change.

For an older task still listed by `service ps`, read its files directly on its
host, replacing `<task-ID>` with that row's ID:

```sh
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stdout
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stderr
```

The stdout/stderr files remain plain text with their existing root-only access;
no extra listener, port, credential or service setting is introduced.
