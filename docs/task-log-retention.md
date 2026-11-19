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
stop time. It reads a snapshot and cannot be combined with `-f`. Without `--previous`, the command keeps its
selection of the newest task, including output written while it is STARTING.
`service ps <name>` lists the retained task IDs and their nodes. Local tasks
keep their existing file read and follow behavior.

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

Current loggers synchronize remote snapshots so they cannot observe an
in-progress rewrite. Remote follow uses a private cursor on the same file
to deliver unread head and tail bytes without replaying prior output. If compaction
drops unread bytes, follow prints an `output gap` marker with the stream name
and number of dropped bytes before resuming from the retained tail. An
incomplete rewrite or file-read failure is reported to the reader. Tasks
started by an older logger remain readable as snapshots; remote follow reports
that the task must have been started by the current release to supply its
compaction cursor. Local follow retains its existing behavior.

When SwarmKit reaps a task, it unassigns it and the executor's `Remove` deletes
its container, snapshot, and log directory. Service removal and scale-down
can also remove task history. The command reports an error when no previous
logs remain. It also reports unavailable/disconnected owners, including during
remote follow; a stalled snapshot is bounded at 30 seconds. A slow subscriber
ends with an overflow error. Each subscriber queues at most 256 publications,
each capped at 64 KiB (16 MiB plus bounded in-flight transport data). An error
can follow already-printed output and does not cause selection of an older
task. Manager control-socket access permits cluster task log reads; the network
read RPC requires a manager certificate. The command cannot recover logs
already removed before this change.

For an older task still listed by `service ps`, read its files directly on its
host, replacing `<task-ID>` with that row's ID:

```sh
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stdout
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stderr
```

The stdout/stderr files remain plain text with their existing root-only access.
The logger stores its compaction cursor in a private file extended attribute;
no extra listener, port, credential or service setting is introduced.
