# Task logs after a restart or rolling update

Connect to the affected host through `ts-orch netbird ssh`. On that host:

```sh
sudo ts-orch service logs ts-terrabase --previous
```

Replace `ts-terrabase` with any service name. `--previous` prints stdout then
stderr from the most recently stopped task that has logs on this host. It skips
tasks that were rejected before their logger started. A header identifies the
selected task, node, replica slot, terminal state and stop time. It reads a snapshot and
cannot be combined with `-f`. Without `--previous`, the command keeps its
existing behavior of reading the newest task. `service ps <name>` lists the
retained task IDs and their nodes; read logs on the node that ran the task.

The runtime uses containerd directly, with the same binary acting as its
`binary-v2` logger. There is no Docker `json-file`, `local` or `journald` driver.
Each task has private files at
`/var/lib/ts-orch/runtime-logs/ts-<task-ID>/{stdout,stderr}`. They survive task
exit, rolling replacement, and reopening the executor and SwarmKit manager.

Retention reuses SwarmKit's existing `TaskHistoryRetentionLimit` of **five tasks
per service slot** (including the current task), or per node for a global
service. Each stream is capped at **1 MiB**, so a settled five-task history
uses at most **10 MiB of log content per slot**, plus filesystem metadata.
Cleanup is asynchronous and can temporarily retain more tasks. Each stream is
truncated when its next write would exceed the cap; immediately after rollover
it may contain only the last read (up to 16 KiB). This is bounded recent output,
not a complete historical transcript or a time-based guarantee.

When SwarmKit reaps a task, it unassigns it and the executor's `Remove` deletes
its container, snapshot, and log directory. Service removal and scale-down
can also remove task history. The command reports an error when no previous
local logs remain. It cannot recover logs already removed before this change.

For an older task still listed by `service ps`, read its files directly on its
host, replacing `<task-ID>` with that row's ID:

```sh
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stdout
sudo cat /var/lib/ts-orch/runtime-logs/ts-<task-ID>/stderr
```

No storage format, service spec, retention setting, or authentication changes
are introduced. Files retain their existing root-only access.
