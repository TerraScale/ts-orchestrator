# Runtime cgroup visibility

Generic service containers get a private cgroup namespace and a read-only
`/sys/fs/cgroup` mount. On cgroup v2 hosts, the container sees its own cgroup at
`0::/` and can read its CPU and memory limits without seeing the host tree.
The existing CPU, memory, swap and PID limits remain unchanged.

This affects newly created generic containers, including TerraBase, ts-auth,
dashboard, NetBird and canaries. Existing containers retain their original spec
until recreated. Stateful `ts-db-*` members use a separately pinned spec that
replaces namespaces and mounts; this change does not update that spec.

Runtime discovery changes application behavior even though enforcement is
unchanged. For TerraBase's current one-CPU, 4 GiB containers, the expected CPU
count becomes one. Default storage workers, pool sizing, usage stripes, memory
budget, cache capacity and pressure denominators can change. The resulting
memory budget must be measured rather than assumed. Current reservations and
unreserved memory need sufficient headroom under that budget.

`TestContainerdBindMountSurvivesTaskRestart` checks the generic controller using
a real non-root container with a 0.25-CPU quota and a 64 MiB memory limit. Its
cgroup arm requires a private namespace, exact visible limits, a read-only
cgroup2 mount, no host `system.slice`, and a refused write to the CPU limit.
The existing merge-group containerd lane selects this test; ordinary test runs
without `-containerd-socket` skip it and do not qualify the runtime behavior.

Before production recreation, qualify the real-containerd test and review the
fleet effects above. After an approved first recreation, record TerraBase's
observed CPU count, memory budget, reservation headroom, pressure signals,
`memory.events`, and readiness before continuing. Host-side limit verification
must still resolve the task's full cgroup path. This change alone establishes no
performance improvement and does not qualify a GC experiment.
