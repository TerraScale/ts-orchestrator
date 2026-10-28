# Runtime cgroup visibility

Generic service containers get a private cgroup namespace and a read-only
`/sys/fs/cgroup` mount. On cgroup v2 hosts, the container sees its own cgroup at
`0::/` and can read its CPU and memory limits without seeing the host tree.
The existing CPU, memory, swap and PID limits remain unchanged.

This affects newly created generic containers, including TerraBase, ts-auth,
dashboard and canaries. Existing containers retain their original spec until
recreated. NetBird foundation components build a separate spec and are outside
this change. Stateful `ts-db-*` members use a separately pinned spec that replaces
namespaces and mounts; this change does not update that spec.

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
The mountinfo check establishes read-only mounting; a write refusal alone does
not, because the non-root process also lacks ownership of the CPU-limit file.
The existing merge-group containerd lane selects this test; ordinary test runs
without `-containerd-socket` skip it and do not qualify the runtime behavior.

Independent qualification at `0346e0c3f7ea0ecad491009a4fd7022bc4a5b94b` passed
the five CI-selected containerd scenarios on delta (Linux amd64, cgroup v2), using
containerd 2.4.2 and runc 1.3.4 in a disposable daemon. Restoring only the baseline
controller made the new cgroup arm fail. An additional review-only check confirmed
the host still reads the full task cgroup path and unchanged resource limits.
Format, vet and Fast passed at that head. This does not qualify arm64 containerd,
the merge-group lane, or production application budgets.

Before production recreation, qualify the real-containerd test and review the
fleet effects above. After an approved first recreation, record TerraBase's
observed CPU count, memory budget, reservation headroom, pressure signals,
`memory.events`, and readiness before continuing. Host-side limit verification
must still resolve the task's full cgroup path. This change alone establishes no
performance improvement and does not qualify a GC experiment.
