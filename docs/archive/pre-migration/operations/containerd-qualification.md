# Local containerd qualification

The opt-in `ContainerdLiveTests` exercise the production
`NerdctlContainerdClient` and adapter against a real, disposable containerd
daemon. The harness builds a synthetic OCI image around a static busybox and
serves it from a loopback registry. It does not build or run ts-auth itself.

The tested tool set is nerdctl 2.3.0, containerd 2.3.3, runc 1.4.3, CNI plugins
1.9.0 and busybox 1.37.0 on Linux x64 with systemd and cgroup v2. OCI ARM64
workload images, registry authentication, mounted secrets, service readiness,
network policy and host enrollment require separate qualification.

Build as the normal workspace user at reduced local priority:

```sh
nice -n 19 dotnet build tests/TerraScale.Orchestrator.Tests -c Release --no-restore
```

Run the harness with explicit executable paths. `--busybox` must point to a
statically linked busybox that includes `sleep` and `touch`. Use a real Python
interpreter path, not a user tool-manager shim. Replace the paths below with
the installed tools and the compiled TUnit executable; no local cloud
credentials are needed.

```sh
sudo -n env DOTNET_ROOT=/path/to/dotnet \
  nice -n 19 unshare --net --mount --propagation private \
  /path/to/python3 scripts/qualify-containerd.py \
  --test /path/to/TerraScale.Orchestrator.Tests \
  --nerdctl /path/to/nerdctl \
  --containerd /path/to/containerd \
  --runc /path/to/runc \
  --cni /path/to/cni/bin \
  --busybox /path/to/static/busybox
```

The harness refuses the host's network or mount namespace. Its registry,
bridge, daemon socket, runtime roots and CNI allocation directory are private
to the rehearsal. The wrapper adds only those isolation settings to nerdctl;
create/start/inspect/stop/delete arguments come from the production client.
It does not disable seccomp, Linux capabilities, cgroups, or digest checking.
Systemd owns the test's temporary cgroup slice on the host.

The tests cover pinned image delivery, canonical security/resource settings,
repeat convergence without restart, explicit stop/restart, wrong-plan rejection,
rejection of a foreign image carrying forged admission labels, and deletion.
They inspect kernel UID, capabilities, no-new-privileges, seccomp, memory/swap
and PID limits. Process-running evidence is not application-ready evidence.

The printed `/tmp/ts-oci-containerd-*` directory retains private daemon/client
logs, TUnit results and `receipt.json`. Successful cleanup verifies that the
daemon has no remaining containers before shutting it down and removing its
storage. A failed test remains a failed receipt even if cleanup succeeds.
The lane is explicitly skipped in ordinary test runs; it must be run and its
receipt retained for release qualification.

Production plans use nerdctl's `builtin` seccomp profile and an explicit
systemd cgroup manager with a `terrascale-<allocation>.slice` parent. Deployments
must pin and qualify their runtime tools: the built-in seccomp policy belongs
to the installed nerdctl/containerd versions. There is no implicit custom
`terrascale-default-v1` profile file.
