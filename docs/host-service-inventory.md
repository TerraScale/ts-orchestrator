# Host services and SwarmKit ownership

C15 inventory, observed on `ts-gru-1` on 2026-11-16. No additional production
workload qualifies for conversion without moving state or taking responsibility
for booting, repairing or identifying the host away from the host. This change
documents ownership and removes obsolete cold-maintenance tooling; it moves no
process, state, port, hostname or secret.

Prometheus, Alertmanager and alert delivery explicitly stay outside SwarmKit:
monitoring must keep paging when SwarmKit itself is broken. Keeping their host
state also avoids a migration. This is the COS decision for C15.

## Scope and evidence

Reviewed `deploy/m1`, `internal/regionhost/cloudinit.go`, the production node
entry points in `internal/app/app.go` and `internal/app/node.go`, the service
specs, and `internal/swarmruntime`. There is no `internal/nodeinit` directory on
this base; `internal/regionhost` installs new nodes and `app.RunNode` starts them.

Production inspection was read-only, through delta:

```sh
cos-ssh delta 'ssh ts-gru-1 "systemctl list-units --type=service,timer --no-pager"'
cos-ssh delta 'ssh ts-gru-1 "systemctl list-unit-files --type=service,timer --no-pager"'
cos-ssh delta 'ssh ts-gru-1 "sudo /usr/local/bin/ts-orch service ls"'
cos-ssh delta 'ssh ts-gru-1 "sudo /usr/local/bin/ts-orch status"'
```

The first command listed 84 loaded services and timers. Installed unit files,
cron filenames, `/etc/crontab` command names and the user crontab directory were
also inspected. No user crontabs were present. This is a one-host observation,
not a claim that every host has an identical OS installation.

`status` returned `gru: ok`, `sjc: ok` and `fra: ok`, with completed pull rollouts
on revision `3f3f17eaaca84fd73d2c95683171df2a924a68da`. This is observation of
the installed release, not a rollout performed for this inventory.

## Platform host responsibilities

| Process or unit | Disposition | Reason and source |
| --- | --- | --- |
| `ts-orch.service` (`ts-orch node`) | Host | Boots SwarmKit and its executor; owns node certificates, admission and Raft state. Scheduling it inside itself would prevent recovery. `deploy/m1/ts-orch.service`, `internal/app/node.go`, `internal/swarmruntime/node.go`. C5 already makes the release install its own unit. |
| `containerd.service`, containerd shims and runc | Host | Execute SwarmKit tasks and preserve their processes across orchestrator restarts. Must be available before the scheduler. `deploy/m1/host-runtime.sh`, `internal/swarmruntime/controller.go`. |
| `chrony.service` | Host | Sets the host kernel clock before identity federation, TLS and cluster startup. `deploy/m1/host-runtime.sh` configures OCI metadata NTP. |
| `netbird.service` | Host | Owns the host's WireGuard interface, routes, DNS, mesh identity and recovery SSH access. `internal/netbird/manager/server_cli.go` installs and starts the pinned client. |
| `netbird-server.service` | Host | This unit is the root enrollment/configuration companion, **not** the NetBird server workload. It installs/repairs the host client and enrolls that host's identity; on GRU it also prepares the existing server's Vault material and config. `deploy/m1/services/netbird-server.service`, `internal/netbird/manager/server_cli.go`. The actual server is already a SwarmKit service below. |
| `terrascale-ts-auth-metadata.service` | Host | Installed/enabled on the observed host. Applies host network-namespace nftables restrictions before containerd and the node start. Must protect workload startup, including scheduler failure. `internal/tsauth/metadata.go`, `deploy/m1/install.sh`, `internal/regionhost/cloudinit.go`. |
| `ts-orch-release-recovery.service` and `.timer` | Host | Restores an unconfirmed release when the new node binary cannot start or prove health. SwarmKit cannot repair its own failed host executable. `internal/releasepush/recovery.go`. The timer was active; the oneshot is linked and runs on demand. |
| `ts-prometheus.service` | Host | Independent monitoring during SwarmKit failure; retains `/var/lib/ts-prometheus` (709 MB observed). `deploy/observability/production/ts-prometheus.service`. |
| `ts-alertmanager.service` | Host | Independent paging and deduplication during SwarmKit failure; retains notification log and silences in `/var/lib/ts-alertmanager`. `deploy/observability/production/ts-alertmanager.service`. |
| `ts-alert-delivery.service` | Host | Independent alert delivery during SwarmKit failure; retains email budget, journey and probe state in `/var/lib/ts-alerts`. `deploy/observability/production/ts-alert-delivery.service`. |
| `ts-alert-delivery-token.path` and `.service` | Host | Monitoring credential-copy helper; keeps the host relay's mesh token current. Shipped by the monitoring installer, not listed as installed by this host's service/timer query. The path unit is outside that query's types. `deploy/observability/production/install.sh`. |
| Cloud-init and `host-runtime.sh` / data-volume setup | Host | Install the executor, node unit and networking and verify/mount the node's existing data volume before workloads can start. They are provisioning actions, not resident workloads. `internal/regionhost/cloudinit.go`. |

### Work inside the node process

These are embedded runtime responsibilities, not independent daemons hidden
behind additional host units:

| Component or child command | Disposition | Reason and source |
| --- | --- | --- |
| SwarmKit manager/agent, container executor, bootstrap endpoint and task reaper | Node | Own task admission, execution and repair. `internal/app/node.go`, `internal/swarmruntime`. |
| Embedded regional NATS/JetStream, region join publication and mesh bridges | Node | Hold node/region identity and carry the communication needed to bootstrap, reconcile and recover the scheduler. `internal/app/app.go`, `internal/natscell/mesh`, `internal/app/node.go`. |
| Release listener, pull updater and probation/rollback handlers | Node | Repair and replace the executable which owns SwarmKit. `internal/releasepush`, `internal/pullrelease`, `internal/app/node.go`. |
| HTTPS/Postgres edge, certificate renewal and inventory follower | Node | Own the node's public ingress and persistent TLS identity under `<state>/edge-certs`, plus `<state>/edge-spool`; tied to mesh bootstrap and release draining. Conversion would require a separate state/identity migration, outside C15. `internal/app/app.go`, `internal/edge/edge.go`; see [node state](node.md#state-layout). |
| Host metrics, region health, SLO target export and host dashboard | Node | Observe the host kernel, filesystems, runtime and control socket for monitoring and diagnosis of scheduler failure; retain host-local observation rather than scheduling their observer. `internal/app/node.go`, `internal/hostmetrics`, `internal/regionhealth`, `internal/hostdashboard`, `internal/app/slo_targets.go`. |
| Journal configuration, `systemctl`, `journalctl`, `iptables`, `nft`, `findmnt`, `lsblk`, `blockdev` and NetBird CLI invocations | Host helpers | Short-lived host administration/inspection, not separately restartable workloads. They act on host units, kernel networking, mounts and identity. `internal/app/host_logs.go`, `internal/swarmruntime/firewall.go`, `internal/datamount`, `internal/netbird/manager`. |

The admission/membership child commands in `internal/swarmruntime`
are bounded identity-verification helpers, not schedulable application
processes. Older native runner and image/self-update implementation packages
are not evidence of production processes: the production entry point is
`ts-orch node`, as described in [the platform runtime inventory](platform.md#what-was-removed).

## Already owned by SwarmKit

| Workload | Observation / source | Ownership |
| --- | --- | --- |
| NetBird combined management, signal, relay, STUN and embedded IdP (`netbird-server`) | Production: `1/1 running`; `deploy/m1/services/netbird-server.json` | SwarmKit placement/restarts; existing `/var/lib/ts-data/netbird` bind. Distinct from the enrollment host unit with the same name. |
| TerraBase (`terrabase`) | Production: `2/2 running`; `deploy/m1/services/terrabase.json` | SwarmKit tasks; existing `/var/lib/ts-data/terrabase` bind. |
| Authentication (`ts-auth`) | Production: `1/1 running`; `deploy/m1/services/ts-auth.json` | SwarmKit tasks. |
| Product dashboard (`ts-dashboard`) | Production: `1/1 running`; `deploy/m1/services/ts-dashboard.json` | SwarmKit tasks; distinct from the embedded host diagnostic dashboard. |
| `app-canary` | Spec in `deploy/m1/services`; absent from the observed GRU service list. Targets SJC/FRA. | A service spec, not a host daemon. No assertion about its running replicas on other hosts. The unused production whoami spec was removed; native mesh endpoints require no app service. |

`internal/swarmruntime/service.go` converts these specs into services with
resource limits/reservations and restart policy; the executor independently
probes readiness. `ts-orch service ls` reports the observed tasks and
`ts-orch status` uses the runtime/mesh inventory. No host install path is added
for these application workloads.

## OS services and timers observed

All entries below stay on the host. They operate the host kernel, filesystems,
network, device discovery, package repair, logging or recovery access rather
than provide TerraScale application replicas. This inventory does not enable,
disable or remove distribution services that happen to be installed.

| Responsibility | Observed units | Why host-owned |
| --- | --- | --- |
| Boot, cloud initialization and filesystems | `apparmor.service`, `blk-availability.service`, `cloud-config.service`, `cloud-final.service`, `cloud-init-local.service`, `cloud-init.service`, `finalrd.service`, `systemd-fsck@dev-disk-by\x2dlabel-BOOT.service`, `systemd-fsck@dev-disk-by\x2dlabel-UEFI.service`, `systemd-remount-fs.service` | Prepare/protect the kernel and filesystems on which SwarmKit boots. |
| Storage and devices | `iscsid.service`, `lvm2-monitor.service`, `multipathd.service`, `udisks2.service`, `kmod-static-nodes.service`, `systemd-modules-load.service`, `systemd-udev-trigger.service`, `systemd-udevd.service` | Discover and maintain host devices and attached volumes. |
| Kernel/system initialization | `systemd-binfmt.service`, `systemd-random-seed.service`, `systemd-sysctl.service`, `systemd-tmpfiles-setup-dev-early.service`, `systemd-tmpfiles-setup-dev.service`, `systemd-tmpfiles-setup.service` | Configure the kernel, device nodes and runtime directories before workloads. |
| Host networking | `ModemManager.service`, `netfilter-persistent.service`, `networkd-dispatcher.service`, `rpc-statd-notify.service`, `rpcbind.service`, `systemd-networkd-wait-online.service`, `systemd-networkd.service`, `systemd-resolved.service` | Operate host interfaces, firewall, name resolution and storage networking. Presence does not imply TerraScale needs every distribution daemon. |
| Administration and recovery sessions | `dbus.service`, `polkit.service`, `ssh.service`, `systemd-logind.service`, `systemd-user-sessions.service`, `user-runtime-dir@1000.service`, `user@1000.service` | Host authorization, operator sessions and recovery access independent of SwarmKit. |
| Console/boot display | `console-setup.service`, `getty@tty1.service`, `keyboard-setup.service`, `plymouth-quit-wait.service`, `plymouth-quit.service`, `plymouth-read-write.service`, `serial-getty@ttyAMA0.service`, `setvtrgb.service`, `systemd-update-utmp.service` | Host boot and local/serial recovery console. |
| Host logging and diagnostics | `apport.service`, `sysstat.service`, `systemd-journal-flush.service`, `systemd-journald.service`, `unified-monitoring-agent.service` | Observe/retain host failures, including runtime failure; OCI monitoring remains host-owned. |
| Image package/agent maintenance | `snap.oracle-cloud-agent.oracle-cloud-agent-updater.service`, `snap.oracle-cloud-agent.oracle-cloud-agent.service`, `snapd.apparmor.service`, `snapd.seeded.service`, `snapd.service`, `unattended-upgrades.service` | Maintain/repair the installed OS and OCI host integration. |
| Cron | `cron.service`; `/etc/cron.d/{e2scrub_all,sysstat}`, daily `{apt-compat,sysstat,dpkg,apport,man-db,logrotate}`, weekly `man-db` | Host maintenance. Hourly/monthly directories contained only placeholders; no user crontabs. `/etc/crontab` invokes the distribution's periodic directory jobs. No separate TerraScale cron workload found. |
| Package timers | `apt-daily-upgrade.timer`, `apt-daily.timer`, `dpkg-db-backup.timer`, `fwupd-refresh.timer`, `man-db.timer`, `motd-news.timer`, `update-notifier-download.timer`, `update-notifier-motd.timer` | Maintain installed host packages and recovery information. |
| Storage/log/diagnostic timers | `e2scrub_all.timer`, `fstrim.timer`, `logrotate.timer`, `sysstat-collect.timer`, `sysstat-summary.timer`, `systemd-tmpfiles-clean.timer`, `unified-monitoring-agent_config_downloader.timer` | Maintain host filesystems, logs, counters and OCI monitoring. |

## Obsolete and separate-deployment units

The observed host also has inactive `ts-zdt-deadman.service` and a disabled,
inactive `ts-zdt-deadman.timer`. The service describes a cold-maintenance
dead-man switch and invokes `/var/tmp/zdt-offline/deadman.py`. The repository
previously shipped their installer in `scripts/maintenance/window.py` and the
founder script in `scripts/maintenance/deadman.py`. C15 deletes that obsolete
window driver together with `deadman.py`, `deadman_workers.py` and their
`qualify-deadman.py` fixture. Removing the coupled driver avoids retaining
maintenance steps whose rollback helpers no longer exist. No surviving script
installs or enables these deadman units. Per COS, C26's Cloudflare cron dead-man
replaced the obsolete mechanism; this change adds no replacement scheduler.
Production was not modified: the observed inactive units remain installed there.

The remaining M1 install units perform the host responsibilities above.
`deploy/systemd` NetBird units are referenced by `internal/netbird/client`;
they are a separate enrollment install
path, not duplicate M1 workload units. `deploy/netbird/manager` targets the
separate `ts-ops` Podman deployment and its own store/backup/firewall, not the
observed SwarmKit host; its installer explicitly refuses other hosts. This
inventory does not claim those units are deployed on `ts-gru-1` or remove them
based on their absence there.

## Release and proof boundary

Nothing moves in this inventory and obsolete-tooling cleanup. Consequently
there is no new cutover, host-unit removal, rollback restoration, service rescheduling or
production-upgrade behavior to prove. The removed installer is not invoked by
the normal release path; removing it does not disable installed host units.
No E2E assertion was added and no node was restarted. The read-only service
counts above prove the observed existing
workload ownership, not a newly exercised failover. Future conversions must
preserve ports/names/secrets and prove cutover, restart/rescheduling and
rollback in `e2e-m1`; any state migration needs a separate decision.
