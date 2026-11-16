# Regional monitoring rollout, 2026-11-16

This records the first production attempt of the regional monitoring install in
[`deploy/observability/production`](../deploy/observability/production/README.md).
It was rolled back on `ts-gru-1`. Production still runs the GRU-only
monitoring it ran before. The regional monitoring is **not** on.

## Before

| Item | State |
| --- | --- |
| Orchestrator release on all six hosts | `f4a7f872` (#368). It contains #349, #350, #355 and #364 (`git merge-base --is-ancestor`). Nothing under `deploy/observability`, `scripts/monitoring` or `test/e2e/m1/monitoring` changed between it and `5a1338b00` (main used here). |
| `ts-gru-1` | Old GRU-only monitoring: `ts-prometheus`, `ts-alertmanager` (cluster disabled), `ts-alert-delivery`, no `ts-alert-delivery-token.path`, no `alertmanager.env`, 17 targets up. The relay still ran the binary from before the 16:16 UTC release (started 2026-11-13). |
| `ts-gru-1` files | `prometheus.yml` `c9a381f8…`, `operational-rules.yml` `03e51304…`, `host-storage-rules.yml` `06187b22…`, `alertmanager.yml` `3021ebb9…` (the files of `2fafe9da4`/`7d7d952c8`), `ts-alert-delivery.service` `b764ed26…` (a later unit), `ts-prometheus.service` `2b1bbe0a…`, `ts-alertmanager.service` `36f764d1…`. |
| `ts-sjc-1`, `ts-fra-1` | No monitoring units, no `/etc/ts-monitoring`. |
| Firing alerts | `TerraBaseReplicaUnverified` (gru, warning) only. No silences. |
| Outside probe | Dead-man open and paging: `probe_state {"open":[{"key":"deadman",…}]}`; every public endpoint `ok`. GitHub runs the 5-minute schedule only every few hours (runs at 2026-11-15 09:16, 16:25, 21:07, 2026-11-16 00:58, 07:38, 17:25 UTC). |

## What was run

From delta, which has the `ts-gru-1`, `ts-sjc-1` and `ts-fra-1` SSH aliases, in a
detached checkout of `origin/main` (`5a1338b00`):

```sh
bash deploy/observability/production/install.sh --check                # exit 0
bash deploy/observability/production/install.sh --preflight ts-gru-1   # existing
bash deploy/observability/production/install.sh --preflight ts-sjc-1   # new
bash deploy/observability/production/install.sh --preflight ts-fra-1   # new
amtool silence add … alertname=MonitoringBackendDown 'region=~"sjc|fra"'  # on ts-gru-1, for the staged install
bash deploy/observability/production/install.sh --fleet-host ts-gru-1  # 17:29:03-17:29:23 UTC, exit 0
```

`--fleet-host` is the per-host step `--fleet` runs after every preflight. It was
used so each host could be checked before the next.

## Why it was rolled back

Within a minute of the `ts-gru-1` install the new rules evaluated alerts that
did not fire before:

| Alert | Hold | Evidence |
| --- | --- | --- |
| `MeshStoreLeaderUnavailable`, `MeshStoreQuorumUnavailable` on `ts-gru-2`, `ts-sjc-2`, `ts-fra-2` | 1m | Every `-2` host exports `ts_orch_mesh_store_observed 0`, `…_leader_available 0`, `…_quorum_available 0`. The `-1` hosts export 1. |
| `RuntimePeerTopologyMismatch` (host `ts-sjc-1`, regions gru and fra) | 30s | `ts_orch_peer_topology_mismatch 1` from ts-sjc-1's exporter. The old GRU-only config scrapes only ts-gru-1's exporter. |
| `EdgeCertificateMissing` on `ts-gru-1`, `ts-sjc-1`, `ts-fra-1` | 10m | `ts_edge_certificate_names_missing` 5, 3 and 3; 0 on the `-2` hosts. |
| `AlertDeliveryProbeMissing` | 15m | The relay's first probe logged `Alert delivery probe incomplete`. |
| `TerraBaseBackupDrillStale` (sjc), `ProductionJourneyTelemetryMissing` | 15m | New coverage (warnings). |

The two `RuntimePeerTopologyMismatch` groups were pushed at 17:30:08 and 17:30:10
UTC, before a silence covered them. Every critical email in the window was
refused with `email admission denied or invalid`. The relay's admission request
to `https://auth.terrascale.tech/v1/terrascale/email/admission` is not admitted.
The old relay already logged `admission unavailable` before the install, so
alert email does not work today.

## Rollback used

The README's step 4 (`install.sh ts-gru-1` from the previous revision) could not
reproduce `ts-gru-1`'s state: its files came from `2fafe9da4`/`7d7d952c8` and its
relay unit from a later revision. The recorded before-state was restored instead:

```sh
# before the install, on delta
ssh -n ts-gru-1 'sudo tar -C / -czf - etc/ts-monitoring etc/systemd/system/ts-prometheus.service \
  etc/systemd/system/ts-alertmanager.service etc/systemd/system/ts-alert-delivery.service' > ts-gru-1-monitoring-before.tgz
# rollback, 17:31:05 UTC
sudo systemctl disable --now ts-alert-delivery-token.path ts-alert-delivery-token.service
sudo rm -f /etc/systemd/system/ts-alert-delivery-token.{path,service} \
  /etc/ts-monitoring/production/rules.yml /etc/ts-monitoring/production/alertmanager.env
sudo tar -C / -xzf ts-gru-1-monitoring-before.tgz
sudo systemctl daemon-reload
sudo systemctl restart ts-alert-delivery.service ts-alertmanager.service ts-prometheus.service
```

The binaries in `/usr/local/lib/ts-monitoring` were unchanged by the install
(same SHA-256 before and after). Every restored file matches its recorded hash.
State directories were kept.

A rollback shortly after an install pages by itself. The series the fleet config
wrote stay visible for Prometheus' five-minute staleness window, and the old
rules read them:

- `TerraBaseBackupHoles` fired through the old first-observation clause. It was
  silenced before delivery.
- `ServiceSLOBurnFast` and `ServiceSLOBurnSlow` (sjc, terrabase) were pushed at
  17:31:57 UTC and resolved at 17:36:57 UTC. sjc's TerraBase tasks are scraped
  only by the fleet config. In that window they reported 105 bad of about
  6,000 requests (5m).

Before a rollback, silence the alerts of the old rules for ten minutes.

## After

At 17:37 UTC `ts-gru-1` again ran the before-state: 17 of 17 targets up, only
`TerraBaseReplicaUnverified` (gru) firing, Alertmanager cluster disabled, no
silences (the three C3 silences were expired). `ts-sjc-1` and `ts-fra-1` were
never changed. No test alert was sent and the dead-man still pages.

## Before the next attempt

1. Decide whether the `-2` hosts should observe the mesh store. If not, scope
   `MeshStore*` to hosts that run the broker.
2. Fix or explain the whoami peers mismatch reported by `ts-sjc-1`.
3. Fix or explain the missing edge certificate names on the `-1` hosts.
4. Make `ts-alerts` email admission at `auth.terrascale.tech` return `admitted`.
5. Get the outside probe to run on schedule (a self-hosted or external trigger),
   or accept a dead-man that runs every few hours.

Then rerun the commands above and finish with `install.sh --fleet`, which reruns
every preflight, leaves unchanged hosts running and checks the three-member
Alertmanager cluster.

## Switching it off

On a host installed by this release, `install.sh --remove <host>` (or
`--remove --fleet`) disables the units and keeps the state. Restore GRU-only
monitoring from the before-state archive as above.
