# TS-783 rollback drill preflight, 2026-10-10

This is read-only preflight evidence, not a completed rollout or rollback drill.
At preflight, the working branch was `cos-hold/ts-783-rollback-drill`, based on
`5f56292c1004a2b1e88985732ee736da05b2069a`. No serving cell, configuration,
KV record, binary, process or infrastructure was changed by these checks.

## Target access

The local operator host was verified as `delta`. NetBird inventory reported
the following six connected targets:

| Region | Node | Mesh address |
| --- | --- | --- |
| GRU | ts-gru-1 | 10.200.87.215 |
| GRU | ts-gru-2 | 10.200.38.135 |
| GRU | ts-gru-3 | 10.200.168.164 |
| SFO | ts-sfo-1 | 10.200.112.213 |
| SFO | ts-sfo-2 | 10.200.122.37 |
| SFO | ts-sfo-3 | 10.200.63.195 |

Target-only `hostname` requests through `sudo -n netbird-wt0 ssh --no-browser`
to GRU1 and SFO1 requested device authentication and timed out after 20 seconds
(exit 124). Pinned, noninteractive OpenSSH to GRU1 refused authentication
(exit 255). Target hostnames, installed binaries/configuration and quorum
were therefore not verified through SSH. No device-login flow or remote
mutation followed.

Local metadata checks also found no installed `operator.json` at
`/var/lib/terrascale-operator`, `/var/lib/terrascale-operator-gru` or
`/var/lib/terrascale-operator-sfo`. No credential values were read. The proposed
flagless command's installed human operator identity is therefore not available
on this workstation; the current dashboard token files establish neither that
identity nor fleet recovery authority.

## Dashboard check

The existing `dist/ts-orch dashboard check` ran with the installed
`sudo -n netbird-wt0` wrapper, existing regional token files and a five-second
request timeout. Tokens and response bodies were not printed. The checker
requested all 15 pages through both mesh IP and NetBird DNS on all six nodes,
for 180 requests. It exited 1: 160 passed and 20 failed.

All 12 `/members` checks observed only one controller, below the check's
required three. Eight `/` requests timed out with curl exit 28. Successful
authenticated page requests establish dashboard reachability only; they do
not establish cell quorum, compatible release-state readers, an agreed
predecessor or retained trusted rollback bytes/configuration.

The raw token-free result is `/tmp/ts783-slice2-dashboard-preflight-r33.log`
on the operator workspace. Dashboard completeness and access findings were
recorded without changing the checker or taking over other tickets' scope.

## Drill prerequisite

A live drill still needs authenticated target verification, current regional
authority/quorum, compatible persisted rollout state, and an exact trusted
good binary/configuration target in each serving region. The dated storage
findings in [the earlier rollout storage evidence](ts783-rollout-storage-20261010.md)
need fresh verification by the serving-cell recovery owner; they are not
proof of current state. No rollout timings or rollback completion are claimed.
