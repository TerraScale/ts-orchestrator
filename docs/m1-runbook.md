# Milestone 1 runbook: ts-orch single host on ts-gru-1

One process (`ts-orch single-host`) runs the SwarmKit manager and worker,
the containerd executor, a local control socket and the HTTPS edge (`:80`
ACME HTTP-01 + redirect, `:443`). Services come from
`deploy/m1/services/*.json`.

## Host

| Fact | Value |
|---|---|
| ssh | `ssh ts-gru-1` (`ubuntu@163.176.124.12`, passwordless sudo) |
| Shape | OCI `gru-1-ctl-1`, A1.Flex 4 OCPU / 24 GB, Ubuntu 24.04 aarch64 |
| Runtime | containerd 2.2.1 + runc 1.3.4 (Ubuntu packages) |
| Open ports | 80, 443 from anywhere; 22 from the operator egress IP |
| State | `/var/lib/ts-orch` (Raft, edge certificates, socket) |
| Data | `/var/lib/ts-data/<service>` (bind mounts; TerraBase uses `terrabase`) |
| Edge certificates | `/var/lib/ts-orch/edge-certs` (Let's Encrypt, HTTP-01 on :80) |

The Ubuntu OCI image ends `INPUT` with a REJECT rule; the 80/443 ACCEPT rules
must sit above it or ACME validation fails with "no viable challenge type".
Fixed on ts-gru-1 2026-10-21 and saved with `netfilter-persistent save`:

```sh
ssh ts-gru-1 sudo iptables -S INPUT   # 80 and 443 ACCEPT before the REJECT
```

## Install or upgrade

Every main push publishes a CI release `ci-<sha>-run-<id>` with
`terrascale-orchestrator-linux-arm64`. Install the newest one:

```sh
tag=$(gh release list -R TerraScale/ts-orchestrator -L 1 --json tagName -q '.[0].tagName')
asset=terrascale-orchestrator-linux-arm64
url=https://github.com/TerraScale/ts-orchestrator/releases/download/$tag/$asset
sum=$(gh release view "$tag" -R TerraScale/ts-orchestrator --json assets \
  -q ".assets[] | select(.name==\"$asset\") | .digest" | cut -d: -f2)
deploy/m1/install.sh ts-gru-1 "$url" "$sum"
```

`install.sh` verifies the sha256, installs `/usr/local/bin/terrascale-orchestrator`
(alias `ts-orch`), creates the state and data directories, installs
`ts-orch.service` and restarts it. Re-running it is the upgrade.

Check:

```sh
ssh ts-gru-1 systemctl is-active ts-orch
ssh ts-gru-1 sudo journalctl -u ts-orch -n 50 --no-pager
```

## Services

```sh
scp deploy/m1/services/whoami.json ts-gru-1:/tmp/whoami.json
ssh ts-gru-1 sudo ts-orch service apply -f /tmp/whoami.json
ssh ts-gru-1 sudo ts-orch service ls
ssh ts-gru-1 sudo ts-orch service rm whoami
```

## Operator commands

Run on the host as root. Every command reads `/var/lib/ts-orch` over the
control socket; none changes state. Known failures end in `. Fix: <next step>`.

| Command | Shows |
|---|---|
| `ts-orch service ps <svc>` | Tasks newest first: ID, node, state, desired state, time in state, last error; then `Fix:` for the newest task's error |
| `ts-orch service logs [-f] <svc>` | Newest task's container stdout then stderr (`<state>/runtime-logs/ts-<task>/`); `-f` follows appended output |
| `ts-orch service inspect <svc>` | JSON: service ID, version, created/updated, image digest, and the declared spec. Secrets show env keys and OCI Vault refs only; values never enter the spec |
| `ts-orch events [-f]` | Latest 100 task and service state records, oldest first; `-f` streams changes from the manager's watch API |

Single-host's NATS carries only releases, so `events` reads SwarmKit's watch API.

Deploy check: `service apply -f x.json`, then `events -f` until the task shows
`running`, then `service logs <svc>`.

Common errors and fixes:

| Error contains | Fix |
|---|---|
| `swarm-root-ca.crt: permission denied` | Run with `sudo` |
| `control.sock: connect: connection refused` | `sudo systemctl status ts-orch`; `sudo journalctl -u ts-orch -n 50` |
| `signed container material is pending` | Check every ref in `service inspect` `.spec.secrets` exists in OCI Vault and the host's ts-orch release delivers Vault secrets; re-apply |
| `disk capacity or retained storage is unavailable` | Each task reserves 10 GiB: `df -h /var/lib/containerd /var/lib/ts-orch` |
| `no suitable node` | The host is out of CPU, memory, disk or the port: `service ls`, remove or shrink a service |
| `load admitted container image` | Registry unreachable or digest missing: `sudo ctr -n terrascale images pull <image>` |
| `exited with status` / `non-zero exit` | `ts-orch service logs <svc>` |

The full table is `operatorFixes` in `internal/app/service_ops_cli.go`.

## DNS (Cloudflare, DNS-only)

Records point at the host public IP; the edge obtains certificates itself, so
Cloudflare proxying stays off.

| Name | Type | Content | Record ID | Purpose |
|---|---|---|---|---|
| `m1-test.terrascale.tech` | A | 163.176.124.12 | `fac1872f4903e4ddbb235db8c3c48af1` | W6 whoami proof |

Create a record (the `cf` OAuth login was absent on 2026-10-21; the
`CLOUDFLARE_API_TOKEN` environment token has `dns_records:edit`):

```sh
cf dns records create -z terrascale.tech --body \
  '{"type":"A","name":"<name>.terrascale.tech","content":"163.176.124.12","proxied":false,"ttl":1}'
```

## Proof log

| Date | Binary (CI release) | Check | Result |
|---|---|---|---|
| 2026-10-21 | local arm64 build of W2+W3+W4+W5 branches (smoke, state `/var/lib/ts-orch-smoke`) | `curl https://m1-test.terrascale.tech/` | Let's Encrypt cert issued, edge 502 (task blocked by container-material gate) |

## Multi-region

Three regions, one host each: ts-gru-1 (sa-saopaulo-1), ts-sjc-1
(us-sanjose-1), ts-fra-1 (eu-frankfurt-1). Each runs `ts-orch single-host`
with its own SwarmKit node and its own NATS cluster (`internal/natscell/mesh`).

- DECISION: full-mesh NATS gateways (a supercluster of one-node regional
  clusters) on public tcp/7222. Reason: one NATS cluster per region (repo
  rule), and sjc and fra keep talking when gru is down (no GRU-rooted tree).
- DECISION: one Vault for every region, `gru-vault`, read cross-region by
  instance principal. Gateway mTLS comes from the single secret
  `ts-orch-mesh-key`: every node derives the same CA from it and issues
  itself a leaf certificate at start. Reason: one secret, no per-region copies.
- A new region joins with no release and no other host touched: its node
  dials the founded regions (gru, sjc, fra) as seeds, gateway gossip
  announces it, and every region opens a gateway to its advertised
  `<region>.mesh.terrascale.tech:7222` (that DNS record must exist). The
  mesh-CA mTLS is the only gate; ping and apply then wait for it too.
- Global services: `ts-orch service apply -f|rm` on any host publishes on
  `ts.svc.apply` and prints one row per region. Each node keeps a
  last-writer-wins map in `<state>/mesh/desired.json` and pulls the other
  regions' maps at start and every 30 s (`ts.svc.state`), so a region that
  was down catches up by itself. `regions` in a spec limits it (M1 specs: `["gru"]`).
- Auto-deploy: ci.yml `deploy/release-push` (W14) pushes each green main
  release to every region in `deploy/m1/regions.json` over TLS :4222.
- Live check: `.github/workflows/multi-region.yml` (every 6 h, after main CI,
  or `gh workflow run multi-region.yml --ref main`) runs `ts-orch release
  mesh-check`: ping matrix, one apply to all regions, HTTPS per region.

### Infrastructure

Created 2026-10-21 with deploy/m1/oci-host.sh and oci-iam.sh, since replaced by `ts-orch region add` (below). Each cell (compartment, ts-orch network, host launch) took 2-3 minutes.

| | sjc-1 (us-sanjose-1) | fra-1 (eu-frankfurt-1) |
|---|---|---|
| compartment | `sjc-1-control` ocid1.compartment.oc1..aaaaaaaaysxjvhdqptflhspi7tqb2c44yhqifcjgfewxjhc2skelpiyugqva | `fra-1-control` ocid1.compartment.oc1..aaaaaaaavvrkl4p77rj3e2sigkf2vvpal45h5bnw7v4vlrphkwmqjabzbnca |
| VCN | `sjc-1-vcn` 10.252.0.0/24 ocid1.vcn.oc1.us-sanjose-1.amaaaaaappuhpdqavgiiwj7fcggty3cqens4zcpa26w5jla5afvuuxinthnq | `fra-1-vcn` 10.253.0.0/24 ocid1.vcn.oc1.eu-frankfurt-1.amaaaaaappuhpdqano5bmeydhkuu43c2maak2ox3hsl6ea5j3vfr65zh4ldq |
| host subnet | 10.252.0.0/25 ocid1.subnet.oc1.us-sanjose-1.aaaaaaaapv7ua3usk3qomfrsyxsxrwpcahqrcv4aazkb6qawztv7umu4ekxq | 10.253.0.0/25 ocid1.subnet.oc1.eu-frankfurt-1.aaaaaaaaqbj7ot2jvw7jjigm3ulkgnn37yn2wkdx3ewpdskgrdohlpn36f4q |
| private subnet | 10.252.0.192/26 ocid1.subnet.oc1.us-sanjose-1.aaaaaaaarjcjej3gxrws6imvwmozlxi3ym7kupobvl5ll4uk55mkeqzjdlya | 10.253.0.192/26 ocid1.subnet.oc1.eu-frankfurt-1.aaaaaaaahsaxngd7rzfsqywtt35wmhokcgwqlvcfuka7qlaw5m5nkolvmlpq |
| IGW | ocid1.internetgateway.oc1.us-sanjose-1.aaaaaaaaddd4a6hq7b6v77soerldw6zzwxqt4rsqnpniofzuvktacyhsp4rq | ocid1.internetgateway.oc1.eu-frankfurt-1.aaaaaaaa7vsowzuoaxljsz5redfolyr62gms5kwsrkylrrzfzpriclcwf42a |
| host SL (empty) | ocid1.securitylist.oc1.us-sanjose-1.aaaaaaaaddq24dkx4eamns6tmcblbkvgwwg3k4c6vqz2kpcybi24hn2bxqaa | ocid1.securitylist.oc1.eu-frankfurt-1.aaaaaaaatcqoyzhokjwu547x7vhj7237ds63iiaelgocbuud56p3zi7i5ryq |
| host NSG | ocid1.networksecuritygroup.oc1.us-sanjose-1.aaaaaaaaqfbxtxwngr3eonyzqvbsieh3n32lsb3xwpbrjzj744roxcu667ra | ocid1.networksecuritygroup.oc1.eu-frankfurt-1.aaaaaaaaxbbsta4gnjup72xtxj75assgn6udapyf2bqs7knooi2hcf76wrwa |
| edge NSG (80, 443, 4222/tcp, 3478, 51820/udp world) | ocid1.networksecuritygroup.oc1.us-sanjose-1.aaaaaaaa6ouqqcuv4jdje62cwdvrvvzn7g7tgg5gszl2dilqrmwj2tzgwafa | ocid1.networksecuritygroup.oc1.eu-frankfurt-1.aaaaaaaa2skml3t4xbcrus4wjyaiogg3wr4al3uhztpwgr7j5rqcxvah5qhq |
| operator SSH NSG (22 from 179.124.206.245/32) | ocid1.networksecuritygroup.oc1.us-sanjose-1.aaaaaaaauyuwubdjesqh7jcnowpvtkv2kzzp552sfoecwncusfjskpphjcyq | ocid1.networksecuritygroup.oc1.eu-frankfurt-1.aaaaaaaadcrfy44zny5tu2rtmdsjkaqa2g7hwipdzwsqmopq3x2r3hsmcz5q |
| instance (A1 2 OCPU/12 GB, 50 GB, Ubuntu 24.04 aarch64 2026.09.18) | `ts-sjc-1` ocid1.instance.oc1.us-sanjose-1.anzwuljrppuhpdqc7opmuobxfqj7xwwoms6eufmjesl4i56ejyayfkhzqkda, AD-1 | `ts-fra-1` ocid1.instance.oc1.eu-frankfurt-1.antheljtppuhpdqchc25czozfaofnepsli2no3yw6ydyyxkyi7ka5mnanl2q, AD-1 |
| public IP | 163.192.54.17 | 130.162.238.198 |

IAM (home region): dynamic group `ts-orch-hosts` ocid1.dynamicgroup.oc1..aaaaaaaa4p2jqmkzg2fh3jbycndc2r42fp2zohnjh45g3fyp2jwakcz2242a (instances in gru-1/sjc-1/fra-1-control); policy `ts-orch-hosts-vault` in gru-1-control ocid1.policy.oc1..aaaaaaaao3hynxzhoqd7ehwdkamnsoxbzfms6kxyywowyvtuzxjgsrnlzbha. Both hosts read `gru-1-vault-canary` (version 1) by instance principal.

DNS (terrascale.tech, DNS only): `gru.mesh` 163.176.124.12 id 1f12e527d20e86d81d9700fd381451d1; `sjc.mesh` 163.192.54.17 id de05828b8740ab51fc8f9773a2d298c3; `fra.mesh` 130.162.238.198 id 6484cf7fdbeea2f5a4945cda65c4f6b1.
DNS (terrascale.tech, DNS only): `gru.mesh` 163.176.124.12 id `1f12e527d20e86d81d9700fd381451d1`; `sjc.mesh` 163.192.54.17 id `de05828b8740ab51fc8f9773a2d298c3`; `fra.mesh` 130.162.238.198 id `6484cf7fdbeea2f5a4945cda65c4f6b1`.

Mesh ports (ts-orch's `oci-region network <cell> --apply`, 2026-10-22): edge
NSG ingress tcp/7222 and host NSG egress tcp/7222 on gru-1, sjc-1, fra-1.
ts-orch adds the matching iptables ACCEPTs (7222, 4222, 80, 443) at every start.

### Proof, 2026-10-22 (PR #62 build on all three hosts)

NATS round trip, `sudo ts-orch mesh ping` on each host:

| From \ to | gru | sjc | fra |
|---|---|---|---|
| gru | 0 ms | 169 ms | 188 ms |
| sjc | 169 ms | 1 ms | 131 ms |
| fra | 188 ms | 131 ms | 0 ms |

One apply from sjc deploys to every region (`w15-probe`, traefik/whoami,
new service, image cached), 1.75 s wall clock:

```
$ ssh ts-sjc-1 sudo ts-orch service apply -f /tmp/w15-probe.json
REGION  RESULT   READY
gru     applied  1526ms
sjc     applied  1530ms
fra     applied  1524ms
```

`curl localhost:8094/` on each host answered `Name: w15-probe` with its own
hostname (gru-1-ctl-1, ts-sjc-1, ts-fra-1).

Failure test (approved): `systemctl stop ts-orch` on ts-gru-1 at 00:21:05 UTC.

```
$ ssh ts-sjc-1 sudo ts-orch mesh ping
gru     -         NO REPLY
sjc     ts-sjc-1  0ms
fra     ts-fra-1  145ms
$ ssh ts-sjc-1 sudo ts-orch service apply -f /tmp/w15-probe-b.json
gru     NO REPLY  -
sjc     applied   45944ms
fra     applied   1535ms
```

Started ts-orch on ts-gru-1 at 00:23:21; it ran `w15-probe-b` 33 s later
(anti-entropy pull, no operator step) and `mesh ping` saw all three again.
Removal is global too (`service rm`, 3-9 ms per region).

Auto-deploy: main CI run 39707217972 (`e728ed36b`) pushed the release to
every region in `deploy/m1/regions.json`, no manual step; afterwards all
three hosts reported `vcs.revision=e728ed36b...` and `mesh ping` saw all three.

| Region | Connect ms | Accepted ms | Serving ms |
|---|---|---|---|
| gru | 610 | 6696 | 10077 |
| sjc | 95 | 3346 | 6136 |
| fra | 544 | 4509 | 8053 |

Automated check: `multi-region.yml` run 39711912422 (after main CI, `5d67e59ef`,
release `ci-d8779fca...-run-39711008818`) passed. Ping matrix as above
(168/188/138 ms); whoami removed and re-applied from gru: gru 10608 ms,
sjc 10597 ms, fra 1526 ms until running; HTTPS on gru/sjc/fra.mesh.terrascale.tech
answered with the run marker and each host's name (460/143/408 ms).
https://github.com/TerraScale/ts-orchestrator/actions/runs/39711912422

Known gaps: updating an existing service in place waits on W14's #28 (the
old task keeps its host port); the 45.9 s sjc time above is not explained yet.

## Adding a region (ts-orch region add)

Every new region (and every extra host) costs money: it needs the user's
approval before anyone runs `region add` for it. The tenancy must already be
subscribed to the OCI region.

```bash
# From the repository root, with the operator OCI config (~/.oci), gh and a
# Cloudflare DNS token (CF_API_TOKEN, or the cf CLI's CLOUDFLARE_API_TOKEN).
ts-orch region add <code> --dry-run       # the plan; changes nothing
ts-orch region add <code>                 # create or adopt everything below
ts-orch region add <code> --host ts-<code>-2 --shape VM.Standard.A1.Flex   # an extra host
ts-orch region rm <code> --host ts-<code>-2                                # remove it
```

It replaces `deploy/m1/oci-host.sh`, `deploy/m1/oci-iam.sh` and the manual
install, DNS and pin steps. In order, it creates or adopts:

1. compartment `<cell>-control` under `TerraScale` (waits until it is visible
   in the region);
2. the network (`ts-orch oci-region network <cell> --apply`);
3. the host: without `--host`, the oldest live instance in the compartment
   (so `region add gru` adopts `gru-1-ctl-1`), else a new `ts-<code>-1`
   (A1.Flex 2 OCPU/12 GB, 50 GB, Ubuntu 24.04, AD fallback). `--host NAME`
   adopts or launches exactly NAME; `--shape SHAPE` launches the smallest
   SHAPE host (1 OCPU, 6 GB Ampere / 8 GB x86) with the matching arm64/amd64
   image and binary. Cloud-init installs host-runtime.sh, NetBird, the
   newest CI release binary (sha256 checked) and only `ts-orch.service`,
   without ssh. Never `deploy/m1/services/*.service`: netbird-server.service
   is gru's one NetBird server; a region's other services ship as mesh
   services. Later cloud-init changes never relaunch a host;
4. IAM: dynamic group `ts-orch-hosts` matches every cell compartment with a
   host; policy `ts-orch-hosts-vault` (gru-1-control) holds the gru-vault
   statements plus one `manage secret-family` per region for its join secret
   `ts-orch-join-<region>`;
5. region host only: DNS-only A `<code>.mesh.terrascale.tech` to its public
   IP, and its release-listener pin (read from the TLS handshake on :4222)
   in `deploy/m1/regions.json` through PR `region-<code>-pin` (auto-merge).

Output is one line per resource, `unchanged|created|updated KIND NAME ID`.
A second run changes nothing and prints only `unchanged`.

`region rm <code> --host NAME` terminates only NAME and refuses the region
host. `region rm <code> --yes`, typed interactively, terminates the region
host, deletes its DNS record, drops it from the IAM and opens the
regions.json PR. The compartment and network stay (free).

## Deploy speed

### ts-orch itself: green main -> live on every region

Every green main push with a changed binary runs `deploy/release-push`
(`.github/workflows/ci.yml`): it pushes the run's release over NATS to every
region in `deploy/m1/regions.json` (TLS on :4222, listener key pinned, GitHub
OIDC credential, see `docs/m1-single-host.md`), each host verifies, installs,
exits and is restarted by systemd (`RestartSec=1s`), and the job polls each
region's `ts.release.version` every 250 ms until it equals the SHA. No ssh, no
manual step, no switch. A region failing never stops the others.

"Green" = the last lint/race job finished; "live" = the push job finished with
every region serving the SHA. Per region: ms from connect to accepted
(download + verify + install) and to serving (restarted, answering with the
new version).

| Main SHA | Run | Build | Green -> live | gru accepted / serving | sjc | fra |
|---|---|---|---|---|---|---|
| bfa55583 | [39706433147](https://github.com/TerraScale/ts-orchestrator/actions/runs/39706433147) | after checks | 190 s | 5978 / 9904 | 1382 / 4117 | 4421 / 7691 |
| e728ed36 | [39707217972](https://github.com/TerraScale/ts-orchestrator/actions/runs/39707217972) | after checks | 132 s | 6696 / 10077 | 3346 / 6136 | 4509 / 8053 |
| 320ab132 (#72) | [39708202161](https://github.com/TerraScale/ts-orchestrator/actions/runs/39708202161) | beside checks | 35 s | 5889 / 9476 | 3221 / 6200 | 19372 / 22733 |
| 8fe8b0d8 | [39708941852](https://github.com/TerraScale/ts-orchestrator/actions/runs/39708941852) | beside checks | 27 s | 8980 / 12906 | 1369 / 4094 | 4712 / 8746 |
| d8779fca | [39711008818](https://github.com/TerraScale/ts-orchestrator/actions/runs/39711008818) | beside checks | 17 s | 5310 / 8681 | 3195 / 6212 | 4434 / 7848 |
| 5d67e59e | [39711436111](https://github.com/TerraScale/ts-orchestrator/actions/runs/39711436111) | beside checks | 23 s | 5784 / 9707 | 3546 / 6288 | 4504 / 8116 |

Every row: all three regions `installed`. Target green -> live <= 60 s: met
since #72 (17-35 s, n=4). Before (ts-orch deploy.yml, failing since
2026-10-16): never.

What was removed to get here: the old `deploy.yml`/`deploy-fleet.sh` admission
chain (dispatch, admission, Vault signing, polling); the 3-4 min release build
now runs beside lint and race (#72) instead of after them; restart delay 5 s ->
1 s. Remaining time per region is the binary download from GitHub releases
(~3-6 s, the accepted column) plus restart and SwarmKit reopen (~3-4 s).
Merge -> live is dominated by CI checks (~8-13 min, race shards).
