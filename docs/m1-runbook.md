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
| Open ports | 80, 443, 5432 from anywhere; 22 from the operator egress IP |
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

## Postgres (pg.terrascale.tech:5432)

A spec's `"postgres": {"port": 6432, "hostname": "pg.terrascale.tech"}`
publishes a second loopback port; the edge serves it on public `:5432` over TLS
only (`sslmode=require`, or PG17 `sslnegotiation=direct` with ALPN
`postgresql`), with the same Let's Encrypt certificates as `:443`. A plaintext
startup gets `FATAL 28000` and never reaches TerraBase. CancelRequests go in
plaintext to every postgres port. At most 1024 connections at once.

ts-orch opens tcp/5432 in iptables at start; the edge NSG
(`ts-orch oci-region network <cell> --apply`) opens it in OCI. 6432 stays
behind the INPUT REJECT. Check:

```sh
ssh ts-gru-1 sudo iptables -S INPUT | grep -E 'dport (5432|6432)'   # 5432 ACCEPT only
psql "host=pg.terrascale.tech port=5432 sslmode=require user=... dbname=..."
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

## A second host in a region joins by itself

`ts-orch single-host` decides at start (`internal/app/single_host.go` `planHost`):

1. A host with stored swarm state (`/var/lib/ts-orch/swarm/admission.json`) keeps its role: the founder stays manager, a worker reconnects from its persisted manager list.
2. Outside OCI (IMDS `/opc/v2/` does not answer, e.g. a CI runner), the host founds a loopback-only cluster at 127.0.0.1:4242, as before.
3. A fresh OCI host reads the gru-vault secret `ts-orch-join-<region>` (JSON: `founder` hostname, `manager` address, `workerToken`, mesh `route`) with its instance principal. If the region has no such secret, the host creates it holding only `{"founder":"<hostname>"}`. OCI keeps secret names unique, so one claimer wins and founds the cluster. Every other host waits until the founder has published `manager` and `workerToken`, then joins as a `container` worker. Its HostID is its hostname and its InstanceID comes from IMDS.

The founder listens on 0.0.0.0:4242 and advertises `<private VCN IP>:4242`. A founder created before this change advertised 127.0.0.1:4242. At every start it re-registers its Raft member at the new address (same cluster, Raft log and services; `TestSingleHostFounderMovesAddressIntegration`). It publishes the join material, and updates it only when it differs. If Vault refuses (the hosts' IAM policy lacks `manage secret-family` for `ts-orch-join-*`), the founder logs `region join material not published; retrying` and retries every 30 s while it keeps serving.

Each host's mesh server joins its region's NATS cluster (name = region, `<private IP>:6222`, the same mesh mTLS). A worker dials the founder's `route` from the secret. A worker answers no ping, state or apply, so each region answers once, from its founder. Its `ts-orch mesh ping` and `service apply` reach every region over the cluster route. A worker advertises the region's gateway name (`<region>.mesh.terrascale.tech:7222`), so other regions always dial the founder.

Ports: 4242/tcp (SwarmKit) and 6222/tcp (NATS cluster) are reachable inside the VCN only. The host NSG admits all VCN traffic, the edge NSG opens neither port, and ts-orch adds the iptables ACCEPTs. A worker has no control socket or edge. `ts-orch service ls` and `member` work on the manager only.

Check and leave, on the manager:

```
sudo ts-orch member ls                  # HOSTNAME ROLE STATUS AVAILABILITY ADDRESS; the worker shows READY
sudo ts-orch member leave <hostname>    # drain, wait until its tasks stop (max 5 min), remove
```

A removed host cannot rejoin with its old identity. Terminate it, or stop ts-orch and delete `/var/lib/ts-orch/swarm` before it starts again. Services without mounts may run up to 8 replicas, at most one per host (host-mode ports). For example, whoami at `"replicas": 2, "regions": ["gru"]` puts one task on each gru host.

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

### Apps: new image digest -> new task serving, every region

`ts-orch service apply -f` on ts-gru-1 sends the spec over the mesh to every
region. Each node pre-pulls the image before touching the running task,
applies, then polls every 100 ms until the task is RUNNING and its `readyPath`
answers (#28); the reply carries the phases (ms since the node received it).

Measured 2026-10-22 on ts-gru-1 with a throwaway service `w14-speed`
(`docker.io/traefik/whoami`, arm64 child digests v1.10.3 `7865582e…` and
v1.10.2 `d57ef47b…`, port 8097, `readyPath /health`; removed afterwards).
A probe hit `http://127.0.0.1:8097/health` on gru every 50 ms during each
switch.

| Step | gru pulled / running / ready | sjc ready | fra ready | Wall (CLI) | gru probes failed | gru port refused |
|---|---|---|---|---|---|---|
| Create v1.10.3 (cold) | 697 / 1108 / 1212 ms | 1125 ms | 1105 ms | 1.35 s | - | - |
| Switch -> v1.10.2 (cold, never pulled) | 712 / 1530 / 1531 ms | 1092 ms | 1267 ms | 1.59 s | 9 / 77 | 0.48 s |
| Switch -> v1.10.3 (warm) | 2 / 516 / 516 ms | 628 ms | 619 ms | 0.86 s | 4 / 65 | 0.18 s |
| Switch -> v1.10.2 (warm) | 2 / 620 / 621 ms | 623 ms | 721 ms | 0.96 s | 7 / 67 | 0.36 s |

Targets: warm <= 10 s: met (0.5-0.7 s per region). Cold: 1.1-1.5 s for this
~3 MB image; larger images add their pull time to the `pulled` phase, which
ends before the old task is touched. Before #28 an update on a live port never
completed: the stopped task kept its port, the new task was rejected and the
update rolled back.

What was removed: the stopped container's port hold, the native snapshotter
(full copies per layer), the executor lock around pulls, SwarmKit's 1 s
cancel wait, the 30 s monitor (now 5 s) and 5 s restart delay (now 1 s); pulls
happen before the old task stops.

Zero-downtime through the edge (#111): one host port per service means the
old process exits before the new one binds (0.2-0.5 s refused above). The edge
retries a refused backend dial every 25 ms for up to 2 s, so clients see no
error. Proof 2026-10-22 on sjc and fra (`w14-speed` with
`"regions": ["sjc","fra"]`, hostnames `w14-sjc`/`w14-fra.terrascale.tech`,
probes every 50 ms from ts-sjc-1 through the public HTTPS edge):

| Edge | Updates | Probes `w14-sjc` | Probes `w14-fra` | Ready per update (40 region applies) |
|---|---|---|---|---|
| before #111 | 6 | 92, 25 failed (502) | 19, 4 failed (502) | 0.5-0.9 s |
| with #111 | 20 | 134, 0 failed | 45, 0 failed | 0.62 / 0.93 / 1.85 s (min / median / max) |
## Go-live proof: TerraBase, ts-auth, ts-dashboard (W12, 2026-10-22)

Host ts-gru-1 (163.176.124.12), ts-orch `b6a7f25dd` (main + this PR), specs
`deploy/m1/services/{terrabase,ts-auth,ts-dashboard}.json` applied in that
order with `ts-orch service apply -f`. Images pull from private GHCR with
`gru-1-ghcr-pull-token` (Vault, instance principal). Secrets reach the tasks
as `*_FILE` from `gru-vault`.

DNS (Cloudflare `terrascale.tech`, DNS-only, TTL auto), all -> 163.176.124.12:

| Name | Record ID | Change |
|---|---|---|
| `api` | `ca6cb548d99346fc4e5fef10b492069a` | A edited from the retired host 66.241.125.72; its AAAA `f57a336c…` deleted |
| `auth` | `0009eae684d826ac79981d4c54fb1ad5` | A created; the retired host's CNAME `20631e8b…` deleted |
| `dash` | `31e6166055f63ecd292b7d16ad8690d1` | A edited from the retired host 66.241.124.105; its AAAA `d55f47bb…` deleted |
| `netbird` | `a795b0e0754299b95fab9d7426e2938e` | A created |
| `whoami` | `0685c40e1acd61687aaf893ec3755d6f` | A created (multi-layer image test) |

Milestone 1 Done rows:

| # | Check | Result |
|---|---|---|
| 1 | `curl -fsS https://api.terrascale.tech/readyz` | 200 `{"status":"ready","revision":"e7fa366d…","region":"local"}` |
| 2 | `curl -fsS https://auth.terrascale.tech/healthz` | 200 |
| 3 | `curl -fsS https://dash.terrascale.tech/readyz` | 200 `ok` |
| 4 | OIDC issuer | `https://auth.terrascale.tech/terrascale` |
| 5 | `sudo ts-orch service ls` | terrabase, ts-auth, ts-dashboard `1/1 running`, `ghcr.io/terrascale/<svc>@sha256:1d91e807…`, `@sha256:d30a0d70…`, `@sha256:5c011ba3…` |
| 6 | Email-code sign-in as mariogk@terrascale.tech on dash | code mailed, verify 303 + `ts-dashboard-session`, `/api/v1/auth/me` email matches, onboarding (Free plan, project "M1 proof") -> Overview 200, orgs TerraScale + Personal, project listed |
| 7 | `systemctl restart ts-orch`, 60 s; then a VM reboot | rows 1-3 200 and dashboard data identical both times; after the reboot all 200 in ~7 min (13:39:14 -> 13:46:26 UTC) |
| 8 | `dig +short api auth dash` | 163.176.124.12 each, no AAAA |

Sign-in proof: `~/.local/state/w12-proof/src/w12_signin.py` on mariogk-dev
(read-only IMAP, mailbox password on stdin only; prints statuses, never codes).
Codes are limited to 5 per hour per email with a 60 s cooldown; the script
keeps the session (0600) so reruns need no new code.

Found and fixed on the way (this PR and #25): ghcr.io pulls (token name
`<cell>-1-`, blob redirect to `pkg-containers.githubusercontent.com`), canceled
long pulls failing as fatal, a private `/tmp` for the .NET single-file
services, and a port claim deleted by an empty containerd label. After a
reboot ts-dashboard (and netbird-server) start before their dependencies and
wedge without listening; the proof build restarted them with a 5 min liveness
check (the ~7 min). #97's `awaitReady` replaces it: a task that is not ready
in time is stopped gracefully and restarted.

Open:
- TerraBase names its region `local` outside a cluster, so onboarding accepts only
  `LOCAL`; project "M1 proof" is homed there. terrascale #349 (`TS_REGION`
  from ts-orch) fixes the name; re-home or recreate the project after it.
- `dotnet TerraScale.Dashboard.dll audit-stripe` (run in the task with
  `ctr -n terrascale t exec`): mode test, webhook endpoint, events and
  `webhook_api_version` (`2026-09-30.endive`) pass; the six published prices
  and the billing-portal configuration are missing in the Stripe account.
- ts-dashboard should exit when host start fails instead of hanging.
