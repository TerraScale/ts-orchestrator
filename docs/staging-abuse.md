# Staging abuse lane

Run from the repository root, after the COS reports STAGING-UP:

```sh
python3 test/e2e/abuse/run.py
```

One command runs all twelve named cases, including the nine workload/fault
cases. Every case prints PASS or FAIL with elapsed seconds and measurements;
any failure makes the command exit 1. Preflight refusal prints attempted=0
for every case and exits 2. The PR stays draft until the full staging output
has been pasted into its body and each failure routed to its owning category.

The runner needs Go, Python, iproute2, the authenticated OCI CLI and existing
SSH access as ubuntu with passwordless sudo on staging's NetBird names.
It uses existing permissions; it does not install credentials or authorize
new permissions. The many-source flood needs three locally assigned public
IPv4 addresses with distinct public egress, two attackers and one healthy
client. Private and mesh source addresses bypass C18's public-source quotas
and cannot qualify that case. No missing dependency counts as a pass.

## Production guard and fault scope

The command accepts no arguments, target URL, region override or endpoint
file. It reads the label containing the exact staging token from
deploy/fleet/fleet.json; exactly one entry must match. Its compartment and
VCN must be distinct from every production entry, its hostname must not be
globally steered, and its fleet node bounds must fit within one to three.
It must have no production GeoDNS continents, and live steering policies in
the fleet DNS compartment must not contain its NLB addresses or API name.

OCI inventory must contain exactly one active orchestrator-owned NLB with
that label, in that compartment, with the network-load-balancer/nlb resource
key. The NLB's public IPv4 addresses must exactly match its regional API DNS
name. Every backend for ports 80, 443 and 5432 must belong to a running
instance's primary VNIC in staging's private subnet. Workload sockets dial
these pinned addresses, verify TLS and never follow redirects.

Before each remote operation, host.py checks OCI IMDS v2 for the exact
instance ID and staging compartment. The regional control executable repeats
that attestation, validates the cluster's region and OCI instance IDs, and
rejects more than three ready nodes. Before each mutation, OCI inventory is
refreshed; a new node's VNIC is verified before installing a workload on it.
Names containing desktop are refused. Nothing runs on mariogk-desktop.

The Go control helper uses ts-orch's local, TLS-authenticated SwarmKit control
API and its ApplyServiceSpec/RemoveServiceSpec implementation. It never uses
the mesh-wide service apply/rm CLI. This preserves the regional boundary even
when production regions are visible through the mesh. The helper can mutate
only the current randomly named abuse namespace.

Each scenario owns an abuse-<random> namespace, service labels, application
tenant identities and DNS names below that namespace's abuse subdomain of
staging's API name. The healthy and noisy apps have separate victim/attacker
tenant labels; single-replica healthy, noisy and leak workloads are placed
together on an attested staging node. This exercises resource isolation
between synthetic app tenants rather than customer account provisioning.
Multiple-replica protocol/fault workloads spread across staging nodes.

DNS operations read the fleet's existing authoritative zone and add/remove
only the new staging abuse hostnames. They never replace an existing name or
a globally steered record. Platform certificate reconciliation provisions
their certificates. Generated database passwords travel only over SSH stdin
and into the staging task environment; they never enter arguments, logs, git
or the PR. OCI/provider errors and remote output are withheld.

## Budgets

This is the one budget table. Latency values are read from
deploy/observability/production/latency-budgets.json, copied unchanged from
C22 PR #405 at 93f1ba3f9d4663a2a49d1068898ea57e06768f78 while it was draft.
The runner matches staging's OCI region to the existing regional API row;
production names in that file are evidence labels, never network targets.
The array positions are p50, p95 and p99, in seconds.

| Budget | Value | Source |
| --- | --- | --- |
| GRU fresh first-byte p50/p95/p99 | 0.12 / 0.15 / 0.20 s | C22 JSON, gru.api HTTP fresh |
| GRU kept first-byte p50/p95/p99 | 0.05 / 0.075 / 0.10 s | C22 JSON, gru.api HTTP kept |
| SJC/FRA fresh first-byte p50/p95/p99 | 0.70 / 0.80 / 1.00 s | C22 JSON, regional HTTP fresh |
| SJC/FRA kept first-byte p50/p95/p99 | 0.25 / 0.30 / 0.40 s | C22 JSON, regional HTTP kept |
| Healthy errors during admission, tenant isolation, OOM, disk and scaling | 0 | T6 DONE WHEN |
| Recovery after node loss | 4 min, with error count and longest outage reported | C14, internal/swarmruntime/liveness.go readinessWindow |
| Replica observation, up/down | 340 / 600 s | C11, default 60 s signal window + stabilization + cooldown + service readiness bound |
| Node observation, up/down | 35 / 60 min | C12, UpWindow + UpCooldown + LaunchTimeout; DownWindow + DownCooldown |
| New workload readiness | 240 s | serviceRollout + 2 x DefaultReadyTimeout |
| HTTP source/node connections | 128 / 32768 | C18, internal/edge/limits.go |
| HTTP incomplete header deadline | 10 s | C18, public ReadHeaderTimeout |
| Header buffer | 64 KiB | C18, MaxHeaderBytes |
| HTTP body progress | 64 KiB per 10 s | C18, bodyProgressBytes/bodyProgressWindow |
| HTTP maximum body | 32 MiB | C18, edge.go MaxBytesReader |
| Replay memory/body budgets | 1 / 8 MiB | C18, replay.go memReplayBody/maxReplayBody |
| HTTP idle / WebSocket write-idle envelope | 120 s | C18, clientIdleTimeout |
| WebSocket source/node sessions | 64 / 512 | C18, regional.go |
| PostgreSQL handshake / idle | 10 / 600 s | C18, postgresHandshake/postgresIdleTimeout |
| PostgreSQL source/node sessions | 64 / 1024 | C18, maxPostgresSourceConns/maxPostgresConns |
| Maximum source socket-buffer retention envelope | source connection limit x header buffer | C18, both operands above; measured orchestrator RSS growth must fit |
| Staging node ceiling | 3 | T6, bounded again by the staging fleet entry |

C18 numeric limits and protocol deadlines are read directly from the source.
The latency sampler measures the first received response byte before parsing
headers or draining the body, including connection/TLS setup on a reconnect.
A healthy client makes at least 100 observations for a nearest-rank p99.
Normal checks use the kept p99; the node-loss case permits reconnects and
uses fresh p99 while requiring recovery within C14's window. The node-loss
request loop continues during the fault, counts every error and measures
the longest interval without a successful response. Ordinary scenario
errors are never retried.

The node and replica observation bounds come from the controller's windows,
not substituted latency allowances. Fixed node bounds are proved to stay
fixed under replica-scaling pressure. With different min/max bounds the
runner observes automatic node growth and shrink and checks OCI capacity
throughout; it never provisions a node itself.

C18 currently exposes a WebSocket write deadline; the lane also asserts that
a fully idle established WebSocket is actually closed within that envelope.
If the listener lacks an idle-session cut, this is a C18 failure to route,
not a reason to weaken or skip the case.

## Scenarios

The stateless probe is compiled for staging's architecture and packed into
a digest-pinned scratch OCI image. The archive is imported on attested
staging nodes without publishing to a registry. These apps use the runtime's
normal stateless task-port, CPU bursting and autoscale paths. PostgreSQL is
the real official 18-alpine image, pinned to per-architecture manifests in
test/e2e/abuse/images.json; no TerraBase binary is downloaded. The probe strips
the edge's validated PROXY v2 address header before forwarding the session
to stock PostgreSQL, which does not understand that transport header.

- HTTP floods fill each attacker's C18 source allowance across the NLB's
  possible backends, require explicit 429 refusal, and issue 100 requests on
  every accepted connection while measuring a healthy client. Connection
  failures without a quota response cannot qualify the case.
- Slow headers and bodies hold incomplete requests to C18's real deadline.
  The body case also sends an oversized upload to a real body-consuming
  app. Socket counts and orchestrator RSS are checked after client cleanup.
- WebSocket and PostgreSQL cases first establish real sessions, exercise
  source caps, and hold an authenticated/echo-proven session idle. PostgreSQL
  verifies the SCRAM server signature. Both require deadline closure and
  released sockets/memory, alongside a healthy app client.
- The noisy tenant repeatedly calls its own CPU-heavy service. Its request
  counter must grow without errors while the other tenant meets X5 p99.
- The leak app is triggered only after readiness. The case requires a new
  running task ID, a killed task, an incremented kernel OOM counter,
  unchanged orchestrator PIDs and surviving neighbouring task IDs.
- Disk pressure allocates a uniquely named file on the orchestrator's real
  filesystem until ENOSPC, including the final filesystem blocks. The case
  requires healthy platform/client traffic and unchanged platform tasks,
  then deletion, recovered free space and platform readiness. A platform
  failure is reported; this case qualifies the stay-up branch of T6.
- Replica load observes actual automatic growth followed by shrink, keeps
  the healthy client running through both phases, and requires zero load
  errors. Node load exercises automatic growth/shrink if fleet policy
  allows; fixed staging policy must retain its exact node count.
- Node loss terminates a verified staging instance through OCI during live
  traffic, requires its running work to move and clients to recover, then
  restores the fleet's declared node count. Its compartment is checked again
  immediately before termination. Cleanup invokes only staging's native
  region apply compute implementation after checking its embedded fleet
  compartment and maximum of three; it never starts a stopped fourth node.

## Cleanup and evidence

Exit stacks acquire cleanup before service creation and fault injection.
Each scenario removes its services, waits for orphaned running tasks to
disappear, removes only its DNS records, removes imported probe-image
references and deletes its private workload directory. The idle probes close
all client sockets before resource-release assertions. Interruptions close
the healthy sampler and all owned connections.

The disk fault runs in a transient systemd unit with RuntimeMaxSec equal to
C14's recovery window and an independent ExecStopPost removal action. It
therefore releases space even if the harness is killed. Fleet restoration
runs in finally using staging's declared compute bounds; a missed self-heal
deadline remains a failure. OCI-terminated or
autoscale-removed nodes need no SSH cleanup; their lifetime ended.

Only new-service/certificate readiness, initial disk filling and resource
release are observed with bounded readiness waits. Fault/workload assertions
are evaluated once. Replica/node/task state changes use SwarmKit watches;
there is no CI polling loop and no sleep or retry added to product code.

The safe refusal proof is:

```sh
python3 test/e2e/abuse/run.py gru
```

It must exit 2 with attempted=0 and no workload traffic. The no-argument
command also refuses before OCI access while staging is absent from the
fleet. The PR must contain the full live staging output after STAGING-UP.
Route each actual failure to C11, C12, C14, C18 or C20 as printed by the case;
setup failures belong to C21 until the harness itself is qualified.
