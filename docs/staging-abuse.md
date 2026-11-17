# Staging abuse lane

Run from the repository root:

```sh
python3 test/e2e/abuse/run.py
```

This is an incomplete staging lane, held as a draft until its dependencies and
fault scenarios are implemented and a full staging run is attached to the PR.
It currently implements HTTP admission and request floods from one or two
sources, with a concurrent healthy client, and incomplete HTTP headers.
The remaining nine scenarios report FAIL with their owning category and
dependency. An unavailable scenario never counts as a pass. Preflight failure
prints attempted=0 for every scenario and exits 2; a scenario failure exits 1.

## Guard

The command accepts no target, positional argument, environment override, URL,
redirect or endpoint file. `staging()` reads `deploy/fleet/fleet.json` and
requires exactly one `label=staging` entry. Its compartment and networks must
be separate from every other fleet entry. Its node bounds must be within
one to three. Its derived `staging.api.<fleet DNS zone>` hostname cannot be in
the globally steered names.

Before opening any workload socket, the guard reads OCI inventory in that
compartment and OCI region. It requires exactly one active `staging-1-nlb`
with the orchestrator's managed-by, owner and
`STAGING/network-load-balancer/nlb` resource tags. DNS IPv4 results must
exactly equal that NLB's public IPv4 addresses. It verifies the running node
count, reads each instance's primary VNIC, checks its private subnet and
requires every port 80, 443 and 5432 backend to belong to those nodes.
All workload connections dial those pinned IPv4 addresses directly with
certificate verification and the staging hostname as SNI. HTTP redirects are
never followed. If C16 publishes a different staging identity or resource-key
convention, adapt this guard to C16's actual contract before any live run.

Only `/edge/ready` is requested. This endpoint is handled by the receiving
edge before peer routing, so these probes cannot follow the service mesh into
a production region. This slice does not submit service specs, delete
services, SSH, invoke an OCI mutation or inject a node fault. Existing
`service apply` and `service rm` fan out across the mesh and must not be used
to implement the remaining scenarios.

The guard can be demonstrated without reaching any region:

```sh
python3 test/e2e/abuse/run.py gru
```

Expected: `FAIL staging-preflight attempted=0 reason=no target or argument
accepted; staging is discovered`, one FAIL per scenario, exit 2.
The no-argument invocation also fails before OCI or socket access while the
fleet document has no staging entry.

## Budgets and evidence

This is the single budget table. X5's numeric latency budget and source are
not present on this base. The lane refuses workload traffic until that row
contains X5's measured value and an existing repository-relative evidence
path in the form `X5: docs/...`. Do not insert an assumed p99. X5's evidence
must cover the same client-observed complete-response measurement used here;
an edge-internal histogram alone is not interchangeable with that measurement.
C18 values below come from its code on this base; the runner reads the HTTP
source limit and header deadline directly and refuses changed source shapes.

| Budget | Value | Source |
| --- | --- | --- |
| healthy_p99_seconds | pending | X5: missing latency baseline |
| Healthy request errors | 0 | T6 DONE WHEN |
| HTTP connections per public source per node | 128 | C18: internal/edge/limits.go, maxSourceConnections |
| HTTP connections per node | 32768 | C18: internal/edge/limits.go, maxPublicConnections |
| Incomplete headers, seconds | 10 | C18: internal/edge/edge.go, ReadHeaderTimeout |
| Body progress, bytes per window | 65536 | C18: internal/edge/limits.go, bodyProgressBytes |
| Body progress window, seconds | 10 | C18: internal/edge/limits.go, bodyProgressWindow |
| HTTP idle, seconds | 120 | C18: internal/edge/edge.go, clientIdleTimeout |
| Replayable HTTP body, bytes | 33554432 | C18: internal/edge/edge.go, MaxBytesReader |
| WebSockets per source / total | 64 / 512 | C18: internal/edge/regional.go |
| WebSocket idle deadline | pending | C18: no established-session idle deadline found in upgrade.go |
| Postgres handshake, seconds | 10 | C18: internal/edge/postgres.go, postgresHandshake |
| Postgres idle, seconds | 600 | C18: internal/edge/postgres.go, postgresIdleTimeout |
| Postgres sessions per source / total | 64 / 1024 | C18: internal/edge/postgres.go |
| Node-loss errors and recovery deadline | pending | X5/C14: no published bound on this base |
| Staging node count | at most 3 | T6; actual bounds read from fleet document |

The flood fills up to the documented per-source allowance times staging's
maximum node count, then opens one excess connection for each attacker.
The finite request phase sends 100 requests on each accepted connection;
32 client workers bound concurrent connection establishment to C18's refusal
worker capacity. The healthy client uses a connection established before
saturation, runs throughout both phases, and needs at least 100 samples for
a nearest-rank p99. Output includes accepted connections, HTTP 429 refusals,
request count, other failures, sample count, errors, p99 and its budget.
Unclassified connection failures do not prove a working quota.

Sources are discovered from locally assigned public IPv4 interfaces using
`ip -j -4 address show`. Mesh, private and loopback sources are rejected:
C18 exempts them. The many-source case needs three addresses: two attackers
and a healthy client. They must have distinct public egress without source
NAT; this must be established in the live run evidence. A single-source case
preserves one healthy connection from that same source. Fresh-client admission
and many independent external load-generator hosts remain unqualified.

The slow-header probe leaves an incomplete header on each NLB IPv4 address
and requires actual connection closure at C18's header deadline. X5's p99 is
the allowance for client/network observation, not a substituted edge deadline.
These are observations through the NLB; they do not claim per-backend coverage.

## Remaining scenario work

Every row remains a failing scenario in the command until implemented. These
are dependencies and missing C21 work, not observed defects in other categories.

| Scenario | Owner to route findings | Required implementation and staging dependency |
| --- | --- | --- |
| Slow bodies | C18 | Isolated body-consuming route; trickle body; body-size and session caps; before/after socket and memory evidence |
| Idle WebSocket | C18 | Isolated echo route; completed handshake and real idle-session deadline; released socket accounting |
| Idle Postgres | C18 | Isolated database; private credential delivery; authenticated idle connection; released session accounting |
| Noisy tenant | C20 | Two isolated app tenants, one loading itself and the other measured against X5 |
| Task OOM | C14 | Region-scoped leak task and cgroup OOM evidence; changed task identity/restarts; healthy node and neighbours |
| Disk full | C14 | Identified staging filesystem; bounded fault with independent cleanup; platform health, alert and recovery evidence |
| Replica scale | C11 | Isolated scalable app; observe automatic growth then shrink while measuring zero errors |
| Node scale | C12 | Observe automatic node growth then shrink only if fleet min differs from max, never above three |
| Node loss | C14 | Verified staging instance; reversible fault and independent recovery; observed task movement and X5/C14 error bounds |

All currently implemented probes own only client sockets. Exit stacks close
every flood connection, stop and join the healthy sampler, and close each
slow-header connection on success, failure, SIGINT or SIGTERM. The command
prints exception types rather than provider output or response bodies, so
credentials cannot be echoed through those errors. OCI authentication uses
the caller's existing CLI installation; the harness creates no credentials.

The node scenarios must acquire cleanup before injecting a fault and prove
cleanup even when assertions fail. A missing dependency, missing observation,
or unimplemented operation must remain FAIL. Do not mark the draft ready until
the full run is pasted in the PR body, each discovered failure has its owning
category, and the COS has routed any unresolved failures.
