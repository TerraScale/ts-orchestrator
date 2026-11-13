# Platform design

This is the target design of the TerraScale platform. It states decisions.
Later pull requests and operators read this page as the one source. Where
today's code differs, a Today line names the pull request or category that
changes it.

## Overview

One orchestrator binary, `ts-orch`, runs on every node of every region. Each
region is one SwarmKit cluster. Regions talk over an embedded NATS mesh.

The orchestrator owns releases, Oracle Cloud (OCI) resources, routing and
scaling. GitHub Actions only tests, builds and nudges.

## Releases

Releases are pull, never push.

CI on `main` tests and builds static `linux/amd64` and `linux/arm64` binaries
with `-trimpath -buildvcs=true`. It publishes them on the GitHub release
`ci-<sha>-run-<id>`. CI holds no production credential. CI cannot reach the
nodes.

A production release is a JSON manifest:

```text
{
  v,
  channel: "production",
  sequence,
  sha,
  created,
  binaries: {
    "linux/amd64": { url, sha256 },
    "linux/arm64": { url, sha256 }
  }
}
```

The manifest is signed with OpenSSH:

```sh
ssh-keygen -Y sign -n ts-orch-release
```

The signing key is one listed with role `release` in
`deploy/m1/allowed-keys.json`. That file is embedded in the binary. Changing
the list needs a release signed by a key that is already allowed.

PR C3 adds these commands:

| Command | What it does |
| --- | --- |
| `ts-orch release manifest` | Writes the manifest |
| `ts-orch release sign` | Signs it with an allowed `release` key |
| `ts-orch release verify` | Checks the signature |

Nodes poll for the newest manifest. A node accepts a manifest only when all
of these hold:

- the signature is valid;
- `sequence` is higher than the one the node already has;
- each binary's `sha256` matches the bytes at its `url`.

CI, or `ts-orch release promote`, may call `POST /v1/release/hint`. The hint
only shortens the wait. It carries no authority.

Rollout order is fixed. One node updates first. Then the rest of its region.
Then the next region. Two nodes of one region never update at once. A node
that is not healthy within the probation window rolls back and marks the
digest bad. That uses the existing probation and selfupdate code. The next
pull request for this path is C3b.

Later, a builder inside production rebuilds each commit and must produce
identical digests. A staging cell receives every build automatically before
production.

Today: CI pushes each build over NATS port 4222 with a GitHub OIDC token
(`internal/releasepush`). That path is removed after C3b is proven (C14).

## Identity and access

SSH keys are the identity. The roles are `read`, `operate`, `release` and
`fleet`.

The remote CLI authenticates by signing a challenge with the SSH agent (C4).

A key stored on a shared server where agents run never gets `release` or
`fleet`.

## Cluster shape

Every region has three manager nodes. Further nodes join as workers.

Join material lives in the Vault secret `ts-orch-join-<region>`. The secret
holds the manager token, the manager addresses and the mesh routes. The Raft
leader keeps the secret current (C5a).

Every manager runs the public edge. A request for a service with no ready
replica on that node goes edge-to-edge, once, to a node of the same region
that has one. The hop carries the peer credential and the header
`X-TerraScale-Edge-Hop` (C5b).

Edge certificates are shared per region through Vault secrets
`ts-orch-edge-<region>-<hash>`. Let's Encrypt allows 5 duplicates a week. A
stopping node answers 503 on `/healthz` for 20 s first (C5c).

Nodes live on private subnets with a NAT gateway. The only public address of
a region is its network load balancer.

## OCI ownership

One fleet document records the regions, the node count and shape, the load
balancer, DNS and the scaling limits. It is signed like a release, by a key
with role `fleet`.

A reconciler on the global leader creates and updates these resources:

- VCNs
- subnets
- NAT gateways
- NSGs
- instances
- volumes
- network load balancers
- reserved addresses
- DNS records
- steering policies
- health checks

The reconciler authenticates as the instance (instance principal).

The commands are `ts-orch region add`, `ts-orch region edit`, `ts-orch region rm`,
`ts-orch region plan` and `ts-orch region status`. `ts-orch region bootstrap`
founds the first region from an operator machine. It is the disaster-recovery
path.

The reconciler touches only resources that carry its ownership tags. It
never deletes data volumes, buckets or backups by itself. Compartment quotas
cap spend.

It builds on this existing code:

| Code | Already there |
| --- | --- |
| `internal/oci` | OCI package |
| `internal/ociclient` | OCI client |
| `internal/ociresource` | Reconcilers for lb, nlb, nsg, seclist, routetable and bucket |
| `internal/ociregion` | foundation, publicapi and peer |
| `internal/edge/geodns` | GeoDNS |

## Routing

`dash`, `mcp`, `platform` and `auth` under `terrascale.tech` use GeoDNS. GeoDNS
is an OCI steering policy with health checks. The zone is
`edge.terrascale.tech`, delegated from Cloudflare. Each name resolves to the
nearest healthy region's load balancer.

`<region>.api.terrascale.tech` is a plain record to that region's load
balancer. The labels in use are `gru`, `sjc` and `fra`. Every new region gets
its record automatically.

`api.terrascale.tech` uses GeoDNS too, for testing convenience only. SDKs do
not use it except as the fallback when Atlas is unreachable.

## Atlas

Atlas is a Cloudflare Worker at `atlas.terrascale.tech`. Its code is
`atlas/` in the terrascale repo.

| Store | Role |
| --- | --- |
| D1 | The record |
| One Durable Object | Every write, in order |
| KV | The worldwide read cache |

The routes are `/v1/discovery`, `/v1/resolve`, `/v1/keys` and a signed
`POST /v1/publish`.

The orchestrator publishes topology every 10 s. TerraBase publishes every
database's home region on create, on move and on delete, through an outbox,
and re-sends every 10 minutes. One placement per database:

```text
{v, project, database, region|null, updated}
```

A region's `api` origin must be `https://<label>.api.terrascale.tech`.

## SDKs

On first use for a database, an SDK asks Atlas once. It caches the answer in
memory and on disk. The disk cache is the user cache directory, mode `0600`.
From then on the SDK talks straight to `<region>.api.terrascale.tech`.

The SDK asks Atlas again only in two cases. The region answers HTTP 421, and
the SDK reads `X-TerraBase-Database-Home`. Or the region stops answering.

When Atlas is unreachable and nothing is cached, the SDK uses
`api.terrascale.tech`. An explicit base URL skips Atlas. An SDK accepts only
hosts under `api.terrascale.tech`.

## ts-auth in every region

Step 1. Replicas run in every region. All of them use one ts-auth database
homed in `gru`. That database stays the single writer. `auth.terrascale.tech`
is geo-routed. There is one SMTP endpoint.

Step 2. Each region has a readable copy, and the home can be promoted.

## Scaling and self-healing

Replicas scale on CPU, memory and requests
(`internal/swarmruntime/autoscale.go`).

A node is added when load stays high, or when tasks cannot be placed. A node
is drained and removed when load stays low. The count never goes below three
managers. The last copy of a database is never removed.

A region is created automatically when demand from a geography stays high,
and only inside an allowed list and a budget. A region is removed only when
it is empty.

A node that stays unhealthy for too long is replaced.

## What was removed

C2 deletes the old controller, the host agent, the cell spec and signed
channel generation. `single-host` is the node runtime. It will be renamed `ts-orch node`.

## Order of work

| Phase | Work | Done when |
| --- | --- | --- |
| 0 | Scouts and this document | This document is the design source |
| 1 | Purge | C2 has deleted the old controller, host agent, cell spec and signed channel generation |
| 2 | Signed pull releases and the SSH CLI | Nodes accept only a signed manifest with a higher sequence, and the remote CLI signs a challenge (C3, C3b, C4) |
| 3 | Three managers and the edge everywhere | Join material, the one edge hop and shared edge certificates match Cluster shape (C5a, C5b, C5c) |
| 4 | Fleet document, reconciler, load balancers, private subnets | A signed fleet document reconciles those resources, and a region's only public address is its network load balancer |
| 5 | New fleet from bootstrap, data restored, DNS switched, old servers deleted | `ts-orch region bootstrap` has founded the fleet, data is restored, DNS points at it and the old servers are gone |
| 6 | GeoDNS, regional names, Atlas, SDK resolvers, ts-auth step 1 | Routing, Atlas, the SDKs and ts-auth step 1 match this document |
| 7 | Autoscaling of replicas, nodes and regions, ts-auth step 2 | Scaling and self-healing and ts-auth step 2 match this document |
| 8 | Drills: node loss, region loss, bad release, Atlas down, region add and remove | Each drill has linked proof |
