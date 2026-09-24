# Restricted regional host artifact delivery

Native host convergence consumes `NatsHostArtifactSource`. It no longer opens
`ORCH_ARTIFACTS` or accepts an arbitrary object name. The caller supplies its
admitted role, environment, cell and desired SHA-256 digest. OCI image roles
(including `ts-auth`) retain their separate digest-pinned container image path.
This protocol does not enable the production host entry point.

## Authorization and transport

Each chunk has a new Ed25519 request in the distinct signature domain
`terrascale-regional-host-artifact-v1`. The signature binds the full enrollment
digest (including issuer, region, node and scope), process session, epoch, role,
artifact digest, offset, length, nonce and UTC time. Selection replies, reports
and session requests cannot authorize an artifact read. Requests expire after
ten seconds and have a 16 KiB wire limit. Duplicate, unknown and missing fields
fail closed.

The host publishes only its exact hashed observation subject with the
`artifact` suffix and subscribes to its exact command subject with
`artifact-<nonce>`. Existing restricted JWT/mTLS permissions suffice; there are
no new host inbox, JetStream, KV or object-store grants. The controller derives
the private object name as `sha256-<hex>`.

For every chunk, the controller checks the signed current session and exact
role/environment/cell target before and after reading bytes. Positive session
and target reads are confirmed through unchanged CAS operations to reject
stale replicas. A missing or different target denies access. These checks are
instant authorizations, not execution leases or promises against later target
updates or revocation. Workload execution still requires the independent host
lease, its expiry watchdog and shutdown path.

Replies bind the request digest, nonce, enrollment generation, epoch, digest,
offset, total bytes, exact chunk length and end marker. Expiry cannot exceed
the checked session or request freshness window. The host rejects inconsistent
lengths across chunks, noncanonical base64, malformed replies and late replies
after cancellation. Every chunk uses the latest signer, while the complete
transfer must retain one enrollment, process session and epoch. Renewal of that
same session is allowed. Temporary store unavailability and contention retry
with fresh proofs inside the five-minute transfer deadline; an exchange has a
five-second deadline. Failed transfers remain private partial files that the
convergence installer removes. The host verifies the complete requested digest
before the executable is installed, even though the controller also verifies it.

## Controller cache and resource bounds

NATS.Net 2.7.2 exposes whole-object reads, not range reads. Its package pins
source commit `17cf6665ffd9618942bac54c6accd1ec396a2c02`. The controller streams
each cache miss once into a private, immediately unlinked file, verifies the
requested SHA-256 and then serves ranges from its open handle. No whole-object
memory buffer or repeated whole-object read per chunk is used. SDK metadata
links are rejected when observed before or after the download; metadata
identity changes are rejected. The SDK can follow a concurrently changed link
internally, but no fetched bytes become available without the requested digest
check. This is not an arbitrary object-store proxy.

Bounds per controller:

| Resource | Bound |
| --- | --- |
| Artifact | 512 MiB, nonempty |
| Decoded chunk | 512 KiB |
| Reply JSON | 704 KiB |
| Cache disk, including reserved partial download | 1 GiB |
| Verified cache entries | 8, evicted by recency |
| Unfinished object downloads | 1 |
| Object-download deadline | 2 minutes |
| Queued requests / replies per exchange | 16 / 1, drop overflow without blocking the connection |
| Unfinished request storage operations | 1 per artifact service |
| Request storage / reply-delivery deadlines | 3 seconds / 1 second |
| Failure identities retained | 1,024 nodes, with sticky overflow |

The 512 MiB artifact bound accommodates the inspected local TerraBase binary
(41,076,336 bytes) and orchestrator x64/ARM64 single-file binaries
(96,460,343 / 103,359,283 bytes). These measurements size this transport; they
are not a fresh release qualification. `ORCH_ARTIFACTS`'s existing 8 GiB limit
is the whole store's limit and is not a per-artifact allowance.

Cache capacity reserves the maximum artifact size before a download begins.
Pinned chunk readers cannot be evicted. A cancelled request does not cancel a
download shared with later requests; the download has its own deadline. A
dependency ignoring cancellation occupies its single slot until it returns;
retries cannot accumulate abandoned downloads. Synchronous blocking storage
cannot block the separate session-renewal service. Expired or disposed fetches
cannot publish a cache entry. Shutdown closes cached handles; the OS reclaims
unlinked files when remaining handles close, including after a process crash.

Each controller can reconstruct its cache independently. Queue delivery needs
no controller affinity, and a controller restart loses only cached bytes.
An R3 controller cluster may therefore hold up to 3 GiB of these caches. Cache
files are not retained data volumes, adopted workloads or execution grants.

## Status and metrics

`NatsRuntime` starts, monitors and disposes the artifact service and cache when
regional host sessions are configured. Authenticated operator status includes
`host-artifact` (`reading`, `listening` or `retrying`) and
`host-artifact:retry-request` when storage or reply delivery failed. Activity
progress uses the existing busy/idle convention (0/100); it is not a fleet
rollout percentage. A successful request from another host cannot clear a
pending failure.

Process metrics have only the cell and bounded outcome labels:

- `terrascale.orchestrator.host.artifact.requests`: accepted/rejected/failed.
- `terrascale.orchestrator.host.artifact.bytes`: successfully published bytes,
  including retries; it is not a host installation acknowledgement.
- `terrascale.orchestrator.host.artifact.retry_pending` and `.in_flight`.
- `terrascale.orchestrator.host.artifact.cache.bytes`: verified retained bytes.
- `terrascale.orchestrator.host.artifact.cache.entries` and `.downloading`.

## Remaining host and OCI gates

The [artifact publisher](artifact-publication.md) now snapshots input and uses
conditional immutable chunk/metadata writes. Same-digest retries share a single
verified prefix without metadata replacement or purge. Abandoned different
digests still consume the bounded store: safe automated retention/reclamation
remains a deployment gate. Hosts have no private-store or purge access.

[Durable cycle/backoff bookkeeping](host-convergence-cycles.md) now uses a
restricted signed protocol. Regional replacement leases still require one:
core convergence retains a controller-supplied runtime KV seam for replacement
in tests. Production host startup must recover local workloads before obtaining
broker credentials or an execution lease. Native queued-job quiescence,
external-command cgroups, storage-writer fencing and exact drain receipts
remain separate requirements.

The region source remains `ts-infra`'s `terrascale_supported_regions` and
generation-tagged region intent. Signed first boot, founding peer/quorum
delivery, seed ownership transfer, regional foundation reconciliation and
retained-volume lifecycle still gate automatic regional takeover. Local
transport tests do not prove guest Instance Principal/Vault IAM or native
ARM64 behavior. Complete those gates before enabling OCI staging.
