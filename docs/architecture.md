# Architecture and boundaries

TerraScale Orchestrator is being rebuilt as one Go executable. The executable
has controller, host, and check modes. It embeds a regional NATS server when
running a controller; host processes connect to that regional cell. The
separate roles share one binary but use role-specific JSON configuration and
credentials.

## Regional cells

Each region has an independent NATS and JetStream cluster. NATS routes connect
the regional servers; the replicated JetStream quorum remains inside its
region. Every controller instance needs a distinct instance name and persistent
store directory. R3 nodes use route seed addresses to find their peers and
must observe the requested peer count before writing replicated control state.

`lab: true` explicitly enables the local unauthenticated fixture mode. Do not
use it outside tests or a disposable local environment. Non-lab connections
require client TLS and an NKey seed or JWT credentials file. A non-lab embedded
server also requires client and route TLS plus an allowed NKey list. See
[`internal/natscell/runtime.go`](../internal/natscell/runtime.go) for the
accepted JSON fields and startup checks.

## Authority, hosts, and delivery

The Go design separates global authority from regional state. A controller
must prove current authority before it admits a mutation; regional host state
uses monotonic generations and epochs so replayed or stale desired state can
be rejected. Hosts authenticate with per-node Ed25519 identities, report
observed state, and install artifacts by SHA-256 digest. Host status reads
verify session and desired generations against leader-served reports while
allowing a newer report timestamp when its meaning remains unchanged. The host
and controller share a bounded artifact reader that verifies object metadata,
chunk sequence and size, and both object and signed digests before the
controller caches bytes for host delivery; it reads chunk messages directly
without creating a JetStream consumer.

Forgejo Actions builds and tests repository source. The control plane owns
admission of signed immutable artifacts and rollout authority. Artifact
admission records verified content metadata outside the authority log; it does
not grant mutation authority. Before deployment, the controller rechecks the
current policy, signature, and artifact bytes, then requires current authority
and ordered desired-state writes. A host executes only the resulting admitted
desired state.

The repository workflow currently creates build outputs and digest evidence;
it does not publish or sign a production release. `ts-deploy` does not own
repository builds or rollout.

The app-level integration tests follow the signed path through host
registration, placement admission, artifact admission, deployment and status,
and host-agent delivery over NATS. Their workload runner is in memory; those
tests do not establish guest process execution or reboot recovery. The
four-VM Firecracker qualification passed for the pinned test image at source
revision `df09ee5692b4a5dc60230f019d1265efccb2f972`. It exercised native guest
execution, host restart recovery, deployment after one controller loss, and
rollback after quorum recovery. During controller loss, host session
renewal/reporting failed with
`context deadline exceeded`; systemd restarted the host agent and the workload
later returned to running. This demonstrates recovery, not uninterrupted
availability, arbitrary-kernel compatibility, or production host readiness.
See [local
qualification details](local-development.md#latest-local-qualification).

The default artifact object-store quota is 2 GiB. The embedded NATS file store
defaults to 8 GiB per server, and controller startup reserves at least 1.5
GiB beyond the artifact quota for control state. The object-store limit bounds
stranded chunks, but concurrent or interrupted uploads may leave those chunks
behind. There is no repository-managed cleanup path, automatic garbage
collection, or eviction of admitted objects. Once the quota is full, new
uploads fail with `ErrArtifactStoreFull`.

## OCI and capacity

Managed placement configuration is provided through the controller's
`oci_region_intent_file`, `oci_region_config`, and `placement_config` paths.
The strict placement file accepts `environment`, `member_role`, `resources`,
and optional `tick_millis`; a zero tick uses five seconds. Configured tick
intervals must be 100 ms to five minutes. These options are rejected unless
all three managed configuration paths are set together.

For admitted placement, the regional controller provisions an OCI host and a
retained volume, waits for the host's exact signed registration and a positive
`ATTACHED` observation, then durably holds the member at
`awaiting-runtime-contract`. It deliberately does not publish TerraBase host
desired state or claim the member is healthy or serving because the repository
does not yet provide an executable TerraBase launch contract or verified
volume-mount check. Host image preparation, bootstrap, and signed registration
remain operator steps; database serving, scale-in, and region decommission
are not implemented acceptance claims.

OCI provider coverage uses fakes; no live OCI account mutation has been
qualified. If OCI accepts a create but the recovery result is lost before
durable journaling, later matching tags alone do not authorize adoption; the
resource remains unowned and requires manual inspection and reconciliation.
Automatic first-region boot, cross-region authority recovery, and safe
retirement still need integration and failure-recovery evidence. The current
implementation is not production-ready.

## Implementation status

The codebase is a greenfield replacement. Archived C# configuration, NATS
subjects, stores, and runbooks are not compatibility contracts. Test receipts
from the previous implementation remain historical only; Go readiness is
measured by the current Go tests and real-caller qualification.
