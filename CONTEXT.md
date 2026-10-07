# TerraScale Orchestrator terms

Use these names in code, issues, tests, and current documentation. The
implementation is a greenfield Go replacement; prior C# commands, wire
formats, and stores are not compatibility contracts.

**ts-orch CLI**

The preferred operational interface to the single Go executable. New
deployment, provisioning, bootstrap, release, and inspection tooling belongs
in Go subcommands in the relevant feature package, rather than Python scripts
or separate tools. CI and thin shell wrappers call these commands.
See [contributing](CONTRIBUTING.md) and
[CLI boundaries](docs/cli.md).

**Go testing**

All first-party tests use Go's standard `testing` package and `go test`.
Keep test cases, fixtures and assertions in Go alongside each feature.
Operational tools and qualification drivers are native Go APIs exposed
through `ts-orch`; tests exercise those APIs or the CLI. Do not add Python test runners.

## Product and regional control

**TerraScale Orchestrator**

One Go executable for regional control, host convergence, signed artifact
admission, and generic native-workload rollout. Forgejo Actions builds and
tests repository source. Managed OCI placement can provision a host and
retained volume and, after confirmed attachment, publish signed TerraBase
desired state; it then holds at `awaiting-healthy` and never reports a serving
TerraBase member.

**Regional cell**

One region's independent NATS and JetStream cluster. NATS routes join servers
inside that region; a JetStream quorum does not span regions. Every controller
uses a distinct instance identity and persistent store directory. A clustered
controller waits for the configured number of peers before writing replicated
state.

**Lab mode**

An explicit `nats.lab: true` setting for local and test use. It allows the
embedded broker to run without production credentials. It is not a production
security mode.

**Authority epoch**

A monotonically increasing fencing value attached to a mutation. A writer must
recheck the current authority before effects and before recording completion.
Delivery that reaches a terminal `held` receipt after fencing requires an
operator to observe the current state and submit a new intent after authority
recovers; the old operation is not replayed automatically.

**Global authority**

The cross-region policy and lease boundary planned around GRU and regional
autonomy. Package-level authority state exists, while production controller
election and OCI mutation remain unqualified.

## Hosts and workloads

**Host identity**

An Ed25519 key pair used by one host. The private key is stored in an
owner-readable file; the controller stores the public identity, node scope,
roles, and generation. A host also pins its controller's public response key.

**Desired generation**

A monotonically increasing version of one role's target on a host. The target
binds an artifact digest, region, host, role, environment, and authority epoch.
Equal generations are idempotent only when their content matches.

**Host report**

The host's signed observation of desired generation and process state. A
submission acknowledgement alone does not prove that a workload is running.
Status reads verify reports against the leader-served host session and desired
generation; a newer timestamp is acceptable when the report's meaning is
unchanged.

**Artifact cache**

The controller's single-object temporary spool used for chunked host delivery.
The shared bounded reader validates object metadata, chunk sequence and size,
and both the NATS object digest and admitted signed digest before bytes enter
the cache. It reads stream messages directly without creating a JetStream
consumer.

**Host session retry**

Startup acquisition and renewal retry only classified transient NATS failures.
If renewal remains unavailable, the agent stops native workloads before the
signed lease enters its five-second execution reserve.

**Native workload**

A digest-pinned executable started by the Go host runner in a dedicated cgroup
v2 subtree. Recovery examines that subtree before accepting new desired state.

**Static names**

A cell server's one name, from `internal/naming`: a node `ts-<region>-<n>`
(`ts-gru-1`, TS-609), or the older `<region>-<index>-<role>-<n>` with role
`ctl`, `db` or `gw` (`gru-1-db-2`), or `<region>-<index>-pool-<pool>-<n>` for a
node pool's host (`gru-1-pool-app-3`), used for OCI display names and NetBird
peers and as cell DNS labels (`ts-gru-1.gru.ts.internal`). A renamed GRU node
keeps `gru-1-ctl-N` as its internal NATS server name, certificate CN and
TerraBase member name. It never carries
a release, deployment ID, date or digest; those live in tags and launch
metadata.

## Artifact delivery

**Artifact record**

An immutable SHA-256 digest and size paired with an asserted source repository,
commit, and source-tree digest. A trusted signature and role/environment grant
are required before regional admission. The signature asserts provenance; it
does not prove that CI independently reproduced the build.

**Repository build**

The Forgejo workflow checks the exact source revision, runs Go tests, vet, race
checks, and builds static Linux amd64 and arm64 binaries. The current runner
prints checksums but does not retain downloadable artifacts or sign a
production release.

**Regional rollout**

After artifact admission, a signed intent selects the exact digest, role,
environment, generation, replica count, configuration digest, and authority
epoch. Hosts converge to that desired state. A rollback is a new intent for a
previously admitted digest.

**Held delivery**

A terminal receipt written when the operation's authority epoch becomes
fenced after its durable claim. Some desired-state writes may have succeeded
before fencing; operators must inspect host state and submit a new intent with
a new operation identity and generation under the current epoch.

## OCI and readiness

**OCI provider**

The provider seam behind regional control. Current tests use fakes; no live OCI
account mutation, automatic regional first boot, or production capacity
convergence has been qualified.

**Operator gateway**

The NetBird routing peer on the ts-ops host (`10.250.10.155`), reached from the
cell through one local peering gateway pair and source-NATed to that address.
The cell admits it only on TCP 22 (every server), 4222 (controllers), and 9465
(members), never on 8443. The private subnet keeps no internet route, NAT, or
public IP. The OCI Bastion remains the break-glass operator path. NetBird's
manager, routing peer and configuration (groups, policies, DNS) are owned by
ts-orchestrator; see `deploy/netbird/README.md`.

**Operator SSH**

Two independent SSH paths into every controller and managed host. NetBird SSH
listens on the server's NetBird address (`ts-gru-1.nb.ts.internal`)
and requires the operator's NetBird identity-provider login and the
`operators-to-gru-servers-ssh` policy. OpenSSH listens on the private
IP and accepts the owner's Ed25519 key, which controller A receives in OCI
`ssh_authorized_keys` launch metadata and forwards to every server it launches.

**Production readiness**

Evidence that the actual Go binary and its caller preserve authority,
durability, host recovery, safe scale-in, and rollback behavior under the
required failures. The app-level signed host-to-workload caller is tested with
an in-memory runner. The separate four-VM Firecracker qualification is needed
for guest execution and failure recovery. Passing package tests or a
fake-provider test alone does not establish production readiness.

## Storage limits

The default artifact object-store quota is 2 GiB; a cell spec
`artifact_store` section replaces the signed one. The embedded NATS file store
defaults to 8 GiB per server and startup requires at least 1.5 GiB beyond the
artifact quota for control state. The authority leader collects the store
every minute: it keeps artifacts desired or in an undecided delivery, each
role's rollback target, and anything touched in the last hour, deletes the
rest by compare-and-set on their metadata, and purges chunks of interrupted
uploads (see [storage](docs/storage.md#artifact-store-collection)).
Once the quota is full, new uploads fail with `ErrArtifactStoreFull`.

## Managed OCI placement

The placement file accepts `environment`, `member_role`, `resources`, and
optional `tick_millis`. Unknown fields are rejected. A zero tick selects the
five-second default; configured ticks must be between 100 ms and five minutes.
OCI intent, region configuration, and placement configuration must be
configured together. The host image, bootstrap, and signed host enrollment
remain operator-provided. After the retained volume is observed as attached
(`awaiting-runtime-contract`), the controller waits for the admitted runtime
artifact and a safe managed mount path, then publishes signed TerraBase host
desired state. The host verifies the pinned, exclusively mounted retained
filesystem and member material, launches TerraBase, and reports local process
and mount status. The controller then holds the member at `awaiting-healthy`
because no independent serving proof exists. It does not discover, format, or
mount the guest block device, claim health or serving, scale in, or
decommission a region. If OCI accepts a create but its
recovery result is lost before durable journaling, later matching tags alone
do not authorize adoption. The resource remains unowned and requires manual
inspection and reconciliation.
