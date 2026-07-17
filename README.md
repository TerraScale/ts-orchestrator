# TerraScale.Orchestrator

TerraScale.Orchestrator is the greenfield, TerraScale-specific control plane described in [ORCHESTRATOR.md](ORCHESTRATOR.md). The repository is executing Phase 0 evidence work and pure Phase 1 contract tranches in parallel, without deployment authority.

Owner choices 1A–10A are accepted with reliability first. Numeric cost, database-storage, RPO, and RTO targets remain evidence-derived deployment gates; they do not justify weakening R3 state, single-node-failure tolerance, backups, storage integrity, or security. The repository must not start a system-under-test VM or mutate cloud infrastructure before exact-tree L0/L0C evidence authorizes it.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --disable-parallel
dotnet build TerraScale.Orchestrator.slnx --no-restore --maxcpucount:1
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

The exact-tree `development-attest` command is the canonical complete local
run. It builds once, runs all five TUnit executables sequentially with at most
four tests active in a module, then runs policy tooling. A repository-wide
lease prevents it from overlapping a Podman lab. Its evidence records the
test count for every module and observed peak memory/process counts under a
14 GiB execution ceiling, leaving 2 GiB of the 16 GiB local budget for the
host. `lab up` rejects legacy or incomplete evidence that omits this bounded
inventory.

All repository validators, generators, audit utilities, conformance checks, and
their tests are implemented in C#. The dependency-free tooling executable
replaces the former Python scripts and exposes named commands for each domain:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- nats-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- supply-chain
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-validate
```

Run the executable without arguments to list every command. The translated
test suite also fails if a Python source file is reintroduced.

The repository produces one operational Orchestrator binary, a dependency-free policy/evidence tool, and a test executable. The `check` command exercises the production controller startup path against a real JetStream-enabled NATS server, then exits cleanly. The `lab` command runs the pinned, rootless-container development adapter used by DevHost. Real systemd and OCI A1 qualification remain separate production-boundary gates.

## Run

The orchestrator requires NATS with JetStream enabled. `check` reconciles the regional control resources, verifies the NATS service endpoint through request/reply, and exits. `run` performs the same checks and keeps the discoverable service online until shutdown.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
dotnet run --project src/TerraScale.Orchestrator -- check

dotnet run --project src/TerraScale.Orchestrator -- run

dotnet run --project src/TerraScale.Orchestrator -- \
  operator status --cell gru --nats-url nats://127.0.0.1:4222 \
  --nkey-file /run/credentials/terrascale/operator-read.nk \
  --tls-ca-file /run/credentials/terrascale/ca.pem \
  --tls-cert-file /run/credentials/terrascale/operator.pem \
  --tls-key-file /run/credentials/terrascale/operator.key.pem
```

`operator status` is a read-only NATS request/reply operation. The regional
service validates and returns its cell, controller instance, R3 configuration,
exact build, start/observation times, and implemented capability inventory.
It also reports the current regional authority state, fencing epoch, KV
revision, and lease expiry. The CLI rejects a response from another cell, an
expired lease, contradictory leader state, or an invalid/unready projection.
The optional `--nkey-file` (or `TS_ORCH_NATS_NKEY_FILE`) must be an existing,
bounded owner-private seed file; raw key material is never accepted on the
command line.
The TLS CA, certificate, and key options (or matching
`TS_ORCH_NATS_TLS_*_FILE` variables) are atomic: all three must be present,
the PEM identity must match its owner-private key, and TLS is required rather
than opportunistically negotiated.

The `run` and `check` paths emit correlated OpenTelemetry traces, metrics, and
structured logs through the pinned OTLP exporter. Export is disabled when
`OTEL_EXPORTER_OTLP_ENDPOINT` is unset or empty and never affects product or
control readiness. Plaintext export is accepted only to a loopback collector;
a remote collector requires HTTPS. The standard OpenTelemetry mTLS variables
provide the CA, client certificate, and client key:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=https://alloy-gru.internal:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_EXPORTER_OTLP_CERTIFICATE=/run/credentials/otel/ca.pem \
OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=/run/credentials/otel/client.pem \
OTEL_EXPORTER_OTLP_CLIENT_KEY=/run/credentials/otel/client-key.pem \
terrascale-orchestrator check
```

The built-in signal attributes are deliberately bounded to cell, controller
instance, and startup outcome. Export queues and batches use the bounded
OpenTelemetry SDK processors; regional disk spooling and drop-oldest policy
remain the responsibility of the managed Alloy/Collector role.

Use `TS_ORCH_REPLICAS=3` with a production regional NATS cluster. Startup reconciles the `CELL_SPEC`, `CELL_OPERATIONS`, and `CELL_EVENTS` file-backed JetStream streams, the `ORCH_LEADERS`, `ORCH_RUNTIME`, and `ORCH_DELIVERY` KV buckets, the `CELL_BUNDLES` Object Store, and the cell-scoped NATS health service. It writes and reads the versioned protocol package through Object Store, whose retrieval verifies the stored digest, before accepting the bytes. Runtime registration is revision-fenced: startup creates and watches a unique `starting` entry, compares-and-swaps it to `ready`, observes that revision, and conditionally deletes it during shutdown. The health endpoint is distributed through a cell queue group; readiness verifies its standard NATS service discovery metadata and request statistics. The orchestrator also publishes a deduplicated startup event with protocol/cell/correlation headers, receives it through a bounded durable pull consumer, validates the metadata, and explicitly acknowledges delivery.

GRU global-controller candidates opt in to the separate global control account
only with the complete `TS_ORCH_GLOBAL_NATS_*` configuration. The connection
requires R3, a `tls://` endpoint, a valid private user NKey seed, and a complete
mTLS identity distinct from the regional account. The endpoint may be the same
GRU control-NATS cluster because account authorization is separate. Startup
then reconciles `GLOBAL_SPEC`, the global-account `ORCH_LEADERS`, the
64-revision-per-release `GLOBAL_RELEASES` KV journal, and the R3
`GLOBAL_BUNDLES` content store plus `GLOBAL_CI` inbox before reporting ready:

```bash
TS_ORCH_GLOBAL_NATS_URL=tls://control-nats-gru.internal:4222 \
TS_ORCH_GLOBAL_NATS_NKEY_FILE=/run/credentials/global-controller.nk \
TS_ORCH_GLOBAL_NATS_TLS_CA_FILE=/run/credentials/global-ca.pem \
TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE=/run/credentials/global-controller.pem \
TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE=/run/credentials/global-controller-key.pem \
terrascale-orchestrator check
```

Supplying any subset, reusing either regional identity, using plaintext, or
configuring fewer than three replicas fails before the global connection.

Native Forgejo ingestion verifies the raw payload HMAC before JSON parsing and
binds the signed repository to the configured endpoint. Its normalized event
contains no secret, signature, or raw payload. Global `GLOBAL_RELEASES` then reserves
both the Forgejo delivery ID and signed-payload digest with compare-and-set;
the normalized event is durably published to `GLOBAL_CI` with that payload
identity before both reservations become accepted. Only a matching, fully
committed identity pair produces an acknowledgeable receipt. Exact accepted
retries do not republish. A crash after publish reuses the same JetStream
message identity, while delivery collisions, altered-ID payload replays,
publisher failure, corrupt records, and interrupted writes fail closed or
resume before acknowledgement.

The shared explicit-ack `GLOBAL_CI` consumer fetches only on the current global
leader. It reconstructs the normalized event, reapplies the closed trigger
policy, and compare-and-sets the exact disposition, reason, trust zone,
capabilities, artifact-publication flag, qualified-candidate requirement, and
authority observation into `GLOBAL_RELEASES` before acknowledging the message.
Ignored and held events are durable decisions too. Followers, authority loss,
decision conflicts, corrupt events, and journal failure do not acknowledge.
This stage classifies input only; it cannot dispatch runner work.

Every accepted push or pull-request event also retains the exact base and head
Git object IDs. The authenticated Forgejo source adapter reads the bounded
`base...head` comparison, rejects empty, duplicate, unsafe, or oversized path
sets, and conservatively selects the whole repository policy for rename/copy
results whose old path is not present in the comparison response. The affected
pipeline coordinator starts only from the durable trigger decision, recovers an
already persisted pipeline before making source calls, reads this bounded exact
change set, and CAS-records the resulting immutable pipeline under the same
event identity. Authority loss before or during source resolution produces no
pipeline. Exact cross-repository descriptor and source selection is an injected
policy boundary; the coordinator never infers those inputs from moving refs.

Once supplied, the exact descriptor blobs, changed paths, source commits/trees,
trigger policy, controller generation, and runner evidence window are rebuilt
through the existing planners and stored as one immutable pipeline object in
`GLOBAL_BUNDLES`. A small CAS pointer in `GLOBAL_RELEASES` binds that object to
the Forgejo event. Restart recovery re-parses every descriptor and recomputes
the impact, pipeline, and job identities; interrupted writes resume, while a
second plan for the same event, corrupt content, or lost authority fails closed.

Each persisted pipeline can also initialize one compact CAS record per job.
Only dependency-ready work can prepare a dispatch, and preparation reuses the
closed runner selector plus the exact cgroup-v2, namespace, seccomp, network,
credential, cache, resource, and output-isolation policy. Prepared, dispatched,
running, success, and failure edges are strictly ordered and idempotent. A
higher global authority epoch increments the job fence; an old controller can
no longer advance it. Pipeline failure stops new dispatch, while successful
dependency evidence unlocks the next deterministic DAG nodes. Prepared attempts
also persist an exact two-hour deadline, encode a canonical bounded command for
the selected runner, require the configured command signer, and advance to
dispatched only after `GLOBAL_CI` returns a durable expected-stream
acknowledgement. Replay reuses the exact bytes and message ID plus the
acknowledged stream sequence. The runner-side inbox rejects malformed,
wrong-runner, expired, invalid-signature, stale-attempt, stale-authority, and
stale-fence commands. It stores the canonical command and signature by digest
in the isolated, 30-day `CI_RUNNER_BUNDLES` R3 bucket, advances a compact
monotonic pointer in `CI_RUNNER_JOBS`,
and acknowledges only after both objects survive readback and the pointer CAS
succeeds. Exact redelivery after an acknowledgement failure resumes from that
durable acceptance; higher fenced takeover and contiguous retry attempts can
replace it. A bounded runner pull adapter derives one durable exact-subject
consumer per runner, permits one in-flight command, rejects wrong
stream/consumer/sequence/redelivery metadata, and uses a double ACK only through
that durable inbox. Command signatures now use a protocol-owned, versioned
canonical encoding that covers every identity, fence, validity, payload, and
digest field without timestamp precision loss. The production identity adapter
uses the supported .NET P-256/SHA-256 implementation: an intermediate private
key is read only from a user-private systemd credential file, while runners load
one to four public-only trust keys and select overlap-rotation keys by their
SHA-256 SPKI fingerprint carried in the bounded signature envelope. OCI KMS
can therefore remain at the offline/root issuance boundary rather than exposing
a root key to the runtime. `TS_ORCH_COMMAND_SIGNING_KEY_FILE` and the
path-separator-delimited `TS_ORCH_COMMAND_TRUST_KEY_FILES` (or their typed JSON
configuration fields) are structurally validated with the rest of startup and
opened before any NATS connection. The process retains the loaded identity for
its lifetime and disposes it on shutdown. A generated runner NATS permission
plan is limited to its pre-created exact consumer, ACKs, own hashed KV journal
prefix, the dedicated runner bundle bucket, and reply inboxes; it cannot publish
jobs, use another runner's consumer or journal, mutate `GLOBAL_BUNDLES`, or call
stream purge. The controller can now reconcile each runner's exact durable pull
consumer and fail closed on altered server readback. A bounded issuer can mint a
STANDARD-only, 1–15 minute NATS user JWT/NKey lease from a private account or
scoped account-signing credential after that readback; it embeds only the exact
runner subject plan and zeroes retained seed buffers on disposal. Live credential
issuance is enabled only with global authority plus
`TS_ORCH_CI_RUNNER_NATS_ACCOUNT_SIGNING_KEY_FILE`; an optional
`TS_ORCH_CI_RUNNER_NATS_ACCOUNT_PUBLIC_KEY` identifies the parent account when
the credential is a scoped signing key. Typed JSON carries the same fields and
startup opens and retains the signer before any NATS connection. Live credential
delivery and exact cross-repository source-graph resolution remain separate
unimplemented gates; no unsigned runtime fallback is installed.
Only explicitly authorized transient feature-validation failures can retry:
attempts wait for the fixed 5-second then 30-second backoff, receive a new
idempotency key and higher fence, and stop after attempt three. Workload/policy
failures and trusted release builds remain terminal so candidate builds stay
clean, immutable first-attempt evidence.

Enable the listener only on the `run` command by supplying the complete
configuration below. The secret file contains the exact Forgejo secret bytes
(no automatic newline trimming), must be 32–4096 bytes, and must be private to
the service user. Plain HTTP is accepted only on loopback for a local ingress
proxy; a non-loopback listener must use HTTPS.

```bash
TS_ORCH_FORGEJO_LISTEN_PREFIX=http://127.0.0.1:8080/hooks/forgejo/ \
TS_ORCH_FORGEJO_REPOSITORY=TerraScale/TerraScale.Orchestrator \
TS_ORCH_FORGEJO_SECRET_FILE=/run/credentials/forgejo-webhook-secret \
terrascale-orchestrator run
```

Configure Forgejo to send JSON `push` and `pull_request` events to that exact
path. Successful durable acceptance and exact retries return HTTP 202;
authentication, collision, timeout, and journal failures never return a 2xx.

After exact commit/tree resolution, the closed CI trigger policy maps feature
PRs targeting `develop` and direct `develop` pushes to compile/test-only
untrusted validation. Only a same-repository `develop` → `main` PR may request
a trusted compile/test/sign candidate build, and that job receives no
production-deploy capability. A `main` push cannot build anything or directly
create runner work; it can only request resolution of the exact already
qualified candidate before promotion. Forks and lookalike branches targeting
`main`, protected-branch deletions, metadata-only actions, tags, and unsupported
refs cannot widen those trust or capability sets.

The command-free `terrascale.ci/v2` descriptor contract admits only closed
static/build/test/artifact nodes, feature/release profiles, bounded resource
weights, safe repository-relative path prefixes, explicit repository edges
with reasons, candidate retention, native/package/pages promotion policy, and
architecture sets. Its compiler rejects unknown or duplicate fields,
free-form commands, retired Flux strategies, missing/profile-narrowing edges,
cycles, unsafe paths, and native candidates that do not cover Linux x64 and
ARM64. The affected planner then requires every changed path to select an
explainable node, closes prerequisites and dependents transitively, propagates
cross-repository reasons, and emits a deterministic DAG digest. At the runner
boundary every accepted node maps to the fixed `.terrascale/ci.Dockerfile`
recipe and `ci-<node-id>` target through the `dockerfile.v0` frontend. The
repository cannot place an executable, argument, host path, or BuildKit
endpoint in the descriptor. The signed command directly retains the exact
`Any` or `linux-x64`/`linux-arm64` architecture set before this plan is built.
The controller-side Forgejo adapter can also fetch a bounded archive for one
already resolved exact commit, bind its repository, commit, tree, byte length,
and SHA-256 identity, and publish it under that content address in
`CI_RUNNER_BUNDLES` with full readback verification. This keeps the Forgejo
token out of runner jobs. The prepared-job CAS lease durably fixes that exact
object name, digest, and byte length across replay, takeover, and retry. Signed
CI job schema v3 carries the same identity into the runner execution plan;
legacy active records remain readable but cannot invent it. The runner-side
materializer verifies those signed bytes, admits one tar root containing only
bounded regular files/directories, applies private owner-only modes in a fresh
workspace, and rejects links, special files, traversal, duplicate paths,
corruption, decompression excess, and missing fixed descriptor/recipe files.
The next compiler emits one exact `/usr/bin/buildctl` argument vector against a
rootless `/run/user/<uid>/buildkit/buildkitd.sock`: fixed frontend, source
context, recipe and target; closed platform mapping; deterministic runtime-only
output/metadata paths; no shell; and a six-variable environment without a
Docker endpoint. Untrusted work disables cache reuse. The process adapter and
output validator then clear inherited environment, enforce timeout and a
combined log-byte ceiling, kill the whole process tree on cancellation, and
classify exit/timeout/log overflow. Raw output never crosses the process
adapter: only bounded UTF-8 lines that pass conservative password, token, key,
JWT, credential, URI-userinfo, and high-entropy redaction are returned with a
verified content digest. Successful local exports are accepted only with
bounded duplicate-free JSON metadata and a bounded, link/special-file-free
regular file tree; private modes and a culture-invariant content digest are
applied before returning evidence. A
runner-side coordinator now acquires and renews the exact execution fence,
materializes that source, invokes the closed executor, requires an idempotent
durable-result sink, and only then commits the terminal lease. Persistence
failure leaves the lease recoverable; crash takeover fences a stale terminal
write. The concrete sink stores the verified redacted log, a deterministic
owner-private tar/gzip archive re-hashed against the accepted output tree, and
canonical evidence under content addresses with full readback verification and
30-day object retention. A strict result manifest carries the required-test
skip count. Source bytes are removed before artifact capture and archive
overhead is reserved inside the signed ephemeral-disk budget. The runner
process mode is still absent, so no BuildKit daemon is invoked by normal
Orchestrator startup.

Release DAGs bind every affected repository to an exact commit and tree before
creating least-privilege trusted-build work. Candidate qualification requires
every planned job exactly once on its first attempt, no required skips,
content-addressed evidence, signed artifacts for every declared architecture,
and exact runtime-digest proof for native artifacts. A later `main` push
qualifies that candidate only when protected `main` observations for the whole
release set have the same tested trees; Forgejo may use different merge commit
IDs. A pure authorization gate can then create production-release work only
when signed deployment evidence, dependency and generated-schema locks, pinned
toolchain evidence, explicit approval, and all three compatibility directions
verify against that exact qualified release-set digest. The request identity is
also bound to its controller generation and runner evidence window. This still
uses no credential and executes no deployment. Its CAS journal admits one
authorization per qualified release set, fences takeover by authority epoch
and a monotonic token, resumes exact phase operations idempotently, requires
SFO then FRA then GRU verification, and unwinds affected regions in reverse.
The promotion coordinator journals every stable operation identity before its
external side effect, passes the current fencing token to an injected actuator,
and replays the same operation after interruption. It drives publish, SFO, FRA,
and GRU in order; any failed forward phase enters the journal's exact reverse
rollback path, whose own failed operation is safely resumable. Authority loss
stops before the next side effect, and a higher epoch adopts the phase with a
new fence. Registry publication, regional actuator and live-verification
implementations, and normal runner process wiring remain separate gates.

Candidates and their later main-tree qualifications survive controller restart.
`GLOBAL_BUNDLES` stores their bounded canonical records under a content digest,
while `GLOBAL_RELEASES` commits only a small immutable pointer after reading the
object back. Recovery revalidates and re-hashes the pipeline, impact, exact
source set, every first-attempt job result, every signed architecture-specific
artifact, runtime digest, and qualified main tree. A qualification cannot be
recorded before its exact candidate. Concurrent exact writes converge; pointer
collisions, corrupt or missing objects, interrupted writes, and a lost global
authority fail closed. Recording also commits a canonical repository/tree-set
index. Signed protected-main observations find the same candidate in any input
order; an interrupted index write is repaired by exact retry, while a second
candidate claiming the same tree set is an identity conflict. The candidate
coordinator consumes only a fully succeeded durable release run, loads exact
signed artifact evidence through an injected reader, reuses the closed
candidate assembler, and commits the immutable candidate and tree-set index
under current authority. Feature-profile, active, failed, incomplete, unsigned,
substituted, and authority-lost inputs produce no candidate. Retention cleanup
remains unimplemented. The qualification coordinator starts only from a durable
admitted protected-`main` trigger, snapshots injected signed protected-main
observations once, locates the immutable candidate by exact tree-set index, and
records the resolved qualification under current authority. Missing triggers,
non-qualification events, missing candidates, changed trees or webhook commits,
and authority loss cannot create a qualification.

Runner admission remains a pure policy contract. Untrusted, trusted-build,
production-release, and control-recovery runners have distinct node classes,
network scopes, cache domains, and phase-scoped credential profiles. Admission
requires disposable cgroup-v2/user-namespace/seccomp isolation, read-only root,
no host Docker socket, rootless BuildKit for compilation, bounded resources and
logs, redaction plus secret scanning, and exact runner/job/sequence identity.
Untrusted and trusted-build runners cannot reach metadata, production,
control-NATS, or database networks. A signed command is now acknowledgeable
only after both its canonical payload/signature pointer and a runner execution
record are durable. The execution record binds that exact acceptance, uses a
bounded renewable lease, fences crash takeover, and records one terminal
evidence digest or typed failure. The runner now compiles and owns one exact
rootless BuildKit daemon, verifies its Unix-socket peer UID, executable, and
closed arguments before use, and stops the process tree on cancellation. The
runner process mode, controller-side result publication, and candidate artifact
interpretation/publication are still separate missing gates. The standalone
coordinator is not wired into normal startup and does not claim that a workload
ran unless its exact durable sink completed first.

Native GitOps desired state is a fresh TerraScale document rather than a
Kubernetes, Helm, Kustomize, or Flux compatibility surface. The bounded v1
compiler accepts only closed catalog roles, catalog-approved runtimes,
lowercase SHA-256 artifact digests, replica counts, cells, dependencies, and a
suspension flag. Defaults are visible in its canonical plan. Dependencies are
validated and topologically ordered, every consuming cell must contain its
dependencies, and the compiler produces deterministic per-cell plans plus a
SHA-256 plan digest:

```json
{
  "apiVersion": "terrascale.io/v1",
  "kind": "TerraScaleDesiredState",
  "generation": 7,
  "workloads": [
    {
      "id": "authentication",
      "role": "Authentication",
      "artifactDigest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "cells": ["gru", "sfo", "fra"]
    },
    {
      "id": "api",
      "role": "Api",
      "artifactDigest": "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "cells": ["gru", "sfo", "fra"],
      "dependsOn": ["authentication"]
    }
  ]
}
```

Concrete instances, allocations, attachments, and expanded volumes remain
regional-journal children. A Git parent removal can only request guarded
retirement; it never grants direct prune or deletion authority. Unknown and
duplicate fields, arbitrary roles/runtimes, paths, image names, unit text,
capabilities, invalid digests, missing/cross-cell dependencies, cycles, and
replica counts below a role's production floor all fail before a plan exists.

Accepted/proposed diffs require monotonically increasing generations and one
digest per generation. Create, update, and resume changes are dependency-first;
suspension and guarded retirement are dependent-first. A stable workload ID
cannot change its admitted role, and an active workload cannot depend on a
suspended role. An explicit empty workload array is a valid bounded generation;
against accepted state it requests dependent-first guarded retirement of every
declared parent without granting direct deletion of any journal-owned child.

The global plan can be compiled into deterministic, at-most-1-MiB per-cell
handoff payloads. Every payload binds the verified repository, commit, tree,
manifest blob and content digest, global generation/digest, complete desired
workloads for that cell, and its ordered local changes. Added cells receive
create actions; cells removed from an otherwise retained workload receive
guarded retirement. Retirement-only cells remain in the required-cell barrier
even when the proposed workload set is empty. Each payload has its own SHA-256,
and an aggregate handoff digest binds the sorted cell/digest set. These payloads
are signable material only: the compiler does not grant unsigned apply authority.
The cell-envelope adapter reuses the shared command protocol and requires the
configured P-256 signer/verifier. Its signed material binds the
aggregate handoff digest, exact cell, generation, global writer epoch, payload
SHA-256, deterministic operation/idempotency identities, delivery attempt, and
validity window. Cell, generation, epoch, payload, aggregate-barrier, expired,
and signature substitution fail before acceptance. A regional acceptance is
acknowledgeable only after the exact payload is written and read back through
`CELL_BUNDLES` and a fenced CAS receipt is committed in `ORCH_DELIVERY`. That
bounded receipt binds the cell, global plan and handoff digests, generation,
writer epoch, signed operation/idempotency identities, signature digest,
acceptance time, and original stream sequence. Replays converge on the same
receipt; stale writers/generations, same-generation equivocation, authority
loss, corrupt payloads, and crash-before-pointer fail closed. Exact global and
regional publishers, bounded pull consumers, and the fenced relay boundary are
implemented; runtime credential composition and OCI KMS-backed
root/intermediate issuance remain.
One compiled handoff targets at most 64 distinct cells, regardless of how cells
are distributed across workloads, and the regional bundle store is capped at
256 MiB so one maximally bounded handoff does not consume its entire capacity.
Each region can validate from a compact descriptor containing the generation,
global-plan digest, aggregate handoff digest, and sorted cell/payload-digest
set; it recomputes the aggregate and checks its own closed payload identity, so
transport does not need to copy every other region's full CellSpec.
Each CellSpec also binds the accepted base generation/global-plan digest and
the exact before/after digest of every changed workload. Regional drift,
retirement, and rollback decisions therefore never infer prior ownership from
the proposed plan or from mutable runtime labels.
The wire contract keeps the CellSpec as raw bytes and carries exactly 16
canonical metadata headers rather than Base64-expanding the payload. CellSpecs
are capped at 896 KiB, headers at 64 KiB, and the complete command plus protocol
allowance at 1 MiB. Duplicate, unknown, non-canonical, oversized, reordered,
digest-mismatched, and payload-substituted inputs fail before durable delivery.
Before publication, the global writer stores each exact signed wire command in
`GLOBAL_BUNDLES` under its content digest and read-verifies it, then advances one
compact branch pointer in `GLOBAL_RELEASES` by CAS. The pointer binds the source
journal revision, global authority/writer epoch, generation, plan and handoff
digests, common validity window, and every cell's payload and wire digest. A
restart or concurrent writer therefore recovers the winning signature bytes;
it never re-signs different bytes behind an already assigned message ID. Crash
orphans are harmless, while authority, source-revision, and generation rollback
or same-generation equivocation fail closed. The worst-case 64-cell pointer
remains within the global 16 KiB KV value limit.
The global publisher then appends those recovered commands to
`ts.orch.v1.global.desired.gitops.<cell>` sequentially and requires a nonzero
`GLOBAL_SPEC` storage acknowledgement for every cell. Exact retries retain the
same message identity and bytes. Authority loss before a later cell or after a
storage acknowledgement returns explicit partial durable evidence and can
never report a complete handoff; regional `CELL_SPEC` publication and acceptance
remain separate fenced boundaries.
Each current per-cell `GLOBAL_SPEC` acknowledgement is then CAS-journaled with
the signed-handoff pointer revision, source revision, authority, generation,
plan/handoff identity, exact wire digest, and stream sequence. Restart readback
distinguishes an incomplete set from all required cells and can skip already
journaled cells. A different sequence cannot relabel an existing cell; a newer
generation or fenced writer starts a new proof set instead of inheriting stale
acknowledgements. Authority-lost publications never advance this journal, whose
worst-case 64-cell record also remains within the 16 KiB global KV limit.
The dispatch coordinator preflights that journal before any publish, skips only
exact wire digests already acknowledged for the current signed-handoff pointer,
and commits each new acknowledgement before attempting the next cell. A crash
after stream storage but before CAS replays the same persisted bytes and message
ID, then converges on the journal. Stale or conflicting durable state blocks the
side effect, and a completed replay performs no publish.
The handoff coordinator starts only from the restart-reconstructed durable
source/base diff, persists its signed wires, and then invokes that resumable
dispatch. Missing sources, legacy pointers without a recoverable diff, a source
written by a newer authority, signing rejection, dispatch conflict, and every
authority-loss edge are explicit non-success results. A crash anywhere after
wire persistence resumes the same signature bytes, message identity, and
per-cell acknowledgement progress rather than rebuilding from process memory.
The global-to-regional relay decodes and validates one exact globally stored
CellSpec against its destination cell, current global writer epoch, validity
window, and injected signature trust policy before any regional side effect. It
then publishes the unchanged payload and canonical headers to regional
`CELL_SPEC` and acknowledges the global delivery only after regional storage and
a final regional-authority check. Authority loss at any boundary leaves the
global delivery unacknowledged; acknowledgement failure redelivers the same
regional message identity and bytes so JetStream deduplication remains safe.
Its per-cell durable pull consumer accepts only the exact `GLOBAL_SPEC` stream,
cell-filtered subject, consumer identity, nonzero stream/consumer sequences,
five-attempt delivery bound, and 1 MiB wire ceiling. Repeated header values are
preserved for strict decoding, and the successful relay uses a double
acknowledgement so an uncertain global acknowledgement remains safely replayable.
The JetStream publisher sends one signed command to
`ts.orch.v1.<cell>.desired.gitops`, requires a `CELL_SPEC` storage sequence, and
uses handoff/cell/writer-epoch message identity so exact retries deduplicate but
a fenced takeover is not suppressed. Authority loss before publish causes no
mutation; loss after the storage acknowledgement is reported distinctly so the
stale durable message cannot be mistaken for authority to advance the global
plan. The regional epoch/signature gate still rejects that stale message.
The regional inbox acknowledges only after decoding the bounded command,
verifying the configured signature policy, reading back the content-addressed
payload, committing the fenced acceptance receipt, and rechecking regional
authority. Malformed, invalid-signature, stale, conflicting, and non-durable
deliveries remain unacknowledged. Authority or acknowledgement loss after the
receipt is safe: redelivery observes the durable duplicate and a replacement
leader can acknowledge it without repeating acceptance.
The concrete pull adapter requires the exact `CELL_SPEC` stream, cell subject,
durable consumer identity, nonzero stream/consumer sequences, and delivery
count within the configured five-attempt bound. Its per-instance consumer has a
15-second acknowledgement window, at most eight outstanding messages/pulls,
bounded backoff, and double acknowledgements. Repeated NATS header values are
preserved so the strict wire decoder can reject duplicates instead of silently
choosing one.
An acceptance barrier evaluates at most one durable receipt per required cell
against the exact generation, global-plan/handoff/payload digests, signed
operation identity, writer epoch, regional stream sequence, journal revision,
and signature digest. Missing cells remain explicit and produce no barrier
digest; duplicate, foreign, stale, or mismatched receipts fail closed. A
complete barrier digest is deterministic across receipt arrival order and
changes across a fenced takeover. This proves only regional CellSpec
acceptance—it is not apply, health, live-convergence, or deployment-success
evidence.
Regional convergence rehydrates that immutable payload, requires its accepted
base plan to match local accepted history, and emits at most one action per
evaluation. Active workload drift uses the shared dependency-safe
reconciliation engine; missing or in-progress state is observed before another
mutation. Suspension and retirement remain dependent-first. Retirement can
advance only with exact ownership, safety, retention, dependency, and domain
authorization proof digests bound to the current writer epoch. Failed health
requests a new generation referencing a previously qualified global plan; it
never rewinds a local artifact in place. Only exact live workload/absence
observations produce a regional convergence digest, and cross-cell success is
still a separate global barrier.
Every convergence decision is CAS-journaled before it can authorize dispatch
or global advancement. The checkpoint chain binds the accepted CELL_SPEC
stream sequence, signature digest, acceptance revision, writer epoch,
observation watermark, exact intent or hold, and prior checkpoint digest.
Exact retries recover the same dispatch identity; changed observations require
a strictly newer watermark. A new generation or fenced takeover must also
advance both the acceptance revision and regional stream sequence, preventing
an old accepted receipt from being relabeled as fresh authority.
Each converged cell emits a signed, validity-bounded receipt over its exact
handoff/payload, convergence checkpoint, acceptance sequence/revision, and
regional writer epoch. The global live barrier verifies those receipts through
the injected KMS trust policy and the current epoch for every required cell.
Missing cells remain explicitly pending with no barrier digest; duplicate,
foreign, expired, signature-substituted, wrong-digest, and stale-writer
receipts fail closed. Only the complete same-generation, same-global-plan,
same-handoff live set produces the deterministic cross-cell barrier digest.
Before a regional live receipt can be acknowledged, the global receiver stores
its exact signed envelope in a bounded per-cell CAS journal. Restart readback
therefore preserves the signature bytes needed to re-run the configured KMS
trust policy rather than trusting a derived success flag. Checkpoint sequence,
journal revision, acceptance sequence/revision, regional writer epoch,
generation, handoff identity, and global authority epoch advance monotonically;
crashes, authority loss, corrupt records, stale writers, and conflicting
generations never become acknowledgeable.
Global live completion is a separate bounded CAS record. It re-verifies the
exact durable per-cell envelopes at the current global and regional epochs,
requires every handoff cell, and persists no success for a partial set. Its
completion digest binds global authority, generation, global plan, handoff,
signed barrier, sorted per-cell payload/convergence/signature/checkpoint
proofs, compact regional/acceptance/checkpoint fences, live-receipt journal
revisions, and completion time. Exact retries recover the same record. Later
generations, checkpoint progress, and fenced regional or global takeovers can
replace it only with monotonic durable proof; stale or relabeled evidence fails
closed. The worst-case 64-cell record remains within the 16 KiB global delivery
journal value limit; raw signed receipts stay in their per-cell journals.

The native source boundary reads `.terrascale/orchestrator.json` only from the
exact immutable commit returned by Forgejo resolution; it never substitutes a
branch or tag for that object ID. Loading requires a signature-verified commit
before any file request is made. The response must identify the exact regular
file path, a nonzero Git blob, Base64 encoding, and a matching declared size
within the 1 MiB manifest ceiling. The loader records an independent SHA-256
of the decoded bytes, compiles the closed manifest, and produces the typed
accepted/proposed diff as one source plan. Symlinks, path substitution,
malformed encoding, size mismatch, unsigned commits, and stale or conflicting
generations fail closed before regional work is planned.

The fenced global leader stores accepted manifest bytes under their content digest in
`GLOBAL_BUNDLES` and advances a compact branch pointer in `GLOBAL_RELEASES` with
exact compare-and-set. It reads the object back before moving that pointer and
records the prior accepted manifest identity with the new pointer. Restart
therefore read-verifies and recompiles both exact plans before reconstructing
the typed update, suspension, or guarded-retirement diff; it never guesses a
fresh-create diff from only the latest manifest. A crash between object and
pointer writes leaves only harmless unreferenced content. A concurrent pointer
winner forces the diff to be recomputed from its accepted base. Authority or
poll-sequence rollback, one immutable commit/tree presenting different bytes,
a corrupt current or base object, and a stale-generation replay cannot advance
accepted state. A repository without the native manifest is treated as not
configured and does not disturb its last accepted plan.

The optional polling fallback runs only on the current fenced global leader.
It reads protected `develop` and `main` refs every 30 seconds, resolves each
observed commit to its exact Git tree, then records the observation in
`GLOBAL_RELEASES` under the authority epoch and poll sequence. A lease change
during the API read discards the result; an old leader cannot overwrite a newer
epoch. Use a private token file containing a repository-scoped Forgejo token
with only `read:repository` permission:

Forgejo listener or polling configuration is rejected unless the complete
global-control NATS configuration above is also present; regional controllers
cannot accept global Git or CI state.

```bash
TS_ORCH_FORGEJO_API_URL=https://git.terrascale.tech/ \
TS_ORCH_FORGEJO_REPOSITORY=TerraScale/TerraScale.Orchestrator \
TS_ORCH_FORGEJO_API_TOKEN_FILE=/run/credentials/forgejo-read-token \
terrascale-orchestrator run
```

The three regional controller candidates share one NATS service queue group
and contend for one `ORCH_LEADERS` lease using exact KV compare-and-set
revisions. The production authority state machine advances the fencing epoch,
binds the lease identity, and grants a mutation permit only to the exact CAS
winner. Followers remain available for read-only operator traffic. The winner
renews every three seconds with a fifteen-second lease; a renewal conflict or
uncertain authority result fences the candidate and terminates it for an
external supervisor restart. The three-region DevHost profile runs one
controller and RF=1 NATS per cell, so it exercises regional wiring but does
not claim election or quorum. Those semantics use a separate targeted
one-region R3 component lane and still do not replace the real multi-host
clock, partition, mTLS, and NATS-JWT gates.

## DevHost three-cell container profile

`lab plan` is a pure operation and prints the fixed `dev-containers-three-cell-lean` topology. It contains GRU, SFO, and FRA cells. Every cell has one Orchestrator controller, one control-plane NATS server, one product-plane NATS server, one TerraBase server, Authentication, API, and Dashboard. Email and Stripe emulators are shared development fixtures. This 23-container profile is fast local integration evidence; it does not claim production R3 failure tolerance.

For control-plane smoke and stability work, `--profile dev-containers-control` keeps the same three regions but starts only one control NATS server and one controller in each region. This six-container slice exercises regional authority and health without building or starting product workloads.

```bash
dotnet run --project src/TerraScale.Orchestrator -- lab plan
dotnet run --project src/TerraScale.Orchestrator -- lab status \
  --state-file "$HOME/.local/share/terrascale-devhost/orchestrator/state.json"
```

`lab up` is fail-closed without short-lived evidence for the exact clean commit, executable, and selected topology. The attestation command runs the bounded complete solution and policy suites before writing evidence outside the repository. Startup first rejects a topology whose declared per-role limits exceed 14 GiB, then verifies rootless Podman availability, creates an owner-labelled pod capped at 14 GiB, and starts only digest-pinned images. The full 23-container plan totals 13,248 MiB. Containers drop all capabilities, enable `no-new-privileges`, have per-role memory and PID limits, mount the workspace read-only, and mount only the Orchestrator data directory read-write. The same exclusive lease prevents tests and labs from overlapping.

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- \
  development-attest \
  --output /tmp/terrascale-orchestrator-control-evidence.json \
  --binary src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator \
  --profile dev-containers-control-three-cell-lean

src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator \
  lab up \
  --workspace /workspaces/TerraScale \
  --data-directory "$HOME/.local/share/terrascale-orchestrator/devhost" \
  --profile dev-containers-control \
  --evidence /tmp/terrascale-orchestrator-control-evidence.json
```

The adapter persists independent control NATS, product NATS, TerraBase, and backup data per cell. It publishes atomic resource and endpoint projections for DevHost. Stopping the foreground Orchestrator removes every owned container and its pod; persisted data remains for the next generation. Startup removes an existing pod only when its ownership label matches exactly and refuses to touch foreign resources.

Run regional fault scenarios sequentially against one healthy lab and reuse it
when clean bootstrap is not the behavior under test. Pure decision logic stays
in-process; real quorum uses a separate one-region R3 component lane; and
systemd, containerd, storage, ARM, and OCI/provider qualification run as
targeted real-boundary fixtures one at a time. The RF=1 lab proves regional
composition, not production HA or destructive-operation safety.

DevHost creates stable, owner-private credentials beneath its Orchestrator data
directory. Every controller has a distinct NKey identity, and each cell has a
separate read-only operator NKey that can request only regional status and
receive its inbox reply. Control NATS denies anonymous clients; every
controller proves that denial during startup before advertising the
`nats-nkey-authenticated` capability. Product NATS uses an independent random
per-cell username/password consumed by the existing product queue client.
Control and product planes have separate development PKI roots, one regional
intermediate per cell, SPIFFE-like leaf identities, mandatory client mTLS, and
separate server/route certificates. NATS configuration files are mode `0600`,
contain public controller/operator NKeys but never their seeds, and are
isolated from product credentials. This closes anonymous DevHost messaging and
intra-cell plaintext transport; NATS operator/account JWTs, cross-cell gateway
mTLS, and rotation/revocation remain separate production qualification gates.

After startup, Orchestrator continuously probes every planned process and its
role-specific health surface: NATS client ports, TerraBase HTTP and native TCP,
Authentication/API readiness, regional Dashboard stack views, and emulator
readiness. A failed probe is projected as degraded immediately; three
consecutive unhealthy observations fail the foreground generation so DevHost
can re-attest and recover the graph.

Every DevHost state projection is also evaluated by the production typed
reconciliation engine. The graph is not accepted as ready unless all 23
allowlisted resources have exact generation/digest observations and converge
in dependency order. Startup progress is written to the resource-state file,
but the endpoint map used for DevHost cutover is withheld until one complete
health pass—including each controller's instance-specific authority endpoint—
and 23/23 typed convergence succeed. This prevents a starting generation from
being mistaken for a deployable candidate.

## Closed production role catalog

The executable exposes the exhaustive v1 production role catalog as JSON:

```bash
src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator catalog
```

All production-shaped DevHost resources project to one of these built-in
descriptors. API, Authentication, and Dashboard retain the production OCI
default; TerraBase, both NATS planes, and Orchestrator retain their native
systemd defaults. Email and Stripe emulators are explicitly development-only
fixtures and cannot be admitted as production workloads.

`runtime plan` resolves a role and artifact digest through that catalog into a
typed host execution plan. It never accepts an executable path, image
repository, unit directive, host path, capability, privileged flag, or secret:

```bash
terrascale-orchestrator runtime plan \
  --role api \
  --allocation gru-api-1 \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --memory-max-bytes 536870912 \
  --tasks-max 128 \
  --cpu-quota-percent 100 \
  --cpu-weight 100 \
  --io-weight 100 \
  --nice 5
```

Native plans derive an immutable artifact path and hardened systemd
properties. OCI plans derive a digest-pinned internal-registry reference,
non-root identity, read-only root filesystem, no-new-privileges policy,
drop-all capabilities, seccomp profile, cgroup, and resource ceiling. Plan
limits may only reduce the role catalog's memory, PID, CPU, CPU-weight, and
I/O-weight ceilings or increase its nice value. Both drivers disable swap and
set a memory-high threshold at 90% of the hard limit. Plan generation is pure;
applying it remains fail-closed until the selected systemd/containerd host
adapter and its pinned runtime are qualified.
