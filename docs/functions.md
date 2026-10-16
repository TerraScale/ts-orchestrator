# Customer function worker contract

Use wazero **v1.12.0** for the first `terrascale.function.command.v1` worker.
This selects an implementation for the narrow contract below. It does not
qualify customer execution in production; the FUNCTIONS gate in
[`REFACTOR.md`](../REFACTOR.md#customer-functions-wasmtime-versus-wazero) still
requires CORE, CAP, REL and QA evidence for each admitted architecture.

## Contract and compatibility boundary

The contract in [`internal/functions/contract.go`](../internal/functions/contract.go)
accepts a WebAssembly **core module** implementing a WASI Preview 1 command,
with a `_start` export. Each invocation gets a new module instance, including
new memory, globals, tables, stdin and output buffers. The worker reuses compiled
code for its admitted module; it does not reuse a live guest instance.

The platform owns the HTTP listener and the NATS/JetStream consumer. It passes
one JSON `Invocation` on guest stdin, then returns guest stdout as raw bytes.
Go's JSON encoding represents the `[]byte` payload as base64:

```json
{"tenant_id":"<admitted-tenant-id>","function_id":"echo","revision":"r1","id":"request-123","trigger":"http","payload":"aGVsbG8="}
```

`trigger` is `http` or `queue`. Tenant, function and revision must match the
worker's manifest. The payload is application data, not a serialized HTTP
request, a NATS message object or a source of host-call identity. Stdout is not
parsed as an HTTP response envelope; a successful HTTP adapter response uses
status 200 and `application/octet-stream`. The adapter accepts POST requests
with a valid `Idempotency-Key`; it passes only the body, not credentials,
headers, URL or query values, to the guest. Stderr is bounded and excluded from
results. Guest failure must not return partial stdout as successful execution.

Both triggers can use this same command ABI: their transport operations happen
in trusted Go code before and after invocation. A guest needs neither a socket
nor a `wasi:http/incoming-handler` export to transform a request body or queue
payload. No WASI HTTP, Preview 2 adapter, WIT package or Component Model binary
is required by this ABI. A future streaming HTTP, outbound network, TerraBase
or component interface would require its own explicit contract and isolation
qualification; it is not silently accepted through this one.

No public historical customer function artifact was available to this stream
for compatibility testing. The historical Preview 2 proposal is not evidence
of such an artifact or a requirement to preserve that interface. These new
prototype modules establish only the command contract above; they do not prove
compatibility with arbitrary customer toolchains or all WASI programs.

## Runtime comparison

Source review on **2026-10-16** compared the installed/pinned wazero v1.12.0
with Wasmtime's current engine release v49.0.3 and the separately tagged
wasmtime-go v49.0.0 binding. Neither Wasmtime version is a project dependency.
This is a contract/integration-cost comparison, not a performance benchmark or
a claim that both candidates passed the prototype.

| Requirement | wazero v1.12.0 | Wasmtime / wasmtime-go comparison |
| --- | --- | --- |
| Core module and Preview 1 command | `wasi_snapshot_preview1`, `_start`, explicit stdin/stdout writers and independent module instances fit this contract. | Engine supports `wasi_snapshot_preview1`; Go binding has `WasiConfig` and WASI linker support. Also fits the command contract. |
| Existing single Go binary and `CGO_ENABLED=0` | Pure Go; compile for Linux ARM64 and AMD64 without a native runtime library. Selected for this smaller integration. | Go binding calls the Rust engine's C API through CGO and native libraries. A separate worker container can contain that cost, but it still needs native builds/lifecycle integration. |
| Execution bounds | `WithMemoryLimitPages` and `WithCloseOnContextDone`; worker supplies bounded I/O and concurrency. Deadline interruption is not an instruction/fuel budget. | Go binding exposes memory/store limits, fuel and epoch interruption. These are capabilities of the candidate, not locally qualified policies. |
| Linux ARM64 / AMD64 | Upstream compiler support and upstream Linux tests cover both. Our architecture-specific qualification remains separate. | Engine documents Linux x86_64 as Tier 1 and aarch64 as Tier 2. Binding tag includes static libraries and CGO link directives for both Linux architectures. No claim that Wasmtime lacks ARM support. |
| Components / WASI HTTP | The selected core-module interface does not require these. No component execution path is admitted. | Engine documents Component Model and WASI HTTP support. Go tag includes component bindings with TODOs for function calling/value marshaling; engine support alone does not establish a complete Go HTTP-component embedding contract. None is needed here. |

The Wasmtime binding README's platform paragraph lists only x86_64, while that
same tag's [`ffi.go`][wasmtime-ffi] and checked-in `build/linux-aarch64` library
include ARM64. Use the tagged code for that fact. Do not infer unsupported ARM,
complete component bindings or build reproducibility from the README alone.
No Wasmtime installation, native build or benchmark was performed for this
comparison. Reconsider the runtime only when a demonstrated required interface
or measured workload justifies its additional integration; do not ship a second
engine or an engine-selection switch for this first ABI.

## Fixed worker policy

These values live in code, with no operator tuning or enable switches.

| Bound | Policy |
| --- | --- |
| Artifact and identity | At most 8 MiB portable module bytes; SHA-256 must match the manifest; exact ABI, valid tenant/function/revision and no declared capabilities. |
| Input and output | At most 1 MiB decoded payload; stdout and stderr bounded to 1 MiB each. The stdin JSON envelope is larger because payload bytes are base64 encoded. |
| Execution | At most 2 seconds per invocation, shortened by the caller deadline/cancellation; at most four concurrent invocations in a worker. Excess concurrency is rejected without an unbounded in-process waiting queue. |
| Guest memory and decoder allocations | At most 256 WebAssembly pages (16 MiB) per linear memory; at most one table with an explicit maximum of 4,096 entries. Resource admission caps section vector counts, local counts and function body sizes before compilation. This is not a total worker RSS/CPU bound. |
| Lifetime | One tenant/function/revision per worker **process**, compiled code reused only within that scope, fresh instance for every invocation, closed after success/failure/cancellation. |

The first ABI rejects custom metadata and element sections until their nested allocation limits have integration coverage. This deliberately excludes some otherwise valid Wasm modules and common toolchain outputs; strip only metadata that is semantically optional. Do not remove element sections from a module that needs them. Admission does not claim general WASI toolchain compatibility.

The module/package cannot itself enforce process placement or a host CPU/RSS
quota. CORE must schedule a long-lived worker process with tenant boundaries;
CAP must provide dedicated function hosts, separate from managers, trusted
services and TerraBase, with non-root execution and bounded CPU, RSS, PIDs and
storage through cgroups/container policy. Four invocations can consume four
guest memories plus native overhead. Compiler admission must also remain within
the worker process's resource limits; a guest deadline is not a measured bound
on compilation time or memory. SwarmKit owns worker process lifetime and restart;
there is no SwarmKit task, image pull or controller execution per invocation.

## Host capabilities and network denial

The first ABI has an **empty production capability set**. Reject a manifest
with any capability. Admission rejects imported memory, non-WASI imports,
`sock_*` imports, unresolved functions and mismatched import signatures. Supply
the invocation's stdin and bounded stdout/stderr. Do not
inherit the worker's environment, command-line secrets or standard descriptors;
do not mount/preopen a guest filesystem or expose host paths, Unix sockets,
raw sockets, listeners, HTTP fetch, NATS, OCI, Vault or TerraBase host functions.
WASI helper imports are not permission to create a directory or connection.
There is no writable guest temporary filesystem in this ABI.

The baseline WASI implementation does provide cryptographic randomness, host
wall/monotonic time and cancellation-aware sleeping. These are intentional
runtime services; the empty manifest capability set means no additional
platform/data/network authority, not that every WASI helper is deterministic or
absent. Guest output can therefore vary between otherwise identical invocations.

This limits normal guest code to the linked WASI implementation and explicit
buffers. It does not protect against an engine or worker-process compromise by
itself. CORE/CAP must deny workload-originated access to OCI metadata and
instance-principal endpoints, host sockets, manager/NATS/control/Vault networks
and other tenants, including IPv4, IPv6 and link-local paths. Any trusted
transport endpoint the worker needs must be narrowly scoped; guest input must
never choose its credentials, destination or tenant scope. Function-host
instance principals must lack infrastructure mutation and general Vault
privileges. NetBird membership is not tenant authorization or network isolation.

There is no outbound HTTP host capability to perform SSRF in this ABI. Adding
one later requires destination authorization, DNS/address validation and denial
on every redirect/re-resolution, including metadata and private control ranges;
a container egress rule does not constrain a trusted proxy's network authority.
Source-level missing imports and denied filesystem calls are useful integration
checks, but do not substitute for live network and host-compromise containment
tests on both architectures. No production credentials are injected into guest
env, stdin, filesystem, errors or results.

## Artifact admission, caches and rollback

The authoritative release artifact is the portable `.wasm` plus a manifest
binding ABI, tenant, function, revision and lowercase SHA-256 digest. Module
size, digest, identity and capability validation are necessary but **do not
authenticate a publisher**. REL must deliver that pair through the normal
signed, scoped, ordered release admission path before a worker loads it. The
public `NewWorker` accepts an opaque `release.VerifiedFunction`, and the process entrypoint verifies the signed receipt, exact expected scope and nonzero durable sequence floor before calling it. It exposes no public module-upload API. The worker closes when that proof expires. A user-controlled digest, URL or HTTP request cannot
serve as admission evidence. Integration tests exercise genuine root/delegation/receipt signatures and tenant/revision/digest/sequence rejection. The automatic material producer additionally checks durable current intent and exact recipient grants; actual startup wiring remains under QA integration.

Keep the portable bytes for recompilation on a new host. Reuse the compiled
module in the current process. Treat any compiled/persistent cache as disposable
trusted derived state, scoped by module digest, runtime/version, architecture,
CPU target/features and relevant compilation settings. Never publish ARM cache
bytes as an AMD64 artifact or assume two ARM families have identical CPU
features. A miss or incompatible cache recompiles admitted portable bytes; it
must not bypass admission or substitute a previous revision. This prototype
does not promise a persistent or cross-host compiled cache.

Wazero's disk-cache source namespaces by runtime version, GOARCH and GOOS and
warns that the directory must be protected against external changes. That is
not proof of compatibility across CPU features or arbitrary runtime settings.
Wasmtime deserialization similarly requires the engine version/options that
produced the serialized code. Neither native-code cache is an untrusted guest
upload format. Live cache compatibility evidence remains required before adding
a persistent shared cache.

Revision rollback means admitting the previous healthy portable artifact and
routing new work to a worker for that exact revision. It does not restore guest
memory or replay external side effects. CORE/REL must prove readiness, drain,
revision routing and rollback under worker loss before live use; a successful
constructor or SwarmKit `RUNNING` task alone does not prove these behaviors.

## HTTP, queue delivery and worker loss

Authentication and tenant authorization belong at the trusted HTTP/queue
boundary before constructing `Invocation`. Manifest scope is checked again by
the worker; a guest-supplied tenant value never authorizes access. The HTTP
adapter is a callable boundary, not a newly exposed public route by itself.

Use the same stable queue invocation ID when delivery repeats. A successful
invocation is acknowledged with a confirmed JetStream ack only after its
payload digest is stored as a durable KV receipt. Queue output is discarded; receipts contain only the 32-byte digest. A repeated ID
with the same payload reuses that receipt and is acknowledged without execution;
a conflicting delivered payload, invalid invocation or guest trap is terminated. Broker publication deduplication can suppress a conflicting ID before delivery. Busy or closed workers and canceled/timed-out invocations retry after one second. A receipt storage capacity or post-execution persistence failure exits the queue loop for supervisor recovery; it does not rerun the guest in a tight local loop. The broker connection must authorize only the worker's exact
tenant/function/revision scope; subject naming alone is not authentication.

The trusted regional material producer calls `ProvisionQueue` with an opaque
current release proof before launching a worker. `NewQueueWorker` only binds and
validates the existing stream, consumer and receipts. Workers cannot create,
update, purge or delete them: restricting a JetStream mutation API subject does
not restrict the subjects embedded in its request body. Retired revisions need
controller-owned resource retirement; receipt expiry alone does not remove
stream or consumer metadata.

`IssueWorkerCredentials` issues one NATS JWT/NKey identity for the exact admitted
revision. Its caller first verifies the regional account JWT against the current
operator/generation; issuance additionally requires the account key or a currently
registered unscoped account signer. The signer remains in the trusted controller.
Grants permit only exact resource information, the existing pull consumer, own
receipt direct reads/writes, matching ack subjects and one private user-key reply
inbox. They prohibit queue publication, resource mutation, other revisions and
control subjects. Credentials last at most one hour and never outlive the
release proof or account claim. Renewal retains the user key, accepts authorized
signer rotation overlap and rejects a retired signer or widened prior grants.
The worker derives its private inbox from the credential's public user key.

Receipts have a fixed **24-hour TTL** and 64 MiB bucket bound. Queue retention
is one hour, 10,000 messages and 64 MiB; a full stream rejects new work. One
durable pull consumer per scope permits one outstanding delivery across workers,
with a 30-second ack wait; broker publication deduplication is two minutes.
These are bounded policies, not indefinite idempotency storage. Resource exhaustion surfaces as failed publication or a supervisor-visible error. The worker checks receipt capacity before executing; a crash or storage failure after execution still leaves the documented at-least-once window.

Queue delivery remains at least once. A worker can execute and die before
recording the receipt; a long stall can also permit broker redelivery. A receipt
does not transactionally commit arbitrary external effects. After receipt
expiry an ID can execute again. Do not promise exactly-once execution. Stateful
external effects require durable idempotency at the trusted destination before
such a capability is admitted. This ABI exposes no external-effect host
capability. HTTP currently validates the idempotency key but does not persist
HTTP receipts or suppress repeated calls.

Worker loss discards in-flight memory and process-local cache state, while
committed queue receipts survive a worker restart in JetStream storage.
An interrupted HTTP call can fail without knowing whether execution completed;
caller retries can repeat it. JetStream redelivery can recover pending queue
work, but only the real durable consumer, result destination and ack ordering
can establish its recovery behavior. No in-process queue wrapper substitutes
for that live evidence. Credentials used by the platform transport stay outside
the guest instance.

## Automatic admission and material delivery

The existing regional Object Storage head bucket retains signed function
receipts and delegations in `releases/functions/channel.json`; portable modules
live under `releases/functions/modules/<sha256>`. The bounded channel index is
only a lookup source. The controller verifies each receipt, delegated tenant and
function scope, environment/cell, module digest and durable current sequence
before admitting it. First publication uses a fixed floor of one; later
admission uses the current durable function floor. A rollback requires a new
signed sequence naming the earlier portable module.

Current function intent and exact task material grants use the existing
`TS_CONTROL_LOG`, ordered with leadership fencing. Service intent is independent
of a particular task; a grant binds the current proof, actual Swarm task/service/
node, cryptographic host registration ID, OCI instance/region and immutable Vault
material digest. A replacement task gets a fresh grant without inventing a new
function release. Material for a given task remains immutable; expiry requires
replacement rather than overwriting a running task's keys.

The controller retires expired task secrets only after the manager confirms the
exact task is terminal or absent. A desired shutdown, a live task or a failed
observation cannot authorize retirement. It checks current Vault bytes/version,
the committed material hash and metadata identity/ETag before scheduling deletion
with a fixed 25-hour provider delay. The SDK rechecks leadership at the request
boundary. Exact pending-deletion readback handles lost replies and restarts;
immutable nonsecret authority grants remain available for audit.

Verified modules use the shared artifact store's `sha256-<digest>` keys. The
existing artifact collector must retain current function-intent digests alongside
host references. Uploading before intent commit refreshes object metadata and
fences deletion from an older collector snapshot. Superseded bytes can be
collected after the existing grace period; a newly signed rollback fetches the
portable module again from the regional release bucket.

The regional `functionmaterial.Controller` provisions the queue and prepares
credentials/TLS through OCI Vault create/read/conditional-version publication.
It rereads and verifies committed bytes before granting the exact recipient.
An interrupted publication can resume while retaining the worker's NKey. A
signer-free reader checks current intent, grant, account/operator generation,
credentials, TLS and expiry. Its result is sealed and copied defensively.

First boot uses the genuine sealed startup inventory directly. The baseline
generator includes a controller TLS intermediate and a distinct unscoped account
signer; their loaders recheck the live source CAS and exact inventory hashes.
No material generation is fabricated for that startup path. The public material
fingerprint is stable across controller slots.

Worker image pulls precede function material delivery. The manager retains the
exact signed worker bundle, including qualification and delegation, and pins its
canonical digest into each task. A previous worker can pull only after its own
retained bundle passes current qualification and the immutable global sequence
allocation check while the function remains current. Receipt-only verification
checks signed function metadata without granting module execution authority.

Workers retrieve the fixed files through the existing authenticated host
session protocol. Each bounded chunk uses request-bound X25519/AES-GCM; every
file digest, the complete inventory and expiry must agree throughout delivery.
Delivery also pins the actual credential deadline: the earlier verified broker
JWT expiry and ingress TLS leaf expiry. This deadline remains separate from the
delivery grant and session lifetime and feeds the executor's credential guardian.
The controller independently checks the current actual scheduler assignment and
admitted host before serving material. Workers receive no general authority-log,
artifact-store, Vault or controller signing access. CORE stages the verified
inventory as the fixed read-only task mount. Source integration of the publisher,
controller loop and host provider must pass QA before deployment qualification.

## Dedicated worker command

`ts-orch function-worker` accepts no arguments and runs HTTP plus the durable queue in a dedicated process. It reads only the fixed `/run/ts-orch/function` task mount. The task/Vault admission producer must create and deliver these files automatically; this command is not an operator recipe for copying secrets:

| Mounted input | Producer contract |
| --- | --- |
| `deployment.json`, `module.wasm`, `receipt.json`, `delegation.json`, `root.pub` | Admitted tenant/function/revision, environment/cell, durable minimum signer sequence and SHA-256 module; raw 32-byte Ed25519 root key. Deployment metadata also supplies one TLS broker endpoint and a required material expiry bounded by the signed release, worker JWT, ingress TLS and bootstrap generation; the worker exits at that deadline. |
| `ingress-cert.pem`, `ingress-key.pem`, `ingress-ca.pem` | Vault-delivered server identity and trusted client CA. Client certificates must carry the exact `spiffe://terrascale.tech/tenants/TENANT/functions/FUNCTION` URI. |
| `broker-ca.pem`, `broker.creds` | Verified broker CA plus an automatically issued scoped NATS user JWT/NKey credential. Broker admission must restrict that identity to the exact tenant/function/revision consumer, receipts and reply subjects; a broad manager account is forbidden. |

The process opens TLS 1.3 ingress on port 8080, caps accepted connections at 64, bounds headers and read/write time, and caps HTTP bodies being read to four. `GET /healthz` requires the same tenant-scoped mTLS identity and reports ready only while its signed worker authority and broker connection remain live. `GET /snapshot` uses that same authorization and availability check, returning only the admitted manifest, runtime/version, architecture and activity/outcome counters, plus `schema_version: 1` and a UTC `observed_at` collection time; it excludes invocation inputs, outputs and credentials. Requests without a verified client certificate fail the TLS handshake; an authenticated certificate for another function fails authorization. Guest code receives none of the transport certificates, keys or endpoint metadata.

Paths are confined through `os.OpenRoot`; all files must be regular and bounded, and private keys/credentials must exclude group/other access. Readiness output identifies the admitted tenant/function/revision and digest without guest data or secrets. Cancellation stops HTTP and queue processing. The command does not provision its own identity, grant NATS permissions or purchase hosts. Automatic Vault/task delivery source exists separately from this command; its startup callers and boundary scenarios remain under QA integration. Dedicated placement, cgroup enforcement and egress/IAM isolation still require live qualification.

## Qualification record

Record exact source revision, module and worker-image digests, architecture,
CPU features, region/host/cgroup policy, command and retained output for each
result. A cross-compile proves buildability only; an upstream CI claim is not
a TerraScale result. As this document is introduced, prototype integration
evidence includes a local Linux AMD64 race run, actual child-process kill/restart and a CGO-free Linux ARM64 cross-build; no live architecture is qualified here.

| Check | Linux AMD64 | Linux ARM64 / A1 |
| --- | --- | --- |
| Upstream wazero compiler/platform support | Documented at pinned tag. | Documented at pinned tag. |
| Project command ABI, real module execution and fresh-instance isolation | Local real-Wasm integration and race check passed. | CGO-free test binary cross-build passed; native-host evidence pending. |
| HTTP body/result and real JetStream delivery/ack/retry | Local real HTTP/NATS integration and race check passed; consume-only JWT and private-inbox checks passed. | Native-host integration evidence pending. |
| Cancellation, memory/output/concurrency rejection and tenant/revision rejection | Local integration and race check passed, including bounded compiler declarations. | Native-host integration evidence pending. |
| Qualified worker placement, signed admission, cgroups, network denial, cache/rollback and worker loss | CORE/CAP/REL/QA live evidence pending. | CORE/CAP/REL/QA live evidence pending. |

The local pre-issuer qualification command was `go test -race
./internal/functions -count=1 -timeout=90s` (13.946 seconds), followed by
`CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c` and a CGO-free Linux AMD64
package build. These ran at local low CPU priority with two Go processors and
package parallelism two. Tests use real tiny Wasm modules, TLS HTTP, JetStream,
signed release artifacts and child workers; no cloud resources were changed.
The subsequent consume-only issuer, bind-only queue and private-inbox process run passed the complete functions race suite in 15.547 seconds; the signer-free credential verifier update passed it again in 16.822 seconds. That run also exercised real broker denials for other tenants/revisions, resource mutation, foreign acknowledgements and inboxes; signer overlap renewal preserved the worker key while retired signers and widened grants were refused.

The actual Vault SDK/JetStream recovery scenario subsequently passed locally in 0.335 seconds. The authority intent/grant scenarios passed in 3.835 seconds. A focused boundary run at `e2bd3b67` passed signed release expiry checks (2.308 seconds), the real OCI SDK publication/channel boundary (0.989 seconds), and real worker process/snapshot/material lifetime scenarios (1.290 seconds). After bounding its NATS observer flush context, the signed host transport and existing managed-material compatibility scenarios passed in 0.584 seconds at `01af84fc`. Automatic startup caller checks remain with QA.

The conditional Vault retirement and lost-reply recovery scenario passed with
current OCI request-bound authority checks (3.828 seconds); tenant-scoped client
mTLS passed in the same run (0.067 seconds). Metadata-only receipt verification
and existing module admission passed at `2125e83f` (2.580 seconds). Sealed startup,
retained-bundle app wiring and the separate credential guardian metadata require
their combined integration checks; these earlier passes do not qualify them.
The credential metadata reader and signed host chunk checks subsequently passed
at `f754395f` (0.321 and 0.530 seconds). At coherent runtime revision `912c14ed`,
the actual executor stopped the function process at its credential deadline
after the host agent exited (15.20 seconds); the corresponding generic process
scenario passed in 15.07 seconds. All seven focused runtime scenarios passed
without skips, including missing/changed expiry and immutable material recovery.
That direct authority fixture does not qualify the complete signed app producer.
Generated startup issuer JWT/mTLS checks passed at `16c601be` (0.186 seconds).
The genuine sealed actor scenario at `6281eb0c` measured a 16,403-byte escrow
against the unchanged 25,600-byte Vault limit, then failed at external-seed
ledger publication because retry-clock metadata was inconsistent. The corrected
`8b76daad` run verified derived founder authority, then failed at external-seed
OCI observation; the sealed issuer and public-trust constructors were not reached.
The next frozen source `f4e3a1b7` includes deterministic OCI observation ETags and
awaits its QA run. There is no completed genuine sealed-startup pass.
The concrete automatic startup helper and exact task-retained material selection
(`05e42ddf`, `8c493857`, `3184f213`) now have an actual app caller at `4f44746e`;
the host providers, scaler demand and observations use the shared regional
dependencies. Combined caller checks remain pending.
Recipient authorization rechecks the live sealed source before and after
verifying the retained task's worker authority. `8e3de807` additionally fences the
entire material preparation and Vault waits to the initial authority epoch and
root head; this source change has not yet passed the combined runtime scenario.
Positive WASM worker enrollment also requires
the original authenticated pool creation lineage; a static descriptor cannot
replace that authority.

The actual manager's automatic rollback image-pull scenario passed at `486da504`
(12.917 seconds). After rejecting worker 102, the manager assigned a new worker
101 task; its exact retained, currently qualified image could pull while another
worker and stale function proof were refused. Material for that older worker
remained denied by the advanced current floor. This proves image-pull recovery,
not a complete running rollback.

The dedicated current-task material verifier `e9fd32b2` subsequently passed
security source review. It admits an older worker only for the actual manager's
current rollback recipe, with current independent qualification and allocation,
an existing same-migration floor at or above the worker, and exact task/service
rereads. It never
authorizes a PreviousSpec-only task. The app caller `1f274dac` retains its sealed
source, current recipient, root and epoch checks, including a final node
admission reread. Security source review closed the caller with `bba89fb5`, which
rechecks function and worker lifetime after the final slow reads; `d2c00761`
also rechecks delivery expiry after the outer authority wait. Actual-manager
material regressions at `3996c37a` and coherent app runtime checks remain pending;
this is not evidence of a running rollback.

The FUNCTIONS gate remains open until its applicable checks pass for the exact
admitted worker on each architecture. No paid capacity, secret or wider IAM
permission was created for this source comparison.

## Upstream evidence

All links below are authoritative upstream sources inspected on 2026-10-16.
Tags are fixed comparison inputs, not moving-branch compatibility claims.

| Source | Retained version evidence and relevant scope |
| --- | --- |
| [wazero README][wazero-readme], [WASI implementation][wazero-wasi], [runtime/module configuration][wazero-config], [cache implementation][wazero-cache] | v1.12.0, tag commit `2ab480b55fa408d6b35df97fe32a60d08bd6e201`; pure Go/no CGO, Linux ARM64/AMD64 compiler support, Preview 1, explicit I/O, memory/deadline/cache behavior. |
| [Wasmtime release][wasmtime-release], [support tiers][wasmtime-tiers], [security model][wasmtime-security] | Engine v49.0.3, tag commit `f96eabaa11a06086e4fb779ed1c1688481067ab9`; release API reported publication 2026-10-14. Engine interfaces/target tiers and import/capability boundary. |
| [wasmtime-go tagged tree][wasmtime-go-tree], [FFI][wasmtime-ffi], [WASI configuration][wasmtime-wasi], [store][wasmtime-store], [runtime configuration][wasmtime-config] | Binding v49.0.0, tag commit `c46e9aab2a5873bcdf4043dd46b5974a9ffca207`; distinct from engine v49.0.3. CGO, both Linux native libraries, WASI, limits, fuel/epoch interruption. |
| [wasmtime-go component bindings][wasmtime-component], [module serialization][wasmtime-module] | Same v49.0.0 binding; partial component API TODOs and serialized-code engine/options compatibility. No component or serialized-cache execution was qualified. |

[wazero-readme]: https://github.com/tetratelabs/wazero/blob/v1.12.0/README.md
[wazero-wasi]: https://github.com/tetratelabs/wazero/blob/v1.12.0/imports/wasi_snapshot_preview1/wasi.go
[wazero-config]: https://github.com/tetratelabs/wazero/blob/v1.12.0/config.go
[wazero-cache]: https://github.com/tetratelabs/wazero/blob/v1.12.0/cache.go
[wasmtime-release]: https://github.com/bytecodealliance/wasmtime/releases/tag/v49.0.3
[wasmtime-tiers]: https://github.com/bytecodealliance/wasmtime/blob/v49.0.3/docs/stability-tiers.md
[wasmtime-security]: https://github.com/bytecodealliance/wasmtime/blob/v49.0.3/docs/security.md
[wasmtime-go-tree]: https://github.com/bytecodealliance/wasmtime-go/tree/v49.0.0
[wasmtime-ffi]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/ffi.go
[wasmtime-wasi]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/wasi.go
[wasmtime-store]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/store.go
[wasmtime-config]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/config.go
[wasmtime-component]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/component_feat_component_model.go
[wasmtime-module]: https://github.com/bytecodealliance/wasmtime-go/blob/v49.0.0/module.go
