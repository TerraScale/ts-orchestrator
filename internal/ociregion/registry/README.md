# OCIR lifecycle boundary

This package is an OCI-specific reconciler, with no registry framework,
CLI fallback, production credential payload, environment settings or dependency
addition. It is not wired into regional reconciliation yet.

1. Construct `New` with the regional shared OCI factory, a replicated file-backed
   non-expiring JetStream KV bucket and a guard bound to the current authority
   epoch. The owning regional operation creates/opens that bucket. Every SDK
   mutation attempt, including a retry, checks the guard after rate limiting.
2. Call `Ensure` for an admitted compartment/name/owner and admitted principal.
   The journal persists a stable create token before OCI receives the request,
   preserves its original creator through leader changes, and binds its OCID.
   Existing unrecorded names are never adopted. Bound repositories must match
   creator, compartment, name, OCID and operation ownership. Privacy and immutable
   tags are reconciled with ETags and re-observed before returning success.
3. After verifying release admission, call `RememberImage` with each exact image
   OCID and sha256 digest. Before admitting releases or starting tasks, publish
   `SetPins` with the complete current/rollback/live-task root set and its full
   index/child closure. Every leaf needs an explicit empty `Children` entry.
   Missing sources must fail the inventory collection, never contribute empty
   success. Generation must advance; the inventory expires after two minutes.
4. Run `Collect` under that same regional authority. Only recorded admitted
   images older than one hour are eligible. A single KV compare-and-set excludes
   a new pin before an ETag-protected delete; a late pin is rejected before its
   workload starts. Lost responses leave the durable retirement identity for a
   later pass. Unknown images, incomplete inventories, foreign ownership and
   ambiguous 404s cannot grant deletion authority.

Existing `delivery.CollectArtifacts` informed the grace/retention semantics, but
its NATS object metadata CAS cannot fence OCIR image deletion. Existing
`releasechannel.ReleasePins` describes binary release hashes, not complete
container index/child/task references. Neither is silently treated as an OCIR
pin inventory.

The integration scenarios run actual signed OCI SDK HTTP requests against a
controlled OCI protocol server and use an actual file-backed JetStream store.
They cover lost create and delete responses, reconstruction with another leader,
ownership refusal, private/immutable repair, ETag conflict, authority checks on
retry, current/rollback/task/index retention, stale/incomplete inventories and a
pin arriving during deletion. They do not qualify live OCI behavior.

Open integration requirements: the regional always-on caller and durable bucket
owner, a complete REL/CORE/CAP pin producer participating before admission/start,
and OCIR pull authentication through OCI Vault. OCI metadata instance principals
do not authenticate private registry pulls. OCIR auth-token credentials require
an IAM principal whose server-side policy restricts the intended repositories;
storing a broad token under a narrow Vault name does not provide that scope.
The credentials owner must automate creation, delivery, rotation and resolution
at the executor boundary; no manual credential configuration is introduced here.

`NewPullSecrets` now provides the narrow existing-token boundary. An independently
root-approved `PullSecret` fixes the OCIR host, namespace/repository
and regional Vault reference. Both username and OCI-issued token remain in
one existing Vault JSON value `{username,password}`; neither enters admission
or object-storage metadata. `Describe` reads the actual CURRENT version and
returns only identity/version/hash/generation metadata for the existing release
or task admission. `Resolve` compares that claim to independently authenticated
`PullScope` and owned binding before rereading Vault. It rejects a changed secret
identity, version or content, missing/expired credentials and foreign registry
hosts. Returned credentials remain in memory for the synchronous pull and redact
JSON and formatting. There is no anonymous, environment or copied-task fallback.

The caller must derive `PullScope` from REL's `VerifiedContainer` and admitted
stable service/workload intent; it must separately verify the actual assigned
task/node identity. `PullClaim` does not establish authentication or monotonic
admission generation by itself. The existing signed admission and CAS owner must
enforce that ordering and independently obtain the root-approved `PullSecret`.
Rotating Vault CURRENT requires fresh admitted metadata; old references fail.

`PullSecrets` consumes a Vault value and conveys no issuance authority itself.
Missing credential ownership, scoped IAM policy, token or authenticated admission
binding leaves private pulls blocked. CORE owns the containerd resolver and
REL/task admission integration; these source checks do not qualify live IAM.

`NewIssuer` adds the first-party IAM-to-Vault producer. It consumes the sealed
`region.VerifiedOCIRIssuer` from the same root-signed foundation grant, the
existing persistent non-expiring regional KV, a fresh authority guard and the
existing tenancy-wide home IAM write lease. The guard must refresh current
trusted roots/source before comparing the exact grant digest and generation;
an initially pinned resolver cannot detect later root rotation by itself.
The issuer discovers the actual tenancy home and Object Storage namespace,
records the exact private immutable repository OCID, then creates only the
signed service user, derived group and single repository `read repos` policy.
The user permits auth tokens only and membership in its dedicated group only.
OCI supports `target.repo.name`; no unsupported repository-ID policy condition
is invented. A changed physical repository or broadened policy blocks progress.

The journal leases and checkpoints IAM creation retry tokens and nonsecret token
operations before each mutation. `CreateAuthToken` supports a persisted OCI
retry token; an uncertain operation never starts another unrecorded creation.
Recovery uses that operation and its pre-request token inventory, records an
exact observed token OCID and confirms revocation before fresh issuance when
the once-returned value cannot be recovered. Username and token enter only
Vault JSON. A new CURRENT version must match its recorded hash, and its token
must be active, before the old token is revoked. Rotation is fixed at thirty
days. Unknown identity, token or Vault values are not adopted.

The always-on controller caller, protected KV ownership and fresh-root guard
remain integration requirements. Runtime pulls need only map the sealed scope
to `PullSecret` and use `Describe`/`Resolve`; workers gain no IAM write authority.
No live IAM, token, policy or Vault writes were performed by these source tests.

Retirement tombstones are intentionally retained: a retired digest cannot be
re-admitted by a stale publisher. Journal exhaustion fails closed at one MiB.
Create recovery replays the persisted OCI retry token; an expired-token conflict
remains blocked instead of adopting a matching mutable name/tag. No repository
deletion, live mutation, paid capacity, IAM grant or secret installation was run.
