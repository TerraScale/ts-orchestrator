# Local Vault key leases

Nonlocal `orchestrator run` starts the key lease server after the embedded NATS
broker is ready and before admitting the runtime. These run-configuration keys
are required:

- `TS_ORCH_KEY_LEASE_SOCKET_FILE`: absolute local Unix socket path.
- `TS_ORCH_KEY_LEASE_CATALOG_FILE`: absolute wrapped-key catalog path.
- `TS_ORCH_KEY_LEASE_ENVIRONMENT`: exact deployment environment.
- `TS_ORCH_KEY_LEASE_PEER_UID`: exact decimal TerraBase service UID.
- `TS_ORCH_KEY_LEASE_SOCKET_GID`: dedicated socket-access group GID.

The socket has mode 0660 and a parent directory with mode 0710, both owned by
the orchestrator service UID and dedicated socket-access GID. TerraBase runs as
a distinct service user in that narrow group. The catalog has mode 0600 and its
immediate directory has mode 0700, both owned only by the orchestrator UID. Every ancestor belongs to root or the service
UID and has no group/other write permission. Symlinked paths are refused. A stale
socket is not unlinked on startup; systemd `RuntimeDirectory` cleanup owns crash
recovery. The server validates Linux `SO_PEERCRED` before reading requests.

The wire contract is TerraBase's `docs/contracts/key-delivery-v1.md`: bounded TBKL
version 1 binary frames, exact environment/tenant/project/database/key-version/
Region/purpose bindings, a 1–1800 second lease, and one fixed refusal response.
No raw provider response reaches callers or logs. The OCI SDK uses the existing
bounded instance principal federation worker. Decrypt requests go only to the
configured Region's exact Vault crypto endpoint, carry the exact KEK version,
and authenticate all binding fields as associated data.

`Provision` generates one DEK in locked, nondumpable memory, wraps it under each
selected Region's admitted OCI KEK version, and atomically persists all wrapped
copies before acknowledging. It never persists plaintext. Database creation must
supply a durable canonical ULID key version and stable expiry/lease settings;
a retry with conflicting settings fails. Different purposes are provisioned
separately. A key version cannot acquire a new Region by generating different
material. `MergeEntries` admits authenticated ciphertext deliveries on member
hosts, refuses conflicting copies, and cannot revive revoked entries.

Bootstrap calls `InitializeCatalog(path)` before starting the server. It
creates missing state and preserves a valid existing catalog; corrupt or unsafe
state fails closed. The database admission workflow must deliver wrapped records to
selected hosts before publishing placement; the read-lease socket refuses a
missing record and never provisions one implicitly.

Every lease reads the current durable catalog, calls Vault, then holds the
catalog lock across its final catalog check and socket transmission. Revocation during an in-flight unwrap therefore
fails closed. Retained old versions are returned only on an exact version
request. Already-issued leases remain valid for their bounded lifetime. Catalog
writes use a nonblocking exclusive file lock, atomic rename and file/directory
fsync; lock contention is a retryable unavailable result.

Tests cover binary framing, scope mismatch, protected filesystem paths, restart,
old/new version selection, revocation during unwrap, sanitized provider failure,
atomic multi-Region issuance and idempotent retry. The Vault transport test uses
local metadata/federation and crypto response fixtures; it does not prove live
OCI IAM policy, Vault availability, or production cross-host delivery.

`DestroyDatabase` removes every wrapped copy for an exact database scope and
persists a permanent tombstone. The same deletion operation returns its original
receipt after restart; another operation identity is rejected. Tombstones block
late ciphertext delivery, new key versions, and stale full-catalog replacement.
The receipt always includes a conservative 1800-second lease horizon, sampled
after acquiring the catalog lock. Clients anchor lease expiry to monotonic
request start, so a delayed response cannot extend this horizon. This is a
local durable receipt: it does not erase another host, historical catalog backups,
or previously exported ciphertext. All-host distribution, authorized deletion of
retained key-catalog copies, and expiry of every lease remain the reaper's
completion requirements. Shared regional KEKs are never deleted for one database.

Application-managed DEKs and their encoded request/response representations use
locked, nondumpable pages. The OCI SDK's ordinary plaintext string decoding and
request-body copying are bypassed while retaining its official federated request
signer. Go's HTTP/TLS implementation still owns transient transport buffers;
this package does not claim to control those internal allocations.
