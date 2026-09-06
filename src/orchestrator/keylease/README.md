# Local Vault key leases

Nonlocal `orchestrator run` starts the key lease server after the embedded NATS
broker is ready and before admitting the runtime. These run-configuration keys
are required:

- `TS_ORCH_KEY_LEASE_SOCKET_FILE`: absolute local Unix socket path.
- `TS_ORCH_KEY_LEASE_CATALOG_FILE`: absolute wrapped-key catalog path.
- `TS_ORCH_KEY_LEASE_ENVIRONMENT`: exact deployment environment.
- `TS_ORCH_KEY_LEASE_PEER_UID`: decimal UID shared by the orchestrator and TerraBase.

The socket and catalog have mode 0600; their immediate directories have mode
0700 and belong to the service UID. Every ancestor belongs to root or the service
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

Every lease reads the current durable catalog, calls Vault, and reads the catalog
again before releasing a key. Revocation during an in-flight unwrap therefore
fails closed. Retained old versions are returned only on an exact version
request. Already-issued leases remain valid for their bounded lifetime. Catalog
writes use a nonblocking exclusive file lock, atomic rename and file/directory
fsync; lock contention is a retryable unavailable result.

Tests cover binary framing, scope mismatch, protected filesystem paths, restart,
old/new version selection, revocation during unwrap, sanitized provider failure,
atomic multi-Region issuance and idempotent retry. The Vault transport test uses
local metadata/federation and crypto response fixtures; it does not prove live
OCI IAM policy, Vault availability, or production cross-host delivery.
