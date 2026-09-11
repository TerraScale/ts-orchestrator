# Auth consensus bootstrap

GRU records an explicit auth-domain genesis grant in the global R3 lease stream.
The same stream CAS fences the grant against the exact live lease; persisted
server time must fall inside that lease. The grant binds the committed sequence,
canonical group ULID, complete database scope, generation one, immutable Regions,
two identified voters per Region, and one designated genesis node.

The production runtime file references `auth_bootstrap_file`. That bounded JSON
file has `version: 1`, `targets` with exact `server_identity` and `principal`
SPIFFE URIs, and `grants` containing producer `AuthGroupBootstrapGrant` protobuf
JSON. Grant `authority_revision` must be zero/omitted. Storage incarnations may
be pinned explicitly or discovered through the authenticated engine Identity
RPC before first acceptance. No ordinary customer database implicitly becomes
an auth domain.

Once accepted, retries replay the same operation, grant, incarnation, and target.
Lost acceptance acknowledgments trigger a journal lookup before delivery. Lost
engine replies trigger the same request. A different incarnation or a second
group for the same database is refused, including after a controller restart.
Disk loss requires recovery; neither a missing file nor a placement PENDING
receipt authorizes another genesis.

Delivery uses dedicated exact-host NATS subjects and host NKeys, followed by
loopback TBEP with pinned mTLS identities. This auth-bootstrap path carries
only its control metadata in NATS; the database-admission journal may also
carry validated BYOK references and wrapped ciphertext, but never provider
credentials, plaintext keys, or customer data.
Receipt validation requires the complete grant echo, operation identity, and
local storage incarnation. PERSISTED is not quorum, catch-up, or API readiness;
the engine's admitted auth Raft runtime owns those decisions.

Tests exercise real TLS/NKey R3 journal restart, lost acceptance and engine
acknowledgments, successor fencing, minority refusal, immutable scope conflicts,
exact-host dispatch rejection, and pinned TBEP client transport. They do not
qualify the complete multi-host Rust auth Raft deployment.
