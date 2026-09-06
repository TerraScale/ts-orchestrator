# Identity service credential delivery

This subsystem owns the shared authentication credential used by TerraBase to
call dashboard identity introspection. It is separate from database encryption,
reactive capabilities, and workload/control TLS identities.

The live GRU controller generates 32 cryptographically random bytes and encodes
them as 43 unpadded base64url characters. Each generation has a separate OCI
Secret named from its public operation identity, fixed `identity-service-auth`
purpose metadata, and immutable version one. The official OCI instance-principal
signer authenticates management and retrieval requests. Generation recovers lost
create acknowledgements by provider name; fetching pins resource, purpose,
operation, generation, and version. The credential and application-owned encoded
provider/delivery bodies use locked nondumpable pages. HTTP/TLS and authenticated
JSON ingress still have transient transport/parser allocations; those are not
persisted or logged. Control records contain provider references, never secret
bytes or secret-derived fingerprints.

`FileConfig.Construct` creates the concrete OCI issuer, Cloudflare updater,
member mTLS client, and authoritative R3 journal. The main global worker runtime
calls the coordinator only under its live authority lease. Its ORCH_LEADERS
state and barrier records share the authority stream CAS; server commit time
fences expired sessions, with a flat prior journal recovering late commits.

First startup persists issuance before delivering the new active key to the
Worker and every configured member. Rotation persists a deadline before any
provider effect. The supported Cloudflare `PATCH scripts/{script}/secrets-bulk`
JSON Merge Patch atomically installs active key, previous key, and Unix-second
previous expiry. Expiry is at most 300 seconds and is never extended on retry.
Member delivery authenticates controller mTLS/SPKI and live authority, then
forwards only to the fixed engine admission Unix socket after verifying engine
UID 62011. The engine accepts orchestrator UID 62010, writes only its configured
identity file atomically with mode 0600, and proves authenticated dashboard
introspection before returning a version-only adopted receipt.

After every member adopts, the controller persists commit before deleting the
previous Worker binding. A recovered commit never restages the previous key.
Failed adoption persists rollback, restores the old Worker active key, and then
restores members with a greater delivery revision. Provider failure may prevent
cleanup by the deadline; the dashboard verifier still rejects the previous key
at the persisted expiry. Service may remain unavailable until authority/provider
access recovers; deadlines are not extended to hide that failure.

The deployment member endpoint inventory must include every admitted host.
Changing membership requires updating the trusted inventory; retiring previous
credentials against an incomplete inventory is not safe. The production estate
owner must maintain the complete roster as hosts are admitted.
