# Membership revocation publication

The GRU lease-owned runtime requires `global.membership_revocations` with
`endpoint` (HTTPS `/api/internal/identity/introspect`), `audience` (the public API
resource), and `service_key_file` (a protected identity service-key file).
`buildProductionGlobalConfig` constructs the publisher with the same durable
Snippet store as key rotation. `productionGlobalWorkers.Start` schedules its
`Tick` every ten seconds and owns cancellation and cleanup.

Each poll sends authenticated POST JSON `{ "kind": "revocations", "audience": ... }`
with `x-terrascale-identity-service-key`. Redirects are rejected. The response is
`{ "active": false, "membershipRevocations": { "revision": ..., "validUntil": ...,
"entries": [{ "scope": ..., "expiresAt": ... }] } }`.
Entries are sorted unique `scope-` plus 64 lowercase hex characters, capped at
32. Revision is SHA256 hex over each `${scope}.${expiresAt}\n` in order. The
source supplies the thirty-second Unix-seconds lease; the publisher never
extends it locally. Durable publication rejects disappearance or shortening of
live tombstones. A failed read or deployment is retried at the next tick.

The Snippet deployment keeps database revocations and membership revocations
separate. A delegated capability authenticates
`<database scope>:<membership scope>` inside its existing v1 scope field. The
native issuer binds both to the same organization before signing. The edge
checks both after HMAC verification and before cache lookup. Missing or expired
membership authority denies delegated reads; native database credentials retain
their database-scoped authorization. Membership never enters the shared URL
cache key. No Worker executes on the reactive read path.

The authenticated ingress probe uses response-v3, appending membership revision
and lease expiry after the existing database revocation digest. Both publisher
source verification and authenticated ingress observation must succeed before a
publication reports success. This observation is not a proof of worldwide edge
convergence; stale locations fail closed when their source lease expires.
