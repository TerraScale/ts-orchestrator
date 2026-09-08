# Tenant authorization lease provisioning

`global.rotation.edge` requires `authorization_lease_audience` (the exact HTTPS
public API resource, at most 256 ASCII bytes) and
`authorization_lease_keys_file` (an owner-only private JSON file). The file has
`{"keys":[{"keyId":"current","key":"<64 lowercase hex>","notBefore":1,"notAfter":2000000000}]}`.
There are one or two keys, with unique IDs and material. IDs contain 1–32 ASCII
letters, digits, underscores or hyphens. Windows are Unix seconds, with an
exclusive `notAfter`; all integers fit exactly in JavaScript. The key is distinct
from capability and origin-proof keys. Provision the same independent ring to
the identity authority and native members; only the identity authority issues
leases. Secrets enter the Snippet only during in-memory template binding and
never enter artifact mirrors or journal metadata.

The identity authority signs the exact tenant epoch, global feature epoch,
audience, Region and original validity window. Members refresh a bounded,
deduplicated set of active tenants in batches through the existing authenticated
identity introspection API. Members verify and serve original unexpired leases
at `/api/v1/authorization/leases/<tenantULID>`; they do not sign or extend them.
The endpoint is served on OCI and cached at the CDN. Native and edge consumers
fail closed at the original signed expiry, including during authority outages.
There is no global membership snapshot publisher, embedded membership list,
periodic Snippet redeployment, or subscriber-dependent control-plane polling.
Database deletion revocations remain a separate existing mechanism.

The edge deployment contains `authorizationLeaseAudience` and
`authorizationLeaseKeys` entries `{id,key,notBefore,notAfter}`. The authenticated
probe uses `terrascale-capability-generation-response-v4` followed by newline
separated nonce, generation, phase, validUntil, revocationRevision,
revocationDigest, authorizationLeaseAudience, authorizationLeaseKeysDigest
(no final newline). The key digest is lowercase SHA256 over entries sorted by
ID, each `${id}.${key}.${notBefore}.${notAfter}\n`. It binds actual material and
windows, so a stale deployment cannot pass by reporting unchanged key IDs.
Source verification and authenticated probe observation must succeed before
publication succeeds. Probe success qualifies the observed ingress, not
worldwide propagation. Rotate using an overlapping current/previous ring;
restart the Go publisher with the new protected ring, then verify publication
before changing the authority's active signing key. Never remove a key before
its last issued lease expires.

The engine declaration optionally includes `publicApi.identity` with `endpoint`,
`issuer`, `audience`, `serviceKeyFile`, and `authorizationLeaseKeysFile`. Once
identity is declared, both protected credentials and an active verification ring
are mandatory. The renderer emits `[public_api.identity]` referencing
`/etc/terrascale/terrabase/identity/service.key` and
`/etc/terrascale/terrabase/identity/authorization-lease-keys.json`. The validated
engine seed transfers compact JSON and the service credential as separate
TerraBase-owned `0400` files; credentials never enter signed TOML, cloud-init
user-data, or the orchestrator's run inventory. The native consumer reloads this
private ring on control-plane lease installation. Its existing member Region
binds both admission requests and lease verification.

The authority uses `TERRASCALE_AUTHORIZATION_LEASE_KEY_ID`,
`TERRASCALE_AUTHORIZATION_LEASE_KEY`,
`TERRASCALE_AUTHORIZATION_LEASE_KEY_NOT_BEFORE`, and
`TERRASCALE_AUTHORIZATION_LEASE_KEY_NOT_AFTER`. Provision values from the same
active ring entry. The issuer clips every signed lease to its key's exclusive
expiry. Missing or expired issuer configuration fails startup; no consumer
mints replacement authority state.
