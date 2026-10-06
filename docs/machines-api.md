# Machines API

The Machines API is a REST API in the style of Fly Machines for one region's
apps and machines. The region's controllers serve it at
`https://gru.orch.terrascale.tech`, and the `ts-orch` CLI uses the same API.
It serves the shared model of [apps and machines](apps-machines.md) (TS-563)
and [dedicated tenants](dedicated-tenants.md) (TS-566); it adds no model of
its own. The code is in [`internal/machinesapi`](../internal/machinesapi),
and the controller wiring is in
[`internal/app/machines_api.go`](../internal/app/machines_api.go). The
OpenAPI document is [`openapi.json`](../internal/machinesapi/openapi.json),
and a running controller serves it at `GET /v1/openapi.json`. Its schemas are
`internal/machines` types and stay unstable (`1-alpha`) until that model
settles.

## Status

The work ships in slices under TS-564.

| Slice | Scope | State |
| --- | --- | --- |
| 1 | ts-auth token verification, tenancy, read apps and machines, OpenAPI, `controller.machines_api` (lab only) | this change |
| 2 | Regions and node pools, events (read) | planned |
| 3 | Changes: leader path, idempotency keys, the envelope check | planned |
| 4 | Machine lifecycle (create, start, stop, restart, destroy, update), scale | planned |
| 5 | Releases and rollouts (status, rollback), logs streamed from NATS | planned |
| 6 | `ts-orch apps\|machines` CLI on the API | planned |
| 7 | Signed listener and TLS material, `gru.orch.terrascale.tech` load balancer listener and DNS through the edge reconciler | planned |

## Routes

| Route | Scope | Returns |
| --- | --- | --- |
| `GET /healthz` | none | `{"status":"ok"}` |
| `GET /v1/openapi.json` | none | The OpenAPI document |
| `GET /v1/apps` | `orch:read` | `{"apps": [App]}`: the apps the caller may see |
| `GET /v1/apps/{app}` | `orch:read` | The app |
| `GET /v1/apps/{app}/machines` | `orch:read` | `{"machines": [Machine]}`, each with its `status` once observed |
| `GET /v1/apps/{app}/machines/{id}` | `orch:read` | The machine and its `status` |

A machine's `status` is the orchestrator's last observation, kept in its
own bucket so host reports never contend with desired-state writes
([apps and machines](apps-machines.md#model)). The API reads the two
records separately, so a status can lag the machine: it may describe the
previous `version` or `desired` state until the next observation.
`updated_at` says when it was observed. The API returns no snapshot of both.

A path value becomes part of a KV key only after it matches the model's
rules (an app name is a DNS label, a machine ID is 16 hex digits).
Otherwise the request gets 400 `invalid_name`, so a value cannot widen a
key filter.

## Serving

A controller serves the API when its config has `controller.machines_api`:

```json
"machines_api": {
  "listen_address": "10.251.0.11:8444",
  "tls_cert_file": "/etc/ts-orch/machines-api.crt",
  "tls_key_file": "/etc/ts-orch/machines-api.key",
  "issuer": "https://gru.auth.terrascale.tech/terrascale",
  "audience": "https://gru.orch.terrascale.tech",
  "jwks_urls": [
    "http://127.0.0.1:8080/terrascale/.well-known/jwks.json",
    "http://10.251.0.12:8080/terrascale/.well-known/jwks.json"
  ],
  "clients": ["ts-orch-cli"],
  "members": {"terrascale": ["<user UUID>"], "<organization ID>": ["<user UUID>"]}
}
```

- Every read uses the replicated `TS_APPS`, `TS_MACHINE_STATUS` and
  `TS_TENANTS` buckets, which every controller can read, so any controller
  answers.
- Off loopback the listener requires `tls_cert_file` and `tls_key_file`:
  requests carry bearer tokens.
- Each controller accepts at most 256 connections. The load balancer brings
  the internet to hosts that also run the cell's NATS quorum and authority.
- **Signed production configs refuse `machines_api` for now.** The
  listener's port, its TLS material from the signed material directory, and
  the load balancer listener all come in slice 7, together with
  `render-controller-config`. Until then the API runs only on lab
  controllers. A signed config can therefore not bind the API onto the host
  enrollment port, or name TLS files that nothing delivers.

## Authentication

Every route except `/healthz` and `/v1/openapi.json` requires a ts-auth
access token as `Authorization: Bearer`. ts-auth has no introspection
endpoint, so the controller checks the token itself:

- The token must be an RFC 9068 JWT with `typ: at+jwt`, so ts-auth ID
  tokens (`typ: JWT`) are refused.
- It must be signed with `ES256`, the only algorithm ts-auth uses, by a
  `kid` from the issuer's key set. No other algorithm is tried, `none`
  included.
- `iss` must equal `issuer` exactly.
- `aud`, a string or an array, must contain `audience`.
- `client_id` must be one of `clients`. Every ts-auth token carries every
  configured audience (`TS_AUTH_ACCESS_TOKEN_AUDIENCES`), so the audience
  alone would accept, for example, the dashboard's tokens. The client
  allowlist keeps them out.
- `exp` is required. `nbf` and `iat` are checked when present, each with
  one minute of clock skew.
- `sub` is required.

**Key set.** The controllers have no internet route, so they fetch ts-auth's
key set on the cell's private network. They use the first of `jwks_urls`
that answers: the local replica, then another controller's. It takes the
first set that holds the token's `kid`, so a replica that has not caught up
with a new key neither hides nor drops it. ts-auth's replicas share one key
ring and never retire a key, so lag only ever hides a new key; a key that
ts-auth withdraws goes once no replica publishes it. ts-auth runs on
some controllers only. Plain `http` is allowed only to loopback and private
addresses. The controller refreshes the set as follows:

- It refetches the set every 10 minutes, so a key that ts-auth withdraws
  stops verifying.
- It also refetches when a token names an unknown `kid`, so a new key starts
  verifying.
- It fetches at most once every 30 seconds, so forged key IDs cannot flood
  ts-auth.
- The fetch does not depend on the request that triggered it, so a client
  that disconnects cannot cancel it.
- If a refetch fails, the controller keeps the keys it has until every
  token signed before the last fetch has expired (one hour more). After
  that it refuses every token, because a key that ts-auth withdrew during
  the outage would otherwise stay trusted.

ts-auth cannot revoke an access token. A token stays valid until its `exp`,
which is one hour after it is issued. A rejected token's reason is logged at
debug level and never returned.

## Authorization

Authorization combines scopes with organization membership.

**Scopes.** Reads need `orch:read`. Changes will need `orch:write`.

**Tenancy.** ts-auth tokens don't carry an organization or project yet, so
the `members` map decides which organization a `sub` acts for. A `sub` is a
user UUID, or a service client's ID for a client-credentials token. A
subject belongs to at most one organization. The map is part of the
controller config, so in production a root signs who acts for which
organization.

- Members of `terrascale`, the platform organization, see every app:
  platform apps and tenant apps.
- Members of any other organization see only the tenant apps whose
  tenant's `organization` (in `TS_TENANTS`) is theirs. An app whose tenant
  record is missing is visible only to the platform.
- An app outside the caller's view returns 404, not 403, so app names don't
  leak across tenants.
- A valid token whose subject is in no organization gets 403
  `no_organization`.

Under [TS-569](settings-in-cell-spec.md), `members` moves into a root-gated
cell spec section, so onboarding a member needs no new controller config.
Once ts-auth publishes organization membership in tokens or through an API,
that replaces `members`, and a member map keyed by issuer as well as subject
is no longer needed. Access per project within an organization comes with
the tenant create path (TS-566 slice 3).

### ts-auth changes needed

The API cannot be used until ts-auth makes these changes:

1. Add `https://gru.orch.terrascale.tech` to ts-auth's
   `TS_AUTH_ACCESS_TOKEN_AUDIENCES`. This is a ts-auth profile change, an
   ordinary cell spec amendment.
2. Add a public `ts-orch-cli` client (authorization code with PKCE, or
   device flow), and let it and the automation service clients request
   `orch:read` and `orch:write`. Today ts-auth registers only `email` and
   `profile` for the dashboard, and gives client-credentials clients no
   scopes.
3. Optionally, per-resource audiences (RFC 8707), so a token names this API
   alone.

## Errors

Every error is JSON, `{"error": "<code>", "message": "<text>"}`. The codes
are stable:

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_name` | A path value breaks the model's name or ID rule |
| 401 | `unauthenticated` | A missing or rejected token, or a client not in `clients` (`WWW-Authenticate: Bearer ... error="invalid_token"`) |
| 403 | `insufficient_scope` | The token lacks the route's scope (`WWW-Authenticate` names it) |
| 403 | `no_organization` | The subject is in no organization |
| 404 | `not_found` | No such app or machine visible to the caller |
| 503 | `unavailable` | The controller cannot read the cell state |

Responses carry `Cache-Control: no-store`.

## Changes (slices 3 and 4)

The design follows the apps model's trust rule: `TS_APPS` is not signed,
only the authority leader writes it, and nothing in an app can widen
authority. The signed cell spec stays the envelope, holding Vault secrets,
releasers, host grants, TerraBase's profile and the admitted artifacts.

- **Envelope check.** An API change is checked on the authority leader
  against the current records and the envelope. Examples are a scale count
  within the app's limits, start, stop or destroy of a machine, or a new
  version of an admitted digest. The leader then writes the change with the
  store's epoch guard and compare-and-swap. A change outside the envelope
  returns 403 `root_required` and names what needs a root. This covers
  Vault secret references, releasers, host grants and TerraBase's profile,
  the same list as `cellspec.AuthorityChanges`. The operator applies those
  changes with a root-signed `ts-orch apply`. There is no API signing key: a
  key that every controller holds would sign what a compromised controller
  wants, so it would add no protection.
- **Leader path.** A controller that is not the leader hands the change to
  the leader over the cell's NATS. Only the leader answers, as with operator
  requests today, so the load balancer may pick any controller.
- **Idempotency.** An `Idempotency-Key` header names a change. The leader
  keeps the request digest and the reply under `(organization, subject,
  key)` in a KV bucket whose records expire after 24 hours. A retry gets the
  same reply, and a different request under the same key gets 409. Keys of
  different callers never meet, so a guessed key cannot reveal another
  tenant's reply.
