# Apps and machines

The [Machines API](machines-api.md) projects the current regional SwarmKit
manager's services and tasks into the public `internal/machines` response
model. SwarmKit owns placement, repair, rolling updates and task lifecycle.
There is no separate app scheduler or machine task store.

## Identity and authorization

Platform services use their signed profile's role as the app name. Tenant
functions use `fn-<lowercase intent ULID>`; their function-tenant binding is
checked against the derived manager service intent. Qualified TerraBase
member services use `db-<lowercase intent ULID>`. Member services currently
carry no tenant binding, so only the platform organization can see them.

An app ID is a canonical ULID derived from its actual manager service ID.
A machine ID is a canonical ULID derived from its actual task ID. Recreating
a service or replacing a task creates a new public identity; old task IDs
are never reassigned to replacement tasks. Versions are manager object
versions, and `regions` reports the service's actual requested replicas.

The existing signed Machines API organization membership and tenant store
control visibility. A tenant organization sees only apps owned by its
tenants. Foreign app and machine lookups return 404. Platform members can
see every admitted regional app. The API is read-only.

## Current observations

Each authenticated request reads a fresh snapshot under the current
controller authority epoch and actual manager leadership. Service and task
versions, host observations and the signed profile snapshot are rechecked
before returning it. Authority loss, ambiguous identities, concurrent
changes or unavailable manager state return 503; retained inventory is
never a fallback.

Machine configuration exposes only image digest, role and resource limits.
Container environment variables, arguments and files are omitted because
they may contain production secrets. `RUNNING` maps to `starting` until an
independent application probe succeeds; it is never sufficient to claim
`started`. Desired shutdown and removed tasks preserve their stopped and
destroyed intent, and retained manager task history remains visible.

`TS_APPS`, `TS_MACHINES` and `TS_MACHINE_STATUS` are retired. The API does
not open or reserve those buckets, and KV snapshots no longer include them.
Manager state remains in SwarmKit's own persistent state.
