# Dedicated tenants

A dedicated tenant is one ts-auth organization's project that owns its own
TerraBase cluster and, optionally, its own ts-auth instance. The orchestrator
places them on demand, on hosts no platform workload or other tenant uses,
and runs their whole lifecycle: create, resize, scale, upgrade, suspend and
delete with data retention. Ticket: TS-566. Package:
[`internal/tenant`](../internal/tenant).

## Model

A **tenant** is one record in the cell's `TS_TENANTS` KV bucket, key
the tenant’s canonical uppercase 26-character ULID, schema `terrascale.tenant.v1`.

| Field | Meaning |
| --- | --- |
| `id` | 3 to 30 lower-case letters and digits, starting with a letter; immutable and never reused. No hyphen, so it is one DNS label, NATS token and KV token, and no tenant's role or Vault name is a prefix of another's. New tenants may not take a reserved name (`api`, `auth`, `www`, ...). |
| `organization`, `project` | The owning ts-auth IDs; immutable. |
| `cell` | The catalog cell that runs it, e.g. `gru`; immutable. |
| `spec.plan`, `spec.member` | The plan and what one TerraBase member reserves under it. `member` is copied from the private plan catalog (`tenant.Plans()` returns a copy) when the tenant picks the plan, and creation and every plan change must match it exactly, so a later catalog never resizes a running tenant. |
| `spec.members` | TerraBase members: 1, or 3 for a replicated cluster (TS-561). |
| `spec.terrabase`, `spec.auth` | Admitted artifact digests. An empty `auth` means no dedicated ts-auth. |
| `state` | `active`, `suspended`, `deleted` or `purged`. |
| `generation` | Exactly one more than the record it replaced. |
| `retain_until` | Set once deleted: when its volumes and backups may go. |

Plans: `starter` (1 core, 4 GiB, 20 GiB disk), `standard` (2, 8, 100),
`pro` (4, 16, 250), `scale` (8, 32, 500). A dedicated ts-auth replica
reserves the platform ts-auth profile (1 core, 1 GiB, 2 GiB).

## Lifecycle

```text
          change (resize | scale | upgrade | rollback | ts-auth on/off)
            +----+
            v    |
 create -> active ---- suspend ----> suspended
            |   ^------ resume -------'  |
            |                            |
            '---------> deleted <--------'
                           |  delete (retention 1 to 90 days, default 7)
                           v
                         purged   (after retain_until; the record stays)
```

Each transition is a method on `Tenant` that returns the next generation.
`CheckSuccessor` decides what a write may do. The store runs it against the
record it holds, never against the writer's copy, so a hand-built or forged
record cannot:

- skip or repeat a generation, move back in time, or move the tenant's ID,
  owner, cell or creation time;
- leave `deleted` other than to `purged`, or purge before `retain_until`;
- change the spec of a suspended or deleted tenant;
- change member resources except by choosing a plan on sale at them, or
  move to a plan with less disk: OCI block volumes never shrink;
- change the release and the topology in one generation, so a rollback is
  exactly the previous release.

A leader whose clock is behind the previous writer's stamps the previous
time instead, so clock skew never freezes a tenant. The store refuses a write
stamped more than a minute past its own clock, so no caller purges a tenant
before `retain_until` by passing a later time.

Every write is a KV compare-and-swap on the revision the writer read. Of two
controllers that read one revision, for instance on either side of a
partition, only the first write lands; the other rereads. Reads come from the
stream leader, because a KV get may be served by a follower a moment behind.
Records are never removed: a create writes only a key that was never written,
and a delete marker reads as tampering. A list holds every tenant created
before it began, each at its latest state; a tenant missing from it was
created during the list, never removed. A read refuses a record that is not
valid, has unknown fields or another schema, or sits under another tenant's
key, and one such record, or a listing cut short, fails the whole list, so a
reconciler never takes a tampered or truncated bucket for tenants that are
gone.

## How a tenant runs

These parts land in later slices, on the shared types of TS-563.

**Apps and machines.** A tenant becomes two TS-563 apps of class `tenant`:
`t-<id>-db`, a stateful TerraBase app with `members` machines, and, when
`auth` is set, `t-<id>-auth`, a stateless ts-auth app. The reconciler
refuses a digest that delivery has not admitted for the `terrabase` or
`ts-auth` role in the tenant environment.

**Isolation.** Dedicated means dedicated hosts. Each TerraBase member gets its
own host, sized to the plan plus the system reserve, with a retained volume,
the way managed members are placed today; the tenant's ts-auth replicas run
on its member hosts. No platform workload and no other tenant runs there.
Each tenant gets its own network security group: the public load balancer
reaches the client port, and only the tenant's own members reach each other's
replication port. Replication uses a member CA per tenant.

**Endpoints.** `<id>.<cell>.api.terrascale.tech` reaches the tenant's
TerraBase and `<id>.<cell>.auth.terrascale.tech` its ts-auth, through the
edge reconciler (`internal/ociregion/publicapi`). These names are two labels
deep, so Cloudflare's universal certificate does not cover them; the cell
needs an advanced certificate for `*.<cell>.api` and `*.<cell>.auth`.

**Secrets.** A tenant's secrets live in OCI Vault under the existing scheme,
`<cell>-1-t-<id>-db-<key>` and `-auth-<key>` (`vaultsecret.ValidateRefs`).
The Vault, the compartment and the key set of the tenant class are fixed by a
root-signed cell spec amendment, so a tenant record never chooses a Vault
secret (TS-554). Each tenant's hosts carry a defined tag with its ID, and a
dynamic group per tenant matches that tag, so a host reads only its own
tenant's secrets. The controller creates them once with `vaultsecret.Ensure`
and never prints a value. IDs are never reused, so a new tenant never
inherits an old tenant's secrets.

**Backups.** The existing TerraBase backup operation writes each tenant to
the cell's backup bucket under the prefix `tenants/<id>/`. Restore goes into
the same tenant. Deleting a tenant keeps its backups and retained volumes
until `retain_until`; the purge removes them and then marks the record
`purged`.

**Metering.** Once a minute the leader publishes one usage event per tenant
to the JetStream subject `ts.metering.<cell>.tenant.<id>`, with message ID
`<id>/<period>` so a retried publish is not counted twice. An event carries
the plan, members, ts-auth, state and reserved core, memory and disk seconds
for its period. Billing consumes the stream; the orchestrator does not price.

**Upgrades.** An upgrade is one generation that changes only `terrabase` or
`auth`. The rollout executor (#188) stages the release on every machine of
the tenant at once and restarts them in waves that keep a 3-member cluster's
quorum. When the health gate fails, it rolls every machine back and writes
the next generation with the previous release, so the record never points at
a release that failed; the failure goes to the decision journal. A 1-member
tenant restarts in place with a short outage. Servers are never replaced for
an update.

**One tenant per project.** The create path (slice 3) first claims the key
`project.<organization>.<project>` with a never-written create, so a retried
create cannot start a second billed cluster.

## Slices

1. Model, lifecycle and the KV store (this note).
2. Tenant to TS-563 apps on dedicated hosts and the controller reconciler;
   suspend stops the machines.
3. Machines API (TS-564), the project claim and `ts-orch tenant` commands.
4. Endpoints through the edge reconciler.
5. Vault secrets for each tenant.
6. Backups, restore and purge after retention (with TS-567 volumes).
7. Metering events.
