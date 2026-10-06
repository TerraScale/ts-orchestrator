# Apps and machines

TS-563 turns ts-orch into a full orchestrator for TerraBase, ts-auth and
tenant workloads. Its model, in the style of Fly.io Machines, is shared by
the Machines REST API (TS-564), autoscaling (TS-565), dedicated tenants
(TS-566), managed volumes (TS-567) and self-healing (TS-568). Package
[`internal/machines`](../internal/machines) owns the types and their store.

## Model

An **app** is one service: `terrabase`, `ts-auth` or a tenant workload.

| Field | Meaning |
| --- | --- |
| `name` | DNS label, unique in the cell. |
| `id` | Set by the store at creation. It names this incarnation of the app, so a machine left over from a deleted app of the same name is an orphan, never adopted. |
| `class` | `platform` (TerraScale's own services) or `tenant`. A tenant app names its `tenant`. |
| `version` | Set by the store: 1 at creation, plus one on every `config` change. |
| `config` | The machine template (below). |
| `regions` | Region pinning and scale: machines per [catalog](../internal/ociregion/catalog) region (`{"gru": 3}`). Autoscaling changes these counts; they do not change `version`. |
| `node_pool` | Optional: place only on hosts of this signed [node pool](../internal/hostpool/pool.go). |

A **machine config** is what a host runs: the admitted artifact `role` and
`digest`, `args`, `env`, `resources` (CPU cores, memory and disk bytes),
`services` (named ports published for discovery), health `checks` (`http`,
`tcp` or `exec`) and a `restart` policy (`always`, `on-failure` with
`max_retries`, or `no`).

A **machine** is one placed instance of an app, the desired state: its `id`
(16 hex digits), `app` and `app_id`, `region`, `host` and the host's
`failure_domain`, the app `version` and `config` it runs, and the `desired`
state (`started`, `stopped` or `destroyed`).

A machine's **status** is what the orchestrator observes: its `state`
(`pending`, `starting`, `started`, `stopping`, `stopped`, `failed`, `lost`
or `destroyed`) and `updated_at`. It is a separate record, so host reports
and desired-state writes never contend.

Regions are the [catalog](../internal/ociregion/catalog)'s and node pools
are the signed controller config's
(`controller.autoscale.node_pools`). Neither is copied into KV: an unsigned
copy would be a second source of truth.

## Trust

The buckets are not signed. An app can therefore never widen authority:
Vault secrets, releasers, host grants and TerraBase's profile stay in the
root-gated [cell spec](cell-spec.md#trust), and a machine config cannot
name a secret. When the scheduler admits an app (slice 2) it also requires:

- A machine gets its role's signed profile, secrets included, only when its
  app is the platform app named after that role, and its `args` and `env`
  are then the profile's. Any other app, every tenant app included, runs
  its role's artifact without the profile's secrets.
- A role that a cell-spec service spec reconciles, or placement's member
  role, is not also an app until it moves onto apps (slice 5).

## Store

The replicated JetStream KV bucket `TS_APPS`, in the regional cell, holds
the desired state and snapshots to Object Storage with the other
configuration buckets ([kv snapshots](../internal/kvsnapshot)). Statuses
live in `TS_MACHINE_STATUS`, which is not snapshotted: a rebuilt cell
relearns them from its hosts.

| Bucket | Key | Value |
| --- | --- | --- |
| `TS_APPS` | `apps.<app>` | App |
| `TS_APPS` | `machines.<app>.<id>` | Machine |
| `TS_MACHINE_STATUS` | `status.<app>.<id>` | Status |

Only controllers can reach the buckets, and only the authority leader
writes them. A store is bound to its region. Every write checks the
writer's authority epoch and then compares and swaps on the record's
`Revision`, which every read and list returns. Two writers therefore cannot
lose each other's update, and a deposed leader's writes are refused once it
sees its fenced epoch. The check and the write are separate operations, so
a leader that stalls past its lease right after the check can still land
one write. Effects on hosts stay safe only because they go through the
epoch-fenced host desired state. Every read decodes strictly (no unknown
fields), validates the record and checks that it belongs to its key, so a
value copied, restored or written under another key is refused rather than
used. A list that meets such a record fails as a whole, so no caller acts on
a partial view; the scheduler lists one app at a time. The store also keeps
these invariants:

- An app's `id`, `class` and `tenant` never change.
- A new machine is in the store's region and names the current `app_id`.
  Its `app_id`, `region` and, once set, `host` never change. Moving a
  machine means creating a replacement and destroying the old one.
- `destroyed` is final for both `desired` and `state`: no late writer can
  bring a destroyed machine back. A machine record is deleted only once it
  is desired destroyed and, if it was placed, observed destroyed.
- An app is deleted only while no machine record names it.
- A status is written only while its machine exists. One that races its
  machine's deletion can outlive it: readers join statuses to machines, and
  the scheduler's `SweepStatuses` deletes statuses without a machine.

## Extending the model

Sibling tickets add to these types rather than wrap them. TS-572 adds the
artifact kind and runtime driver, volumes, placement constraints, an
update strategy and stateful quorum rules; TS-567 adds volume mounts.

- Add an optional field (`omitempty` or `omitzero`) and check it in the
  type's `Validate`. A record without the field must keep its meaning.
- Put what a host runs in `config`, so that changing it is a new app
  `version` and reaches the machines. Put scheduling and rollout policy on
  the app; changing it is not a new version.
- Reads refuse unknown fields. A controller binary that predates a field
  therefore refuses a record that uses it, instead of rewriting the record
  without it. Release the binary that knows a field before anything writes
  it.
- `resources` counts whole CPU cores, as host capacity and placement do.
  Finer CPU shares would be a new field.

## Slices

1. Shared types and their store (this note).
2. Scheduler on the authority leader. `machines.Plan` (2a) is the pure
   planner: every app gets its region's count of machines; a machine goes
   to a schedulable host of its role and node pool that runs no other
   machine of the app and has its resources and service ports free,
   spreading across failure domains first and packing the fullest host
   within them. A new app version updates machines in place where their
   host still fits. Machines of a deleted or recreated app are destroyed;
   machines of a lost host are replaced and marked `lost` (they may still
   run), those of a deregistered host are destroyed. A destroyed record is
   deleted only once its process is known gone. Apps of a role the cell
   spec or TerraBase placement still places are held. The leader loop (2b)
   feeds it the registered hosts and applies its writes.
3. Runtime: the host agent runs each machine as a hardened systemd unit
   (`DynamicUser`, CPU and memory limits, `ProtectSystem`, a seccomp filter,
   private `/tmp`), runs its health checks and restart policy, logs to the
   journal and reports the machine's state.
4. Service discovery: machine endpoints over NATS, and load balancer backend
   sets kept in step with them (replacing the placement-driven public NLB
   sync in [OCI reconcile](oci-reconcile.md)).
5. Move ts-auth and TerraBase onto apps, edited through `ts-orch apply` and
   the REST API.
