# Database creation admission

The GRU lease owner accepts a database name, immutable Region/residency policy,
and an opaque operation ID within an authenticated environment, tenant, and
project. Acceptance allocates canonical ULIDs for the database and data-key
version and persists the entire plan before acknowledging it. Retrying the same
request returns those identities; changing its name ownership or policy fails.
Customer operation IDs are namespaced before placement publication.

The R3 journal shares the exact authority lease's JetStream stream and fencing
transaction with placement publication. Reads use a leader-routed barrier;
mutations preserve prior state against delayed post-expiry commits. The journal
reserves ciphertext capacity before admitting an operation. Its current 480 KiB
aggregate bound is a control-state limit, not a qualified customer capacity.

Reconciliation performs these durable steps:

1. Generate one DEK, wrap it under the admitted exact regional OCI KEK versions,
   and persist every wrapped copy in the journal before host delivery.
2. Deliver only the receiving Region's ciphertext to its two exact hosts. Each
   host merges the immutable binding into its private catalog before asking the
   local engine to durably admit the full database identity.
3. Publish the exact persisted placement request under its scoped retry ID.
   A lost response repeats the same host admission or placement operation.

`placement_pending` proves neither membership activation nor RF=2, catch-up,
writer ownership, or service readiness. After separately authorized membership
delivery, the engine admission is retried to publish the same closed scope under
its accepted role. A fresh nonce then challenges every selected member for a
signed readiness receipt. The authority verifies the exact database/key/placement
identity, two matching snapshot and WAL boundaries per Region, and equal causal
cut, frontier, and reconciliation root across selected Regions. Only those
persisted receipts advance the operation to `ready`. Missing evidence stays
pending; a transport acknowledgment never substitutes for it.

Local TerraBase calls the UID-authenticated Unix HTTP ingress:

- `POST /internal/v1/databases/create` accepts `environment`, `tenant_id`,
  `project_id`, `name`, `operation_id`, `regions`, and `residency`.
- `POST /internal/v1/databases/status` accepts only `environment`, `tenant_id`,
  `project_id`, and `operation_id`.

Creation returns HTTP 202 and status returns HTTP 200 with the original scope, operation ID, database ID, key
version, name, Regions, residency, and state. Create always acknowledges `pending`;
polling returns `ready` only after the verified proof set is durable. The scope must originate
from verified product identity; a request body is not ownership evidence. The
authority's required `Authorize` producer checks the original accepted request
again on polling. Missing authorization or control authority fails closed.

The host engine receives `POST /internal/v1/databases/admit` with the original
request plus `database_id`, `key_version`, `region`, and `member_id`. Only an
exact HTTP 200 `operation_id`/`database_id`/`state: admitted` receipt resolves
delivery. Engine and orchestrator pin each other's Unix peer UID.

NATS uses dedicated NKey identities, verified mutual TLS 1.3, no reconnect
buffer, and exact grants for `orch.database.create`, `orch.database.status`,
and `orch.database.host.<SHA256-of-engine-SPIFFE>.install`. Only GRU authority may
publish host installation. Member identities may request admission/status and
subscribe to their own installation subject, replying on request inboxes.
NATS carries bounded control metadata and wrapped ciphertext only.

Tests exercise real authenticated NATS transport, R3 restart and quorum loss,
lease replacement, immutable concurrent name ownership, lost effect responses,
UID rejection, cross-project polling isolation, and ciphertext-before-admission
ordering. They do not qualify OCI deployment or replication readiness.
