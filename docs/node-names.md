# Canonical regional node names (TS-776)

The final node name is `ts-<region>-<n>` everywhere: hostname, OCI display
name, NATS server name, enrollment, cell state and DNS. Roles belong in
metadata. Renaming a serving cell must preserve its instances, data volumes,
JetStream accounts, Raft groups and opaque peer IDs.

## Preparation release

NATS v2.15.0 derives its eight-character Raft ID from the server name. A
different name would therefore strand the persisted metadata, stream and
consumer peers. Removing the store ownership check cannot fix that.

Preparation keeps all names and identity calculations unchanged. Before
starting an embedded broker, ts-orch atomically pins the actual Raft ID,
cell and controller slot in `<store_dir>/node-identity.json` with `version: 1`. The record is
owner-only and synced to disk. Another slot, ID, malformed record or unsafe
file fails startup. The existing `server-name` ownership check remains.

The broker advertises `raft_node_id` in route/client INFO and system server
messages. Existing receivers ignore the new field, so preparation can roll
beside the previous binary. `/v1/snapshot` also reports the local ID under
`nats.raft_node_id`; it must match the owner-only pin.

1. Deploy the CI-qualified preparation release to every controller, one node
   at a time, through the existing signed release/self-update path.
2. Before each restart, verify the whole metadata group and current replicas
   for every serving stream and durable consumer. Wait for recovery before
   restarting another node. `FullClusterReady` alone does not prove catchup.
3. Read each node's snapshot and pin. Require all three peers to run
   preparation and advertise their unchanged IDs before any name changes.

Preparation is a prerequisite; it does not complete TS-776. Do not rename a
NATS server, edit its persisted Raft files, remove peers, restore stores or
re-found the cell during this release.

## Final naming release

The subsequent release must consume the pinned explicit identity and the
advertised peer IDs independently of display names, without old-name aliases
or missing-ID fallbacks. It must reject changing a running process's identity.
Qualify rolling name changes and a two-of-three cold restart using the same
stores, messages and durable consumer acknowledgements before deploying.

Then remove role-based naming generators and admission, fix every node/DNS
consumer, add the naming regression guard, and rename verified live targets
in place. Delete obsolete records only after their replacement is serving.
TS-776 acceptance requires final deployment evidence from GRU and SJC and
canonical names in the dashboard and APIs; preparation evidence is insufficient.
