# Global control storage

`ts-deploy` owns CI execution and candidate publication. The orchestrator owns
signed candidate admission, per-Region OCI artifact mirrors, rollout and recovery.
Its global NATS runtime opens only the control records needed for those duties.

| Resource | Purpose | Limit per replica |
| --- | --- | ---: |
| `GLOBAL_SPEC` | Accepted desired-estate revisions and regional handoffs | 256 MiB |
| `KV_ORCH_LEADERS` | Global leases and fenced operational state | 8 MiB |
| `KV_GLOBAL_CELLS` | Regional directory observations | 64 MiB |
| `KV_GLOBAL_DELIVERIES` | Original signed intent and resumable regional fanout | 1,024 MiB |
| Total | Before overhead, snapshots and regional stores | 1,352 MiB |

Production remains R3 in GRU/SFO/FRA, totaling 4,056 MiB of declared stream
limits before overhead. These are storage limits, not measured allocation or
performance. The current qualification seed's 256 MiB broker budget cannot
admit this topology. Initial R1 provisioning must declare an adequate budget
and prove the complete profiles without reducing production limits.

The desired-state consumer is `global_cell_spec_{cell}`, consuming the retained
global desired subject. Its exact pull, acknowledgment, redelivery and replica
profile remains mandatory. Closed stream limits explicitly represent NATS's
unbounded fields as `-1`, so real broker readback matches the declared profile.

The runtime identity can inspect the profiles, acquire and renew the global
lease, read directory state, update the explicitly granted operational keys,
read and update `master.>` delivery records, and publish/consume desired state.
It can acknowledge allowed work and answer signed delivery requests. It cannot
create, update, delete or purge streams/buckets, or create/delete consumers.
Separate infrastructure authority provisions those resources before startup.
Direct KV read subjects are scoped to the permitted lease/operational keys and
master delivery keys; the broker rejects sibling mutation subjects.

The former CI stores, runner identities, runner OCI implementation, CI subjects
and credential issuer are deleted. No old-format reader, alias or migration
path remains for them. Accepted release payloads live in OCI mirrors. Exact
NATS inventory and access tests, including restricted real R3 startup, preserve
that delivery path while denying provisioning through runtime credentials.
