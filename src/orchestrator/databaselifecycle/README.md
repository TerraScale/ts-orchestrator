# Authoritative lifecycle inventory

`databaseadmission` embeds this state in its epoch-fenced R3 authority journal.
A database or branch create and its immutable lifecycle identity enter in one
CAS transaction. The create-only record list is not a billing inventory.

Resources retain their original organization, project, database identity,
parent linkage, selected Regions and creation time. Branches use their own
canonical database identity in usage facts. Branch admission checks that the
parent remains live, including a pending deletion fence. Parent deletion covers
all descendants. Retained backups do not extend the billable existence interval.

The deletion workflow first persists its exact cutoff and expected regional
stop targets. Inventory closure blocks while any stop receipt remains unresolved.
Only the complete set of authenticated native stop receipts permits the atomic
access-revoked tombstone and usage cutoff. Physical cleanup remains a separate
operation; accepting deletion does not claim retained artifacts were destroyed.

Routing registration supplies the complete trusted stream history, including
partition identities and every epoch. Existing identities and start times cannot
be rewritten or removed; an open stream can receive its terminal stop once.
Registering a new stream whose effective start precedes a closed inventory window
is rejected even if the registration request itself has a later timestamp.

`FreezeEnvironmentInventory` closes one organization interval atomically with its
resource and expected stream set. It rejects mixed environments, overlapping
closures, incomplete routing coverage, and unresolved deletion stops. The receipt
contains only streams intersecting the resource's billable interval, while the
live authority retains full historical stream and resource records. Empty-cycle
receipts also carry their deployment environment. Exact retries return the same
revision and SHA-256 digest. Native per-stream usage sealing and the authenticated
all-Region usage barrier remain required to close billing; this inventory receipt
alone does not prove usage completeness.

The journal is bounded. Capacity estimates reserve future terminal deletion and
stream receipts as well as key/readiness progress. Exhaustion rejects the new
transition; it never truncates history or fabricates a complete inventory. Long
term history archival requires a separately designed durable authority log, not
pruning these accepted receipts in place.
