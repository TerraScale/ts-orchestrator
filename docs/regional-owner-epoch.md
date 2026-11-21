# Regional owner epoch prototype

The release mesh needs to tie readiness publication and dispatch to the
current admitted manager process. The installed app lease stores a caller
ID and expiry. A second client can renew it using the same ID, so that lease
cannot fence an earlier process or authorize readiness completion.

The prototype's `Store.InstallMembership` accepts a signed membership view
for one region and Swarm cluster. The authority connection and membership
signing public key are provisioned at its trust boundary. A view identifies
the admitted manager node IDs, a monotonically increasing epoch and a
deadline. The membership
source must derive it from committed membership and deliver changes through
the protected authority before the new membership is used. The journey
uses a separate fixture signer, reads a real admitted Swarm manager and
verifies its regional manager certificate. Production integration requires
an independently authenticated delivery of that committed view. Local
`state.json`, a caller-supplied region and a Swarm term read taken before a
JetStream write cannot supply the ordered membership transition.

An acquisition is signed by the regional manager credential and by the
fresh process session key. The authority derives the manager identity from
the verified certificate, compares it with the current membership and
binds the owner epoch to the session public key. Subsequent renewals and
publications require that session's signature over the region, cluster,
membership epoch, owner epoch, operation and strictly next sequence. A
different process with the same manager ID cannot take a live lease.
Keep the session private key in the owning process. Copying the key gives
another process the same signing authority. Generate a fresh key for
admission after restart, and keep session keys out of persisted state,
backups, and restores.

Admitting a newer membership view clears the lease and its publication at
the same revision. The next acquisition advances the owner epoch across
that change, including when the manager retains its node ID.

The authority uses a dedicated three-replica JetStream stream with leader
reads and acknowledged compare-and-set. The stream can hold all regional
owner records and orders writes using both its watermark and the region's
latest sequence. An operation needs a current follower alongside the
leader, then a store acknowledgment and matching readback before its
deadline. Missing quorum, conflicting revisions, uncertainty and expiry
produce no successful result. Leases last at most 15 seconds. Trusted
authority processes require synchronized clocks.

The renewal candidate keeps the existing expiry and fences owner writes
until confirmation. The authority observes the candidate's quorum
acknowledgment and exact readback before the previous expiry. It then
persists that observation against the candidate's revision. A delayed
proposal can reach quorum after the caller times out, and the broker's
proposal timestamp can still predate expiry. Such a proposal remains a
candidate. The old session cannot publish or renew again. Recovery requires
a fresh authenticated admission at a higher owner epoch.

Recovery of the store requires continuity of the protected log. Before
opening writes after a restore, verify its membership and owner epoch floors
and revision against an authenticated checkpoint independent of the restored
snapshot. If continuity cannot be verified, establish newer fenced floors
from the trusted membership authority and retire earlier sessions before
admitting new owners.

Only the private authority connection can access this stream in the
journey. No ordinary ORCH, Fabric, application or workload OIDC grant
changes. A future readiness decision can record exact signed release,
generation and placement observations on the same protected order and
reject a completion CAS after an intervening owner or readiness change.
C65's five-second observed-readiness window remains a sampling bound.
HTTP failures may be unseen until a sample is committed. Brief changes
between samples may be missed.

The prototype establishes no installed lease handoff. Legacy updaters
still understand their existing lease and would continue scheduling. A
cutover has to fence every legacy owner before exposing a rollout
candidate, retain live JetStream quorum, and prove the GRU-first ordering
through the existing restart, probation, rollback and bake guards.
