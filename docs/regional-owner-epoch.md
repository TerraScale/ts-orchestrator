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
Admitting a newer membership view clears the lease and its publication at
the same revision. The next acquisition advances the owner epoch across
that change, including when the manager retains its node ID.

The authority uses a dedicated three-replica JetStream stream with leader
reads and acknowledged compare-and-set. The stream can hold all regional
owner records and orders writes using both its watermark and the region's
latest sequence. An operation needs a current follower alongside the
leader, then a store acknowledgment and matching readback before its
deadline. Missing quorum, conflicting revisions, uncertainty and expiry
produce no successful result. The stream records use a bounded lease
deadline of at most 15 seconds. The trusted authority and brokers require
synchronized clocks. A record stamped by the broker after its deadline
fails validation. A timed-out operation can still have reached the store,
so callers need a fresh protected revision before asserting ownership.
A newer signed membership view can clear an invalid record without
reusing epochs.

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
