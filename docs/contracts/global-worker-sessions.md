# GRU global worker sessions

The GRU global runtime owns election. Each process retains its regional runtime
and signed regional delivery while following global leadership. The elected GRU
master alone constructs the estate publisher, rotation coordinator, reaper and
restore drill for one fixed global lease identity.

Static admission resolves declared endpoint and credential references, signing
trust, estate scope and required adapters before starting listeners. It neither
opens connections nor invents an epoch. After the embedded broker starts, the
root constructs regional delivery and the master-ingress inputs and starts the
regional and global runtimes. Only then can it construct a global worker session.
Missing production adapter contracts remain admission failures.

A session requires the exact authoritative global lease candidate, epoch and
lease ID, plus a new quorum-committed barrier in `KV_ORCH_LEADERS` on
`$KV.ORCH_LEADERS.security.rotation.barrier`. The barrier records the lease document
and lease revision and uses expected stream last sequence, so a concurrent lease
change rejects the commit. Success requires exact committed bytes, the broker's
sequence and a commit timestamp within the lease. Cached snapshots and same-value
reads are never positive ownership proof. The global connection must use mTLS,
NKey authentication, no reconnect and no reconnect publication buffer.

Renewal preserves the session only after another fresh proof for the same
candidate, epoch and lease ID. Failed proof, replacement, expiry, lost transport
or root cancellation permanently cancels that session. A separate lease-expiry
timer cancels work even while a renewal request is blocked. A new session may
start only after the prior worker group has stopped. An unjoinable group fails
the root; it cannot overlap a successor. Followers remain alive without global
workers. Worker failure while ownership remains valid is observable as root
failure, not silently retried. Construction that loses authority is canceled
and its returned resources are closed before any successor starts.

The root does not journal service completion: rotation, restore and reaper own
their durable intent and effect receipts. Session stop/start cannot reset those
records. Global state adapters are reconstructed with the actual new epoch.
An identical session renewal never restarts completed work. Startup succeeds
only after valid static admission, real transports and supervised components;
leader-worker readiness additionally requires fresh lease proof and successful
construction. No group can report ready solely because its factory returned nil.

A session checker can repeat the fixed-lease quorum barrier at adapter dispatch.
Cancellation and this check do not retract a remote request already sent. The
existing provider or engine contract must enforce ownership and idempotency at
its mutation boundary. The reaper now uses a globally fenced durable store;
actual database, key and mail adapters are still required before enabling it.
No new provider, TBEP, catalog or credential contract is defined here.

Prerequisite: lease CAS acknowledgements use stream-wide KV revisions. A valid
same-key CAS can jump over sibling journal/barrier writes; authority observation
must accept a greater revision while checking the exact proposed lease identity.

The root reuses `keyrotation.NATSStateStore.RefreshAuthority` for ownership proof
and `CheckEffectAuthority` at supported dispatch boundaries. These operations
write a new barrier without calling Load or changing the state-session cursor.
The supervisor owns a separate guard instance; each rotation coordinator owns
its own optimistic state instance. Both bind the same actual LeaseID.

Operational sessions require an R3 FileStorage authority stream with no TTL. A
temporary R1 bootstrap cannot activate these workers. The regional process and
master ingress keep their own lifetimes; infrastructure provisioning uses a
separate declared identity before any live worker construction.

Rotation, restore and reaper state configurations require the exact
`LeaseID` in addition to `CandidateID` and `AuthorityEpoch`. The root replaces
caller-provided journal configurations with stores bound to the proven session.
A dispatch checker belongs to that session: failure cancels it immediately and
no subsequent successful proof can reactivate it. Factory cancellation has a
bounded join; late resources are disposed and never adopted by a successor.

The provider factory transfers a mandatory `Close` receipt with every successful
bundle and with any partial allocation returned alongside an error. The root
cancels the constructor context before closing partial bundles. A successful
group owns the receipt until its services have stopped. Closing is idempotent;
cleanup errors remain fatal and cannot be classified as canceled execution.
The NATS session connection outlives the group and its provider client cleanup.
