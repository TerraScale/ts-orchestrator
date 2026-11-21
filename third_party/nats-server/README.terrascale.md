# Pinned NATS Server source

This directory is the complete `github.com/nats-io/nats-server/v2` Go module at
`v2.15.0`, copied from the Go module cache. The upstream module checksum is
`h1:M99yf0y05rTr46/qc/Is6ZAowI58Ryp2SjufLCUeVJc=`. The canonical upstream
tag `v2.15.0` resolves to commit `eb763679aa3c24a40dcd3012aa046ad1996d851c`
(annotated tag object `4165d0d62508a8abe99feed39bb9e8ca4216aede`). The
upstream Apache-2.0 `LICENSE` and module files are retained. Under TerraScale's
test policy, upstream test files were deleted on 2026-11-04, the TerraScale
regression test on 2026-11-10 and the test-only packages `test/` and
`internal/testhelper/` on 2026-11-11.

The first upstream source change is in `server/server.go`: when `DontListen` is
true, `Server.Start()` closes `clientListenReady` itself. In v2.15.0, route
startup waits on that channel, but the normal closer, `AcceptLoop`, is skipped
when the client listener is disabled. Without the change an embedded broker
cannot form an R3 route cluster and shutdown waits indefinitely. The fix does
not create a TCP client listener; TerraScale's closed-by-default mTLS bridge
remains the only external client path.

The second change, also in `server/server.go`, adds the exported
`Server.UpdateAccountClaimJWT`, a thin wrapper over the unexported
`updateAccountWithClaimJWT`. The embedded account resolver reports
`IsTrackingUpdate() == true`, which stops the server from applying
`$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE` requests (routed or client-sent)
without the resolver's interregion contract check; the resolver validates a
replacement in `Store` and then installs it through this wrapper. No other
server behavior changes in that wrapper.

`server/accounts.go` serializes account claim updates and captures trace labels
under the account lock. `server/leafnode.go` also holds the account read lock
when capturing a solicited leaf's label, preventing a race with claim refresh.

TS-776 preparation adds `raft_node_id` to client/route INFO and system server
advertisements in `server/server.go`, `server/route.go` and `server/events.go`.
It reports the actual current eight-character Raft ID. Receivers and Raft
identity calculation are unchanged in this preparation release, so it can
roll beside the previous binary. Every controller must deploy preparation
before a later release consumes explicit IDs and renames its server.

`server/server.go`, `server/client.go` and `server/auth.go` add immutable
creation-time account and exact user-JWT constraints for in-process client
connections. Every CONNECT must keep the required account; the exact-JWT API
also requires the original user claim before native JWT/nonce authentication.
The public bridge pins its cell account on every CONNECT. These constrained
connections always use native authentication.
Root's internal system handles retain the original InProcessConn API.

`server/stream.go` retains the account and streams parent directories when a
stream is deleted. Asynchronous empty-parent removal could race immediate
stream recreation's `MkdirAll`. Stream data deletion and account cleanup are
unchanged. The root-resource delete/recreate authority regression
passed 100 executions across five concurrent groups after this fix.

`server/jetstream_cluster.go` selects consumer peers from the stream's target
assignment during replica migration. An R1-to-R3 stream update publishes the R3
configuration while its serving peer set can still contain only the original
R1 peer. Consumer creation and scale-up use `targetPeers()`, including the desired
assignment, so a matching consumer replica count is not rejected against that
stale serving set. The function publication and R1-to-R3 consumer migration
integration passed five race-instrumented repeats after this change (76ae267d2).

`server/raft.go` exports `RaftNodes` (a copied slice of the existing public
`RaftNode` handles) and `TransferRaftLeaders` (the lame-duck handoff step).
For every elected Raft leader, including one whose initial entry has not yet
reached the upper layer, the handoff names a follower that has stored every
entry the leader stored (`li >= pindex`), was heard from within two heartbeats
and is not offline, excluding the local node. Under the Raft lock it sends that
follower the existing leader-transfer entry, marks the local group an observer
and steps down. The named follower receives the transfer in order and starts
its election at once. When no follower qualifies, the leader keeps leading and
stays electable, so `jetstream_cluster.go`'s observer step-down never hands the
metadata group to an arbitrary peer; callers call the handoff again until a
follower qualifies or their stop budget ends. Non-leaders become observers so
they cannot be elected. `StepDown` and its other callers are unchanged.
Embedders can check quorum and confirm successor leadership before closing
listeners. Raft messages, membership, persistence, and election timeouts are
unchanged; transfers work with unmodified v2.15.0 members in
either direction. Current-replica observations use the existing RAFTZ system
request, which is also available on unmodified members.

`server/opts.go` adds `JetStreamMetaBootSize`, and `server/jetstream_cluster.go`
uses it when the metadata group's log is empty. Upstream estimates the size of a
new metadata group from the number of configured route URLs, but the mesh dials
three seed URLs per peer region, most of which name hosts that do not exist on
a new fleet, so three founders expected six peers and never elected a leader. With
the option set, a server whose metadata log is empty expects that many peers and
starts its metadata node as an observer, so it never campaigns; the embedding
mesh ends observer mode once the node has seen a leader, or, on the one region
founder its Vault founder record names, once no reachable server has metadata
state. Unset, behavior is unchanged.

`server/jetstream_cluster.go` also starts JetStream clustering with no
configured route when the server has a named cluster listener and sets
`JetStreamMetaBootSize`. The mesh adds every cross-region route at runtime
with `Server.AddRoutes`, from the seed records peer regions publish in Vault,
so a region's first host may start before any peer region has published one:
the founder of a brand-new fleet, or a region whose peers' records are missing
or refused. Upstream refuses to start clustering without a configured route,
so that host had no JetStream and its joiners had no cluster listener to route
to. Its metadata node starts as an observer and joins a group once routes
arrive, unless it is the one founder the mesh's create-once founder record
names. A server without the option keeps upstream's check.

`server/raft.go` starts a Raft node's run loop at once when its cluster size is
1, instead of waiting for a first route, leaf or gateway connection. A group of
one needs no peer to elect itself, and the mesh's one founder of a brand-new
fleet may start before any other host exists, so upstream's wait left that
founder without a metadata leader until a second host came up. Groups of two or
more still wait for routing.

`server/route.go` no longer reuses a configured route's hostname as the TLS
server name of a route dialed to a bare IP (a gossiped route) when the cluster
TLS config sets `InsecureSkipVerify`. Upstream borrows that name only so
hostname verification of gossiped routes can pass; a config that skips
hostname verification does not need it. The mesh skips it and checks its CA in
`VerifyConnection`, where it also binds a seed hostname's region to the
region the peer certificate names, so a borrowed name would bind a gossiped
route to the region of whichever seed was configured first. Routes dialed by
hostname still send that hostname, and configs that verify hostnames keep
upstream's behavior.

`server/route.go` keeps a known server's JetStream configuration and usage
stats when a route connection to that same server ID registers again. Upstream
rebuilt the server's node entry without them, so after a route pool closed and
reconnected (route churn at cluster formation, or any route reset) the
metadata leader treated a live peer as never heard from until its next statsz,
up to ten seconds later, and refused R3 placement with "no suitable peers for
placement, peer offline". A new server ID still starts without stats. The
fabric lane's route-churn step creates R3 streams right after every route of a
member is re-registered.

`server/opts.go` adds `Cluster.SolicitImplicitRoute`, and `server/route.go`
consults it, with the gossiped route URL and pinned account, before dialing a
gossiped route. NATS forwards one advertised address per server to every peer,
so ts-orch's in-region hosts, which reach each other over the VCN through
configured routes, also learned each other's NetBird address from other
regions and dialed it, and whichever connection filled a pool slot first won.
The mesh declines a gossiped route to a server of its own region and records
it. `Server.ConnectImplicitRoute` dials a recorded route exactly as gossip
would have; the mesh uses it only while no current manager of the region has
published membership for three rounds, so a region whose managers predate
this change keeps upstream discovery. The check only declines to dial; it
never closes or replaces an established route. Unset, behavior is unchanged.

`server/route.go` also adds `Server.AddRoutes`, which appends routes to the
configured list and solicits them (with the pinned accounts) the way a config
reload's added routes are, without touching any existing route or connection,
and `Server.RetainRoutes`, which drops configured routes the embedder no longer
wants so the server stops soliciting them; it closes no connection, and a
dropped route is not reconnected once its connection ends. The mesh configures
a VCN route to every member of its region's cluster and retires only the
routes of hosts that left the cluster or were replaced, so every pooled and
pinned-account route to a current member re-forms after any reset.

Compare this directory with the upstream `v2.15.0` Go module archive before
upgrading. Apart from this README,
`server/server.go`, `server/accounts.go`, `server/leafnode.go`,
`server/route.go`, `server/events.go`, `server/client.go`, `server/auth.go`, `server/stream.go`,
`server/raft.go`, `server/opts.go` and `server/jetstream_cluster.go`
are the changed upstream files. An upgrade re-applies each change above and
updates the source digest that `scripts/ci/audit-replacements.py` pins for this
directory.
