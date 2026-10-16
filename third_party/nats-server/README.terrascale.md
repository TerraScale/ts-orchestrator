# Pinned NATS Server source

This directory is the complete `github.com/nats-io/nats-server/v2` Go module at
`v2.15.0`, copied from the Go module cache. The upstream module checksum is
`h1:M99yf0y05rTr46/qc/Is6ZAowI58Ryp2SjufLCUeVJc=`. The canonical upstream
tag `v2.15.0` resolves to commit `eb763679aa3c24a40dcd3012aa046ad1996d851c`
(annotated tag object `4165d0d62508a8abe99feed39bb9e8ca4216aede`). The
upstream Apache-2.0 `LICENSE` and module files are retained. Test changes are
recorded below.

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

Compare this directory with the upstream `v2.15.0` Go module archive before
upgrading. The production differences are limited to
`server/server.go`, `server/accounts.go`, `server/leafnode.go`,
`server/route.go` and `server/events.go` are the changed upstream files. An upgrade must pass the route-start, absent-client-listener, bounded
shutdown, R3 formation, and real JWT bridge caller regressions before replacing
this pinned copy.


## Test migration provenance

The migration inventory contains 1,449 original unit or mixed test declarations
(1,215 unit and 234 mixed); integration declarations, benchmarks, fuzz targets
and shared fixtures remain outside that removal target. A replacement must
exercise production transport or durable-storage boundaries and preserve the
original safety contract before its original declaration can be removed.
Passing a related test alone does not establish equivalence for private buffer,
allocation, decoder rejection or synchronization assertions.

The first qualified source removals are limited to these eight declarations:

| File | Original declarations | Replacement |
| --- | --- | --- |
| `server/nkey_test.go` | `TestServerInfoNonceAlwaysEnabled`, `TestServerInfoNonce`, `TestNkeyClientConnect`, `TestMixedClientConnect`, `TestMixedClientConfig` | Corresponding `TCP` tests through real server listeners, signed nonce authentication and message delivery. |
| `server/ring_test.go` | `TestRBAppendAndLenAndTotal`, `TestRBclosedClients` | `TestClosedConnectionRingOverHTTP`: 100 real connections and HTTP monitoring verify cumulative totals, bounded retention, identifiers, names and order. |
| `server/filestore_test.go` | `TestFileStoreConvertToEncryptedDoesNotResurrectXoredCache` | `TestFileStoreEncryptedConversionRecoversMessagesAndAppends`: original stale-cache/used-keystream fault, AES and ChaCha ciphertext, exact message recovery, append and reopen. |

All original and replacement declarations above passed together in test-only
union `3a9f09da5862d7d56bfe2826d3a00bf10ed44b5a` using Go 1.27.1,
`GOMAXPROCS=2`, `GOFLAGS=-p=2`, `go test ./server -count=1 -timeout=120s`.
The source removals are `b71db3cd07101707d75bbd9e9a7bb8abcf426660`
(NKey), `1f42963beb39d2ea2ea6bd59a484e38227c6d1b7` (ring) and
`ae39dcd68be2af2337a1e14dda6785cf0d130cfb` (file store). The shared NKey
nonce helpers and all four NKey benchmarks remain unchanged. Only unused local
NKey setup helpers and the ring's unused formatting helper were removed.
Combined removal source `cb868ebc3e8fc4025bc06b33b71214f5a54540f2`
compiled successfully; nine additional selected boundary tests passed in 1.428
seconds with no skips. Central integration qualification remains pending.

`TestMain` moved without changing its body from `server/sublist_test.go` to
`server/integration_bootstrap_test.go`.

Auth source `319b113a07dd1a25880a717f0c83d7a2fcdb51b3` separately removes
`TestUserUnknownAllowedConnectionType`, `TestDNSAltNameMatching` and the three
`TestProcessUserPermissionsTemplate*` originals. The corresponding real listener
type, 36-row TLS DNS and signed scoped-template cases passed; both original
DNS/type cases also passed in `cb868ebc`, and the original three template cases
passed in `3a9f09da`. All other retained function bodies are unchanged. These five
additional removals await compilation in their combined final source. All five
clone originals, the concurrent proxy original and twelve existing auth
integrations remain. The strengthened directional clone replacement is unrun.

Every original outside these thirteen approved removals remains while additive
candidates are qualified. This migration is incomplete; these source removals
do not qualify the remaining inventory.

The deterministic real-TCP regression
`TestJWTSystemAccountRefreshKeepsInflightReplyOverTCP` currently fails after a
signed metadata-only account refresh, although its no-refresh control delivers
the reply. Refresh clears the pending imported-service response mapping. Its
failure is retained; no production account-refresh fix or expected-loss retry
is included in the test migration.
