# Pinned NATS Server source

This directory is the complete `github.com/nats-io/nats-server/v2` Go module at
`v2.15.0`, copied from the Go module cache. The upstream module checksum is
`h1:M99yf0y05rTr46/qc/Is6ZAowI58Ryp2SjufLCUeVJc=`. The canonical upstream
tag `v2.15.0` resolves to commit `eb763679aa3c24a40dcd3012aa046ad1996d851c`
(annotated tag object `4165d0d62508a8abe99feed39bb9e8ca4216aede`). The
upstream Apache-2.0 `LICENSE`, module files, and tests are retained.

The sole upstream source change is in `server/server.go`: when `DontListen` is
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
server behavior changes.

Compare this directory with the upstream `v2.15.0` Go module archive before
upgrading. Apart from this README, `server/server.go` must be the only differing
file. An upgrade must pass the route-start, absent-client-listener, bounded
shutdown, R3 formation, and real JWT bridge caller regressions before replacing
this pinned copy.
