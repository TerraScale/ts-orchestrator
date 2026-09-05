# Snapshot envelope verification

The snapshot and connection changes are in `485367bc`, following the base
envelope in `cff061eb`. These are development checks, not production or
Firecracker qualification.

`GOMAXPROCS=4 GOFLAGS=-p=2 make check` passed. A linux/arm64 cross-build with
`GOOS=linux GOARCH=arm64 GOMAXPROCS=4 GOFLAGS=-p=2 go build ./...` also passed.
The checks began with the changes in the shared working tree; another session
committed that tree while verification was running.

Snapshot race tests exercise public restoration of fresh and purged empty
streams, sequence allocation, consumer checkpoints, body readback failure,
missing archive files, truncation, duplicate entries and nested JSON fields.
A configuration integer above the exact float64 range survives the envelope
unchanged. These fixtures do not prove arbitrary archive/state equivalence or
a complete consistent capture across both control accounts.

The first portable run failed
`TestConcreteConnectionDeadlineClosesStalledHandshake` with a raw socket
timeout. The socket deadline can precede the context timer's error update.
The connection now checks the absolute deadline while preserving cancellation
precedence. Both connection packages passed five race runs and the stalled
handshake test passed twenty repetitions after the fix.

The tagged suite has not passed this verification attempt. Its first run
failed `TestControlConsumerPromotionPreservesDurableCheckpointAfterSourceLoss`
at the replica update with `context deadline exceeded` after 28.56 seconds.
Five focused tagged race repetitions then passed. A sequential full rerun with
`GOMAXPROCS=4 GOFLAGS=-p=2 go test -race -tags sandboxvm ./...` failed the same
update with `bootstrap: verified control runtime is unavailable` after 3.55
seconds. Twenty focused diagnostic repetitions subsequently reproduced three
promotion timeouts. No timeout was increased.

Pinned NATS v2.14.6 responds to singleton stream promotion before actual
leadership converges, as described in `server/jetstream_cluster.go` around
lines 5344–5368. Consumer promotion uses the assigned stream peers and proceeds
even when its current-leader lookup fails. Source inspection therefore supports
waiting for the exact healthy stream assignment before consumer promotion.
It does not establish the root cause of every observed failure. Diagnostic
errors now distinguish consumer preflight, promotion and state validation
without relaxing the accepted profile or checkpoint invariants.

The full Firecracker suite was not rerun for this snapshot slice. The
[previous guest attempt](vm-test-command-binding-2026-09-05.txt) remains failed
at TerraBase startup with missing configuration. Runtime composition, the
fenced R1-to-R3 transition, complete control-state capture and the remaining
production gates stay open.
