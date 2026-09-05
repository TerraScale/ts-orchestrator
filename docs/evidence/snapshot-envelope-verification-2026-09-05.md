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

The initial tagged attempts failed. The first run
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

`eaa2acf8` adds the stream readiness barrier before consumer promotion,
including retries. It reuses the exact stream-assignment check and requires
all three admitted peers current, online and without lag, with live lease
checks during the wait and after readiness. The initial peer-stop regression
used an unreliable 250 ms observation window and was replaced. Its replacement
uses real NATS operations while withholding one replica's readiness in a
controlled stream-info wrapper. It checks that consumer mutation remains
blocked and resumes after releasing the observation. The controlled test
passed three repetitions; an overlay removing only the production barrier
failed all three repetitions at the consumer-effect-before-readiness assertion.
Further assertions preserve the real consumer's R1 configuration and checkpoint
while blocked, then verify R3 and original creation, delivered and acknowledged
positions after release. The checkpoint and readiness pair passed five
repetitions. The final controlled regression passed three repetitions, and the
negative overlay failed all three at the intended assertion.

After the production barrier, these checks passed:

```sh
GOMAXPROCS=4 GOFLAGS=-p=2 make check
GOMAXPROCS=4 GOFLAGS=-p=2 go test -race -tags sandboxvm ./...
GOOS=linux GOARCH=arm64 GOMAXPROCS=4 GOFLAGS=-p=2 go build ./...
```

The portable gate began before the last test-only refinement. The refined
test passed targeted race runs, formatting and package vet checks; the tagged
suite also passed. The tagged command allows Go's successful package cache.
These passing reruns establish the checked revision's results, not the precise
cause of every earlier intermittent failure. The production barrier adds a
required ordering check; it does not relax any creation or checkpoint rule.

The full Firecracker suite was not rerun for this snapshot slice. The
[previous guest attempt](vm-test-command-binding-2026-09-05.txt) remains failed
at TerraBase startup with missing configuration. Runtime composition, the
fenced R1-to-R3 transition, complete control-state capture and the remaining
production gates stay open.
