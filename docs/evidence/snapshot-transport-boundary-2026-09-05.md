# Snapshot transport and source authorization

The existing snapshot client now checks the pinned NATS 2.14.6 transfer
protocol before publishing acknowledgements. It accepts only ordered full
1 MiB chunks with the expected stream, a stable server nonce, exact byte count
and canonical positive index. It permits one short final chunk without a
reply. A transfer with full chunks must finish with status 204; small transfers
use the server's empty-header completion. Failed or malformed completions are
not accepted as successful captures.

Tests cover changed reply subjects, streams and nonces, repeated or malformed
indices, invalid lengths, early termination, extra or duplicate headers,
incorrect completion status, and data after the short tail. An in-process
NATS regression verifies that a substituted reply subject receives no ACK.

`TestSnapshotterCrossesFlowWindowAndRestoresExactRecords` writes twenty
incompressible 512 KiB records and acknowledges two through a durable consumer.
It captures through the production snapshot adapter, requires the compressed
archive to exceed the server's 8 MiB flow-control window, restores it through
the public API into another broker, and compares records, headers, timestamps,
sequence allocation and consumer checkpoints. Retrying the immutable stored
snapshot returns the original identity. The focused race run passed in 10.926
seconds; malformed-terminal additions passed separately in 1.062 seconds.

Review of the server implementation changed the planned source transport.
`jsStreamSnapshotRequest` in `server/jetstream_api.go` checks only publish-subject
syntax for `deliver_subject`; `streamSnapshot` publishes archive data to that
subject internally. Source-account SNAPSHOT credentials must therefore not be
represented as a read-only capability based on client publish permissions.
The proposed snapshot-reader fields and credential generation from `1ec19d31`
were removed. No new source-account capability remains enabled.

The next implementation needs a source-owned worker with explicitly admitted
privileged credentials, typed transition requests, internally selected delivery
inboxes, immutable object publication and independent candidate receipts.
Candidates must not receive raw source-account snapshot access. Snapshot client
protocol checks do not implement that authorization boundary or establish a
consistent final cut. See [the transition contract](../contracts/control-snapshot-transition.md).

A separate package extraction moved startup diagnostics and their tests into
`guestdiagnostic`, leaving the VM adapter as a direct call. `vmqualruntime`
is now 9,943 Go lines including tests. Its ordinary and sandboxvm-tagged
focused race tests passed with unchanged errors, JSON, bounds and timing.

The full `GOMAXPROCS=4 GOFLAGS=-p=2 make check` passed on the implementation
recorded in `d04ccc7d`. Initial-control recovery took 18.608 seconds; the
complete restore-drill package, including the large snapshot, took 23.414
seconds. The run used the ordinary user in an isolated mount namespace with
an executable tmpfs at `/tmp`, as in the preceding candidate verification.
It changed neither the test target nor the host's real temporary filesystem.
Physical storage latency remains a separate qualification requirement.
Full-check log SHA256:
`0b99d9fde1db844a92e3cefd2536ab13c5c2df452611262cbe63ad6717f833ba`.

`GOMAXPROCS=4 GOFLAGS=-p=2 go test -race -tags sandboxvm ./...` passed in
the same isolated temporary-filesystem environment. Log SHA256:
`a46ccd9fd334228cbd56da8d86e77594da38a0d348917f95ef9a7b7b8ab3a9c0`.
`GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOMAXPROCS=4 GOFLAGS=-p=2 go build ./...`
passed as the ordinary user outside the namespace, with empty output. Only
this verification evidence changed after those gates.

The prerequisite audit also re-read clean TerraBase `e1059e23` and ts-deploy
`ae305798`. TerraBase still lacks a production durable-membership source and
the required lifecycle mutation/status RPCs. The published protobuf source
digests still match the orchestrator pins. ts-deploy's generated candidate
shape does not match its strict direct-delivery parser, and its direct HTTP
submission does not provide the orchestrator's signed NATS command envelope.
Release listing returned no entries for either repository. These remain
production integration requirements; no new real VM/provider result is claimed.
