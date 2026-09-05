# Initial inventory capture verification

The promotion integration test now uses the production
`NATSJetStreamSnapshotter` for every stream in both initial control accounts.
Its old direct snapshot helper is removed. A test-only decoder reads the stored
envelope and passes the exact inner archive and API metadata to public NATS
restore. No production restore API or transition capability was added.

The initial inventory contains 11 GRU streams, 10 empty, and four global
streams, all empty. The test captures those inventories before fixture writes,
then captures all 15 populated streams and restores them into the fresh
GRU/SFO/FRA cluster. Existing checks still cover exact stream/consumer R3
membership, GRU outage reads, full retained-directory restart, three consumer
resumptions, and the unchanged stopped source directory.

The focused normal and race runs passed. The first full portable run failed
`TestControlConsumerPromotionWaitsForStreamReplicasBeforeConsumerEffect` while
resuming promotion; the initial-inventory integration test passed. The failed
fixture allowed ten seconds for sequential stream and consumer convergence.
Pinned NATS uses four-to-nine-second elections and a two-second consumer-leader
lookup. The fixture budget is being aligned with the existing 25-second
promotion test, with fresh replica diagnostics and strict checkpoints retained.
These timer bounds do not prove the precise cause of the failed run. A repeated
ten-second fixture reproduced an unanswered promoted-consumer info request
consuming the operation deadline. Fresh bounded diagnostic queries then showed
exact healthy R3 and preserved creation, delivered and acknowledged state.
Promoted-consumer readiness now uses one-second read attempts within the
unchanged operation deadline. Only an attempt deadline with a live parent
context permits retry; each retry first rechecks the lease. Stream/consumer
mutation requests are not replayed. A deterministic lost-read regression
recovers with exactly one consumer update. Replacing the real lease after the
lost read prevents any subsequent readiness observation. Three focused runs
passed. Removing the bounded-read change via overlay consumes the entire
25-second test budget and fails while fresh queries still show healthy R3 and
intact checkpoints. Raising the fixture deadline alone does not fix that case.
After the fix in `6e35b0f4`, the following checks passed:

```sh
GOMAXPROCS=4 GOFLAGS=-p=2 make check
GOMAXPROCS=4 GOFLAGS=-p=2 go test -race -tags sandboxvm ./...
GOOS=linux GOARCH=arm64 GOMAXPROCS=4 GOFLAGS=-p=2 go build ./...
```

The tagged command permits Go's successful package cache. Verification began
with the changes in the shared working tree; another session committed them
while checks were running. The earlier failures remain part of this record.
This is an integration test with controlled writers and an in-memory immutable
object-store fixture. It does not establish a production writer fence,
consistent multi-account final cut, OCI availability, transition admission,
or six-guest readiness. The characterized consumer creation-metadata limitation
remains unchanged.

The TerraBase startup blocker was rechecked against clean source revision
`fbaecb93b5613e0011fe03973f71af14ad4cc4ae`. Its production startup still rejects
missing durable orchestrator membership. The guest launch lacks the required
database, key-version, RF2 placement, member and peer-TLS inputs. The host agent
already supports immutable configuration and `--config @config`; inventing
those identities would not fix production composition. No new Firecracker run
was performed in this verification; the real transition remains unqualified.

Forgejo run 102 for `d76e379b5af5e49eb203fbf6f28355779610ff59` failed after nine
seconds. The task status was read through `fj actions tasks`; job logs were not
available through the installed CLI or exposed REST routes. Separately,
`fj release list --repo TerraScale/ts-deploy` returned no releases and
`fj release view latest --repo TerraScale/ts-deploy` failed because the release
was absent. The workflow requires that release lookup. This confirms a missing
CI prerequisite, but does not identify the actual failing step of run 102.
