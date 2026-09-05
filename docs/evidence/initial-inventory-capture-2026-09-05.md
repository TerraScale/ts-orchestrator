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

The focused normal and race runs passed. Full portable verification is pending.
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
was performed for this test-only capture change.

Forgejo run 102 for `d76e379b5af5e49eb203fbf6f28355779610ff59` failed after nine
seconds. The task status was read through `fj actions tasks`; job logs were not
available through the installed CLI or exposed REST routes. Separately,
`fj release list --repo TerraScale/ts-deploy` returned no releases and
`fj release view latest --repo TerraScale/ts-deploy` failed because the release
was absent. The workflow requires that release lookup. This confirms a missing
CI prerequisite, but does not identify the actual failing step of run 102.
