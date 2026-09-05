# Single-metadata-member seed experiment

Pinned server: `github.com/nats-io/nats-server/v2 v2.14.6`.

A bounded local Go experiment started a clean embedded GRU server with cluster
name `CONTROL`, a system account, both control accounts, file-backed JetStream,
and an explicit route to its own route listener. The client listener became
ready. For the following 30 seconds, `Server.Jsz(nil).Meta` reported `Size:2`,
no leader, and no replicas. The required one-member metadata leader never
became ready. Stream creation and promotion were not attempted after that gate
failed.

This agrees with the pinned source: `server/jetstream_cluster.go:1046-1048`
bootstraps the metadata Raft node with `allPeersKnown=false`.
`server/raft.go:379-383` then forces the expected peer count to at least two.
A self route does not establish a second voting member.

A second bounded experiment added an ordinary routed GRU NATS server with
JetStream disabled and the same system-account identity. This was not a second
metadata or storage replica. The one-member metadata-leader gate again timed
out after 30 seconds. The mixed-cluster adjustment in
`server/jetstream_cluster.go:1954-1959` exists, but this experiment did not
establish a working topology using it. Its applicability remains unverified.
Neither experiment proves that every possible public configuration is
unsupported; neither supplies a working single-member clustered bootstrap.

The experiment used loopback plaintext authentication solely to isolate server
metadata behavior. It did not qualify production mTLS, authorization, host
admission, promotion, or restart behavior. No vendor code or retained metadata
was modified. The temporary test was removed from the production test suite
because repeating a known failed readiness gate adds no production coverage.

Local artifacts (not durable release evidence):

- `/tmp/ts-cluster-seed-experiment.log`, SHA-256 `f2292fc4d9edf92f4e0913119fa224256410efa02a854a992dcb4bf86cab38fa`
- `/tmp/ts-cluster-seed-mixed-experiment.log`, SHA-256 `603cff2b34d926aaa9d6f82c64e81630eb5cc6e1fbd435f49d2dcfc20c63ac3f`
- `/tmp/ts-cluster-seed-experiment_test.go` (second experiment source), SHA-256 `623080339bba6ee43888f58f2f1141de993ea0274b8e81abe80ef65191d6b30b`

Reproduction used `go test ./src/orchestrator/initialcontrol -run
'^TestClusterSeedExperiment$' -count=1 -v -timeout=120s` while the temporary test
was present. Both invocations failed at the single-member readiness gate.
