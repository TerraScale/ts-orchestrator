# First candidate preparation admission

The producer now emits separately signed SFO/FRA initial bootstrap grants and
one owner-signed preparation grant. The CLI dispatches directly to
`candidateplan.Run`. The grant binds the existing GRU source proof and the
exact candidate manifest/bootstrap hashes. Separate bootstrap and preparation
deadlines allow a pinned preparation to survive initial bootstrap expiry.

The existing local host bootstrap verifies the same owner across both grants,
pins preparation under the host epoch-store lock, and publishes fixed
root-owned evidence for the unprivileged preparer. The preparer prints an
admission receipt, polls that evidence, and exits on expiry or invalidation.
It opens no broker and starts no authority workers.

Review corrections reject a different current release and a same-version
ordinary launch, recover interrupted activation through an exact candidate
journal entry, and reject runtime epoch admission when public preparation
evidence has lost its private pin. Successful runtime epoch admission removes
and syncs the publication before persisting the floor.

Other components retain their independently signed initial-bootstrap
authority while that grant is live. Both local recovery and normal NATS
receiver startup restrict expired preparation to the candidate. The latter
preserves the full manifest digest for status and later manifest comparison,
but bypasses ordinary saved drain/release effects. Live bootstrap effects
retain both issuance checks and their original deadline.
The command and signature tests cover strict input,
signature domain separation, exact identity bindings, conflicting admission,
deadline boundaries, cancellation, and public evidence loss or change.

The privileged host regression uses a fresh mount namespace and a tmpfs at
`/var/lib`; it does not alter the host's actual admission directory:

```sh
go test -race -c ./src/orchestrator/hostagent -o /tmp/ts-candidate-host-race.test
sudo -n unshare -m --propagation private bash -c 'mount -t tmpfs tmpfs /var/lib && mkdir /var/lib/candidate-tests && TMPDIR=/var/lib/candidate-tests TS_INITIAL_R1_ISOLATED_TEST=1 /tmp/ts-candidate-host-race.test -test.run "^TestCandidatePreparation" -test.v -test.timeout 30s'
```

The first portable run failed the existing snapshot recovery test during
full-cluster restart, with no NATS metadata leader before the deadline. An
unchanged five-run reproduction on the normal temporary filesystem passed
four times and failed once. A directory creation probe there took 23.833
seconds; the same probe on tmpfs took 0.000139 seconds. Three unchanged
snapshot recovery runs on tmpfs all passed, taking 15.74, 15.48, and 15.92
seconds. No snapshot assertion or timeout was changed.

The same portable run exposed a separate KV qualification fixture race:
persisting replacement input files while the refresh ticker ran allowed extra
unchanged refreshes during slow writes. Qualification must select a complete
prepared revision before notifying the provider loop. The corrected fixture
persists both revisions before starting the ticker and pins matching health
and placement input during each pass. Its new regression and the complete
local scenario journey passed together under race detection in 52.092 seconds.
Cadence, deadline, write-count, and ordering assertions remain unchanged.

The final portable run uses the ordinary user and unchanged `make check` in
an isolated mount namespace with an executable tmpfs at `/tmp`. The host's
actual `/tmp` is unchanged. This separates temporary-filesystem stalls from
the code gate; it does not qualify the host's physical storage latency.

`GOMAXPROCS=4 GOFLAGS=-p=2 make check` passed on the final implementation.
The snapshot package took 18.056 seconds and the complete VM qualification
scenario package took 25.561 seconds. Its log SHA256 is
`205f1a69dc45cdb72f03b5034a2175d6f805979eede762a9b6e66dd314e9d27e`.

This evidence does not qualify source fencing, consistent capture, broker
synchronization, restoration, R3 promotion, or the final authority election.
No new Firecracker or OCI qualification result is claimed. The last real VM
run remains stopped at TerraBase's missing production configuration, and the
ordinary orchestrator production composition remains closed. See the
[preparation guide](../guides/control-candidate-preparation.md) for the artifact
delivery contract and [transition design](../contracts/control-snapshot-transition.md)
for the remaining storage protocol.
