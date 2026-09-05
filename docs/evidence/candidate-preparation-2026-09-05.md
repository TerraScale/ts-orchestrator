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
authority while that grant is live. Expired preparation recovery must affect
only the candidate. The command and signature tests cover strict input,
signature domain separation, exact identity bindings, conflicting admission,
deadline boundaries, cancellation, and public evidence loss or change.

The privileged host regression uses a fresh mount namespace and a tmpfs at
`/var/lib`; it does not alter the host's actual admission directory:

```sh
go test -race -c ./src/orchestrator/hostagent -o /tmp/ts-candidate-host-race.test
sudo -n unshare -m --propagation private bash -c 'mount -t tmpfs tmpfs /var/lib && TS_INITIAL_R1_ISOLATED_TEST=1 /tmp/ts-candidate-host-race.test -test.run "^TestCandidatePreparation" -test.v -test.timeout 30s'
```

This evidence does not qualify source fencing, consistent capture, broker
synchronization, restoration, R3 promotion, or the final authority election.
No new Firecracker or OCI qualification result is claimed. The last real VM
run remains stopped at TerraBase's missing production configuration, and the
ordinary orchestrator production composition remains closed. See the
[preparation guide](../guides/control-candidate-preparation.md) for the artifact
delivery contract and [transition design](../contracts/control-snapshot-transition.md)
for the remaining storage protocol.
