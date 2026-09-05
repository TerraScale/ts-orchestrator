# Candidate admission path isolation

Candidate preparation now rejects overlapping store, owner-grant, and owner-key
paths even when preliminary synchronization is disabled. Manifest admission
also requires a canonical data-volume path and refuses owner material anywhere
inside that service-writable volume, including siblings of the candidate store.

Previously the optional synchronization validation checked its own paths against
the preparation material, but preparation alone did not enforce these storage
boundaries. A protected file's mode does not protect its directory entry when
the service can write the containing directory. The checks now run through
`transitiongrant.ComponentConfig`, which the host agent uses before preparing
the candidate launch.

Regression tests reject equal paths, containment in either direction, grant/key
containment, and owner material under the broader data volume. A positive case
accepts a separate directory whose name shares the volume's string prefix.
Existing runtime ownership and filesystem checks remain necessary; lexical
configuration checks alone do not establish filesystem identity.

Focused race tests passed for `transitiongrant`, `nodeauthority`,
`hostbootstrap`, and `candidatesync`. The privileged host fixture also passed
both candidate tests, including real admission and recovery after expiration
of the original bootstrap grant:

```sh
go test -race -c ./src/orchestrator/hostagent -o /tmp/ts-candidate-path-host.test
sudo -n unshare -m --propagation private bash -c 'mount -t tmpfs tmpfs /var/lib && mkdir /var/lib/candidate-tests && TMPDIR=/var/lib/candidate-tests TS_INITIAL_R1_ISOLATED_TEST=1 /tmp/ts-candidate-path-host.test -test.run "^TestCandidatePreparation" -test.v -test.timeout 30s'
```

The fixture output is retained in `candidate-admission-host-2026-09-05.txt`.
`make check` passed formatting, vet, build, and the full portable race suite;
output is retained in `candidate-admission-portable-2026-09-05.txt`.
This change does not add the finite storage-transition grant or recovery after
source retirement. Those requirements remain open.
