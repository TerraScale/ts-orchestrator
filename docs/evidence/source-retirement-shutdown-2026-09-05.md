# Source retirement shutdown regression

The real initial-control runtime retirement test now keeps privileged NATS
clients from both the regional and global accounts connected across retirement.
Both clients successfully read account information before the existing host
receiver retires admission using the runtime's actual regional lease.

After runtime completion, the test verifies that those clients and the regional
runtime client cannot flush traffic, the TCP listener refuses connections, and
the original admission cannot restart the runtime. It hashes every retained
store file immediately after completion and again after the rejected requests,
rejected restart, and a 150 ms observation interval. The file inventory and
contents must match and must be nonempty.

Validation passed ten consecutive race-enabled runs with real embedded NATS,
root-owned admission, and private mount and network namespaces:

```sh
go test -race -c -o /tmp/ts-retirement-runtime.test ./src/orchestrator/initialcontrol
sudo -n unshare -mn --propagation private env TS_INITIALCONTROL_TEST_NAMESPACE=1 /tmp/ts-retirement-runtime.test -test.run '^TestInitialRuntimeBlankDiskRetryAndRetirement$' -test.v -test.count=10 -test.timeout 120s
```

This is regression evidence for supervised shutdown. It does not implement or
prove a durable seal, an atomic final cut, crash recovery, credential revocation
on a destination cluster, or the complete R1-to-R3 transition. The production
runtime behavior is unchanged. Ordinary unprivileged tests skip this fixture;
the explicit isolated invocation above executed it.

`make check` also passed formatting, vet, build, and the complete portable race
test suite. Its output is retained in
`source-retirement-portable-2026-09-05.txt` alongside this note.
