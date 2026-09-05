# Source-owned preliminary capture verification

Verified source revision: `9651d284a3a3ac15893883f8456c29d71ed417ba`.
This records source-local preliminary capture, not a completed control-plane
transition or production qualification.

## Implemented boundary

An explicitly owner-signed initial GRU seed configuration can admit a local
capture worker with separate privileged credentials for its two NATS accounts.
Participants receive no capture credentials. Existing signed configurations
retain their original privileges. The VM configuration has an explicit paired
byte-limit opt-in; enabling it does not manufacture a request or authority term.

`plan-preliminary-capture --config FILE` verifies the original owner-signed seed
grant and derives its source identity, store scope, profile and complete stream
inventory. It emits a signed public request bundle. The worker accepts only the
protected root-owned request file and verifies it against the owner key retained
by its initial admission. It constructs NATS inboxes internally.

Each attempt requires the matching live global term and is bounded by admission,
request expiry and a ten-minute operation limit. Initial retirement cannot
complete while the capture holds its admission lock. Runtime shutdown cancels
and joins capture before closing the broker. Capture refusal leaves an otherwise
healthy source runtime live. The actual initial CLI emits capture status changes.

Local staging uses exclusive process ownership, immutable request and artifact
publication, bounded bytes, descriptor-based file checks and durable readback.
Identical retries finish directory synchronization before reporting success.
Receipt reuse verifies the complete retained inventory and every artifact's size
and hash. The receipt has a separate signature domain and uses the source
membership identity pinned by the original grant.

One signed request pins one output directory. Replacement requests fail after
pinning. A restart that acquires a newer global term refuses the old request;
automatic request rotation and abandoned-output recovery are not implemented.

## Live-consumer snapshot correction

The admitted-runtime test exposed an actual failure on `KV_ORCH_RUNTIME`:
NATS 2.14.6 counts memory-backed watch consumers in snapshot API state but omits
them from file archives. Pinned `server/filestore.go` skips non-file consumer
stores in `streamSnapshot`, while `FastState` counts all consumers.

Envelope version 2 records bounded, sorted consumer identities from matching
names/info observations before and after capture. The original API state remains
unchanged. Only explicitly recorded ephemeral memory consumers may be absent;
memory-backed durable consumers refuse capture. Every file consumer still needs
its matching metadata, checksum and nonempty checkpoint file. Version 1 is
rejected rather than silently losing this obligation.

The public restore fixture now includes a durable file consumer and a live
ephemeral memory watcher. It restores the durable consumer's records and
checkpoint into an independent broker while the watcher is intentionally absent.
Structural archive validation alone does not prove arbitrary checkpoint
equivalence or an atomic multi-stream cut.

## Verification

All commands below exited successfully on the verified source tree:

- `make check`: formatting, vet, build and uncached repository-wide race tests.
- `go test -race -tags sandboxvm ./...`.
- `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...`.
- The complete `initialcontrol` race-test binary in private mount/network
  namespaces with root-owned admission and a tmpfs `/var/lib`.
- The complete `initialgrant` race-test binary with its explicit isolated-root
  publication test mode.

The ordinary and tagged suites ran as `mariogk`, with `GOMAXPROCS=4`,
`GOFLAGS=-p=2` and a private tmpfs `/tmp`, avoiding the previously measured host
temporary-filesystem stalls. The wrapper was:

```sh
sudo -n --preserve-env=PATH unshare -m --propagation private bash -c 'mount -t tmpfs -o mode=1777,size=8G tmpfs /tmp && exec runuser -u mariogk -- env PATH="$PATH" GOMAXPROCS=4 GOFLAGS=-p=2 make check'
```

For the tagged lane, replace `make check` with its command above. The complete
root runtime suite used a freshly compiled race binary:

```sh
go test -race -c ./src/orchestrator/initialcontrol -o /tmp/ts-preliminary-runtime.test
sudo -n --preserve-env=PATH unshare -mn --propagation private bash -c 'mount -t tmpfs -o mode=0755 tmpfs /var/lib && ip link set lo up && exec env TMPDIR=/var/lib TS_INITIALCONTROL_TEST_NAMESPACE=1 /tmp/ts-preliminary-runtime.test -test.v -test.timeout 180s'
```

An initial full-root invocation omitted loopback setup before the first ordinary
network test and failed with `network is unreachable`. The corrected wrapper
above passed the entire suite; no production assertion was relaxed.

The independent full-root run recorded:

| Test | Result |
| --- | --- |
| `TestInitialRuntimePreliminaryCaptureBothAccountsAndReplay` | Passed, 28.49 s: both accounts have archives exceeding 8 MiB; signed receipt, invalid-before-pin, immutable replay, substitution/expiry refusal, real newer-term restart refusal and subsequent retirement |
| `TestInitialRuntimePreliminaryCaptureCloseDuringTransfer` | Passed, 1.74 s: partial progress, cancellation and joined shutdown, no completion receipt |
| `TestInitialProfilesSnapshotRestoreR3Recovery` | Passed, 15.55 s; its existing consumer-creation-time divergence remains an explicitly observed limitation |

Store regressions cover process locking, quotas, request pinning, hostile files,
bounded orphan cleanup, corrupt/missing receipt artifacts and cancellation.
A real descriptor test permits rename but makes directory fsync fail: initial
publication and identical retries both refuse durable success until a
sync-capable descriptor is restored. Planner and grant tests cover wrong owner,
scope, dates, protected files, malformed input and credential isolation.

Retained local logs (SHA-256):

| Log under `/tmp` | SHA-256 |
| --- | --- |
| `ts-preliminary-capture-check.log` | `823077f45015dc3beebc1433a2aca2b9b847e3901254b05190fe8c7c1b8847f2` |
| `ts-preliminary-capture-sandboxvm.log` | `bef9def29818b5122df30c3d509a2cb4715e19595984e81ab50b6729e4363fa9` |
| `ts-preliminary-capture-root-all.log` | `287537c53db5dd99fa88cc05218e77ea4c46d560d8b533fdbd1d64824fdcc896` |
| `ts-preliminary-capture-grant-root.log` | `d36fc14b17a2306fb1bd32e3324967d357fc05559049bbad1dcc9f98c6c39361` |
| `ts-preliminary-capture-arm64.log` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Remaining qualification

There is no OCI upload, source-to-candidate transfer, candidate restore worker,
stopped-source final cut, R3 activation or post-transition snapshot in this
slice. In-flight global lease-loss injection is not established by the shutdown
test. Disk limits do not qualify peak snapshot memory use. No new Firecracker
production gate was run or claimed.

The read-only dependency refresh found TerraBase at
`dc2de437026b5c64d8b64f4a631015baa4a158b7`, with unrelated local edits. Its
production runtime still rejects missing durable membership at
`crates/terrabase-server/src/runtime.rs:215`, and the required TBEP lifecycle
mutation/status surface is absent. The engine/family protobuf pins remain
unchanged. ts-deploy was clean at
`ae305798c731a473d4ee2412d3ac37d5b82c2d7d`: its candidate producer still conflicts
with its strict delivery parser, and direct HTTP delivery does not implement the
orchestrator's signed NATS command-envelope ingress. Both configured
`fj release list --include-prerelease` calls returned no entries.

The ordinary production composition, complete transition, VM/provider gates,
soak/drill windows and owner sign-off remain open. See the
[transition contract](../contracts/control-snapshot-transition.md) and
[operator guide](../guides/control-preliminary-capture.md).
