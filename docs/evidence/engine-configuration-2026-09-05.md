# Engine configuration and consumer election verification

Implementation commits `c4850605` and `d2325e70` add the explicit TerraBase VM
declaration, bind it to the signed GRU bootstrap manifest, and provision member
TLS material as protected NoCloud root files. The
[configuration guide](../guides/terrabase-vm-configuration.md) specifies the
input, installed result, and remaining qualification limits.

Verification used Go 1.27.1 on linux/amd64 with the Modern Go Guidelines CLI.
The following passed:

```sh
make check
go test -tags sandboxvm -race ./src/orchestrator/vmengineconfig ./src/orchestrator/vmimage ./src/orchestrator/vmqual ./src/orchestrator/vmqualruntime
go test -race -count=3 ./src/orchestrator/bootstrap -run 'TestControlConsumerPromotion(PreservesDurableCheckpointAfterSourceLoss|WaitsForStreamReplicasBeforeConsumerEffect)$'
```

Retained output:

- [Complete portable gate](engine-configuration-portable-2026-09-05.txt)
- [Sandbox-tagged configuration and image tests](engine-configuration-tagged-2026-09-05.txt)
- [Repeated consumer election regressions](consumer-election-checkpoint-2026-09-05.txt)

The tests reject changed artifacts and releases, missing or duplicate identities,
wrong-host TLS material, missing database/key inputs, placement outside the
explicit database Region list, duplicate Region entries, invalid bounds,
unrepresentable TOML integers, excessive output, ambiguous JSON, and publicly
readable private keys. Reordering declaration hosts preserves the generated
configuration and immutable launch version.

The signed-bootstrap test uses all six assigned hosts and verifies the five-peer
configuration carried by each GRU host's verified owner grant. The NoCloud test
verifies the dedicated TerraBase file owner, mode 0400, absence of TLS contents
from user data, wrong-address refusal, and signed-configuration tampering refusal.
These are host preparation tests, not evidence of serving engine membership.

## NATS failure found by the full gate

One portable run failed
`TestControlConsumerPromotionPreservesDurableCheckpointAfterSourceLoss` with
`profile=true replicas=3 created=true checkpoint=false`. The subsequent
diagnostic showed a consumer group without a leader and with noncurrent peers.
The code had compared a provisional election checkpoint with the predecessor
before waiting for the admitted replica set to become current.

The production loop now checks profile and creation identity immediately, waits
under the original deadline and lease for the exact current replica set, then
requires nonregressing checkpoints before success. The real-broker regression
adds a controlled provisional zero-checkpoint observation. Another case supplies
a regressed checkpoint from an otherwise current group and requires refusal.
The lease-replacement case still refuses another observation after authority
changes, and the real source-loss test still proves pending-message delivery
without replaying the acknowledged prefix.

## Evidence limits

No new configured Firecracker run or engine parser execution was performed for
this declaration path. It requires explicit qualification database/placement
inputs and TLS material. The pinned parser marker is still a worktree source
hash, not a published contract or source-to-binary attestation. The engine's
durable membership source and SFO/FRA admission remain unfinished. The prior
[full VM attempt](vm-test-candidate-recovery-2026-09-05.json) failed at missing
TerraBase configuration and supplies no passing scenario result. Neither these
portable results nor the renderer close PR-03, PR-05, or production acceptance.
