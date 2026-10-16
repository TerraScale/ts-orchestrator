# Retained-volume deadline integration — 2026-10-16

The production placement-controller deadline scenario passed on clean source
`2ac7a4f3f35bac870d437552357678d72f598da0` in 0.149 seconds. Exact selector:
`TestVolumeDeadlineJetStreamControllerIntegration`; log:
`/tmp/ts-data-volume-deadline-2ac7a4f3.log`. QA granted the capacity lane; the
command used its lock, GOMAXPROCS=2, GOFLAGS=-p=2 and nice -n 19. No skips,
provider network requests, paid resources or TerraBase execution occurred.

## Real boundary and retained assertions

The scenario starts a real TCP NATS server with file-backed JetStream, commits a
placement intent through the real authority runtime and uses the production
placement store/controller. It opens an independent NATS client and store before
rechecking the persisted deadline. Fleet and host observations are controlled
test projections; cloud and workload mutations are counted and must remain zero.
This is controller/persistence evidence, not live OCI acceptance.

| Removed direct test | Retained production-boundary assertion |
| --- | --- |
| `TestCorruptOrFutureSinceExpiresImmediately` | The actual controller refuses an attachment timestamp two minutes ahead, accepts 30-second skew, and the durable store refuses a missing phase timestamp. |
| `TestDeadlineValidation` | Actual controller construction rejects negative, unbounded and excessive-retry policy; the controller honors a one-minute attach deadline. |
| `TestStablePhasesNeverExpire` | A late ATTACHED observation advances persisted state to the runtime-contract hold, clears the attach timestamp, preserves the host attempt and does not become stuck after 1000 hours. |
| `TestRemediationPerStalledPhase` | The actual ATTACHING consumer reports force-detach-retry at its deadline while performing no cloud/workload mutation. Other direct-test phases have no production consumer; their conservative remediation implementation is unchanged. |

The 9-, 10- and 11-minute observations also prove that repeated observation and
opening another client do not rewrite phase start or member revision. A late
positive observation records progress instead of resetting a stalled wait.

## Unused transition API removal

Source search found no production or remaining test callers of `Apply`, `New`,
`Event*`, `FromOCIAttachmentState`, `Phase.Valid`, `ErrInvalidTransition`,
`ErrTerminal` or `HeldFrom`. The unused graph and its ten direct transition tests
were removed, including the attach-retry review file. These APIs never supplied
the production controller's authority or effects; production uses only
`Check`/`Remediate` and their deadlines. Their source/history remains in git.

No active fencing, first-format, retained-mount, drain, writer-stop or OCI mutation
guard was removed. Actual host ext4 format/growth and kernel retained-mount
qualification are separate scenarios. Runtime spec tests still need conversion
through the real containerd boundary and have not been deleted.
