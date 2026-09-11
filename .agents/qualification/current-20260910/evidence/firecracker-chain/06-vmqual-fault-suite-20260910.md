# Firecracker qualification harness verification (2026-09-10)

Source checked: `git rev-parse HEAD` = `97476cc3 CI actions and initial grant traversal updates`.
The worktree already contained unrelated qualification evidence changes; no source,
harness, or fixture files were changed by this verification.

## Commands and results

* `go test -race -count=1 ./src/orchestrator/vmqual ./src/orchestrator/vmqualsuite ./cmd/vm-qualify` — PASS.
  Exact package results: `vmqual` `ok` (26.543s), `vmqualsuite` `ok` (71.511s),
  `cmd/vm-qualify` `ok` (1.350s).
* `go test -count=1 -run 'Test(LocalScenarioJourneyUsesAllProviderEndpoints|RunSuiteCleansAfterCancellation|RunSuiteCleansAfterFailedScenarioAssertion|FaultContractsQualifyStateTransitions|FaultContractsRequireRealCapabilities|RecoveryFaultContractRejectsUnprovenOutcomes)' ./src/orchestrator/vmqualsuite` — PASS (`ok`, 22.591s).
  This exercises the six-guest baseline, GRU-first launch ordering, provider
  contracts, all required disk fault modes, recovery/certificate/shape/clock
  checks, cancellation cleanup, and false-positive rejection. The local journey
  additionally verifies the fourth-region expansion reaches eight create attempts.
* `make vm-doctor` — BLOCKED (exit 2), after all software/image checks passed.
  The host reports: `FAIL net-admin effective capability mask 0x0000000000000000`;
  `FAIL jailer-access effective uid 1000 is not host root`; and
  `FAIL cgroup-v2 cgroup v2 mount root /sys/fs/cgroup is not writable: permission denied`.
  Repairs printed by doctor: isolated job with `CAP_NET_ADMIN`, root jailer with
  required capabilities, and delegated writable cgroup-v2 subtree.
* `timeout 90s make vm-test` — BLOCKED by build timeout (exit 124):
  `vm-artifacts: build ts-node: signal: terminated`. No guest or provider result
  was inferred from this timeout.

## Boundary evidence

The current command declaration boundary remains explicit: `stack`/`test` reject
an absent TerraBase declaration before host work; configured TerraBase/run/control
paths are checked with `os.Lstat` and must be regular files. The real six-guest
Firecracker path cannot be qualified on this host until the doctor capabilities
are supplied. Existing prior live smoke logs in this directory show Firecracker
boot/cleanup succeeded but guest readiness stopped at NATS `no responders` with
`terrabase-configuration-missing`; those logs are historical runs and are not
claimed as current-source pass evidence.

## Coverage gaps / next action

No live six-guest `vm-test` or fault matrix was admitted because the host doctor
gate is not satisfied and the 90-second build timeout did not produce a runtime
result. Run `make vm-doctor`, then `make vm-test` with exact TerraBase/run/control
declarations on a narrowly privileged Linux/KVM runner. No harness defect was
reproduced, so no vmqual fixture repair is suggested.
