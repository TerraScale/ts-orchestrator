# Migration and qualification status — 2026-09-26

**Status: IN PROGRESS; NOT PRODUCTION READY.**
**Acceptance completion: 0/16 gates verified (0%)**, as recorded in the
[shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md).
The fixed denominator is M0 exit plus D01–D15. At each named breakthrough,
report the fully verified count and percentage and list completed and remaining
gate names. A gate counts only when every child requirement has passing
evidence from its specified environment. This measures acceptance coverage,
not elapsed time or production readiness; GOAL requirements outside the 16
gates remain separate until complete.

## Current milestone summary — 2026-09-29 02:54 UTC

Root `GOAL.md` SHA-256
`99de61cbd4bd49a678d2d48b5cbc92297d93849746773229a80594ba7533d0a6`
remains the scope authority. The [current shared-goal ledger](evidence/shared-goal-acceptance-20260926.md)
and `/tmp/ts-alpha-acceptance-queue-20260928.md` keep the M0–M3 map and next
checks. **Formal acceptance remains 0/16.**

TerraBase main `d2017ca9668a650ec490dff3f79bd51b75bb6466` passed CI #1012/run
11696 Fast 138/0/2, release and publish ([qualification](/home/mariogk/Projects/TerraScale/.qualification/terrabase-ci1012-d2017ca/qualification.json)
SHA-256 `69ef5119a78ec1692d49f12447f66cdeb72ca09d8e42f135c05e779ef0e992e9`).
Go main `db0231f1f2ee85cda8c087c8f9cb384147a7662d` published active $200 preview
caps, but CI #696 failed test fixtures. Its seven-path test-only correction passed independent review and the repository-wide race run passed locally; corrected main and matching Forgejo CI qualification are pending. These source and CI results do not qualify OCI serving.

R3 A and boot are TERMINATED, and its late signed intent has no HEAD. Fresh R4
`ts-preview-gru-20260929-r4` is selected with StorageDomain prefix `r4-20260929`;
it needs signed authority and an image from corrected, CI-qualified current Go
main. No live controller or managed pair exists. M0 create-only passed, then two
`conmon` placement probes held and cleaned up exactly without guests. D10 Complete
implementation remains active. Current combined qualification and preview ceiling
is US$200/month; dated $100 admissions remain historical.

## Historical 2026-09-26 qualification observations

The source snapshot for this dated report was
`dafce2e44c4b8380e82ef79e535cfa32d57075c3`. Recorded milestones include
`c30b3c` (host unit, image builder, and harness), `28ef` (continuity), `45ac`
(CI fixture repair), `9496` (production fixture), `a20d2b29` (authority-startup
retry), `984b8405` (managed-volume source/report), and `e38e45a1` (descriptor
and placement-to-OCI metadata integration), `6ded2c12` (host-session recovery),
and `dafce2e4` (namespace checkpoint).

| Area | Latest evidence and what it establishes |
| --- | --- |
| Member-status process boundary | **PASS, one VM.** Dedicated run-03 booted one isolated guest (two vCPUs, 6 GiB RAM, no guest NIC) and passed `TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery` and the Rust `member_control_managed::managed_member_status_cross_language_process_boundary` test, including the nested `MEMBER_STATUS_GO_OK` and authenticated sender markers. Firecracker exited 0 and cleanup was clean. This used orchestrator `4c284550310f5629976251d157047bc0282eb7be` and TerraBase `12850214606652f036e9fde000695fe5743b374b`. It proves the cgroup accounting check and the authenticated Go-to-TerraBase member-status process boundary only, not client serving, replication, restart, or quorum behavior. |
| Managed-volume preparation | **PASS, one VM.** One test run with no skips mounted the retained volume. This used orchestrator `22ec45f9f9cc683852fd5519e4826cddfaa5c995` and TerraBase `12850214606652f036e9fde000695fe5743b374b`. The VM had no guest NIC; the run proves local volume preparation only, not member serving, a signed running report, or OCI ownership. |
| Two-member managed serving | **FAIL.** Both guests accepted host sessions, but run-03 timed out before a signed running report; offline inspection found no member claim or shard. It produced no serving, client write/read, or replication-ACK evidence. Teardown was clean. This qualification used orchestrator `22ec45f9` and TerraBase `12850214`, not the current published source snapshot. |
| Three-VM restart fixture | **FAIL before bootstrap.** Run-02 stopped at `ntp-synchronized`: the guest reported `NTPSynchronized=no` and packet count 0, so bootstrap/controller services failed by dependency. Its OCI audit recorded no requests, overflow, or unknown sources. Cleanup reported no errors and no OCI resources were created. This run used source `c4f56f050e7d916e18df5bc64df4547474c9cfcf` and an older artifact. The three-file namespace fix is now published in `dafce2e4`; a new VM build and rerun have not started. |
| CI and release gates | Runs 612 and 614 failed in the ordinary test gate. Run 612 hit NATS stream-not-found 404/10059 and host-session 503/10008. Run 614 had host-session and authority-startup 503/10008 failures, with no 10059 in that run. Run 615 on `984b8405` passed Python and ordinary `go test ./...`, then failed the race-test gate on host-session 503/10008. The host-session fix was later published; full final CI on the updated source is unverified, and the release-artifact stage did not run. |

The authority stream-visibility retry is published in `a20d2b29`, but run 614
still observed authority-startup 503/10008; a separate authority-fixture
transient-read correction remains pending. The descriptor and placement-to-OCI
metadata integration is published in `e38e45a1`, independently reviewed, and
passed clean-package, real-caller clock tests, and `go build ./...`. It does not
complete first-boot enrollment: issuer/credential provisioning remains
outstanding.

The separate host-session 503/10008 recovery batch is published in `6ded2c12`.
Focused host tests passed, as did the real blackholed-session test (41.578 s)
and clean-kill test (22.735 s) on `984b8405` plus the exact patch. Full final CI
on the updated source is not yet verified.

The only measured latency baseline is the existing
[deployment-convergence measurement](benchmarks/deployment-convergence-20260925.md):
5 warmups and 30 measured samples yielded p50 **392.267510 ms**, p95
**405.332181 ms**, and max **418.143554 ms**. It measured signed operator call
through NATS to an in-memory runner on one controller and host; it did not start
an OS process or VM and included no database, C# comparison, or capacity test.

The automatic enrollment engine is **not implemented**; there is no
`internal/hostenroll` package. Issuer/credential provisioning and first-boot
wiring remain outstanding.

Remaining qualification includes a passing signed TerraBase serving report,
real write/read and peer-ACK evidence, durable drain and quorum behavior,
enrollment/first-boot integration, building and rerunning the three-VM
fixture after the namespace fix, complete CI/release gates, and final
high-availability and multi-region qualification. At this dated checkpoint, OCI work was plan/simulator-only and created no cloud
resources. Its pause and CI status do not describe the current milestone
summary above.
