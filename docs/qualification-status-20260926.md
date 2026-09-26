# Migration and qualification status — 2026-09-26

**Status: PAUSED pending the next CI/tool-status update; NOT PRODUCTION READY.**
The coordinator's rough estimate is that migration and local qualification
are about 70% complete. That is a subjective progress estimate, not a
production-readiness score. The latest published source snapshot is
`dafce2e44c4b8380e82ef79e535cfa32d57075c3`. Recorded milestones include
`c30b3c` (host unit, image builder, and harness), `28ef` (continuity), `45ac`
(CI fixture repair), `9496` (production fixture), `a20d2b29` (authority-startup
retry), `984b8405` (managed-volume source/report), and `e38e45a1` (descriptor
and placement-to-OCI metadata integration), `6ded2c12` (host-session recovery),
and `dafce2e4` (namespace checkpoint).

| Area | Latest evidence and what it establishes |
| --- | --- |
| Managed-volume preparation | **PASS, one VM.** One test run with no skips mounted the retained volume. The [summary](../../.qualification/ts-orchestrator/20260926-managed-volume/run-03/summary.json) is SHA-256 `b0c3d7e3bf2a5f1ad57451c81e428fd72e18d197ec59b1afada2d04d6531ecf6`; its static Go test binary is `431ac464aab20186fa68711c65e236b87b4c7d66ed2735944a807b696c55a56e`. This used orchestrator `22ec45f9f9cc683852fd5519e4826cddfaa5c995` and TerraBase `12850214606652f036e9fde000695fe5743b374b`. The VM had no guest NIC; the run proves local volume preparation only, not member serving, a signed running report, or OCI ownership. |
| Two-member managed serving | **FAIL.** Both guests accepted host sessions, but run-03 timed out before a signed running report; offline inspection found no member claim or shard. It produced no serving, client write/read, or replication-ACK evidence. The [summary](../../.qualification/ts-orchestrator/20260926-managed-member-serving/run-03/summary.json) is SHA-256 `03a07ad18d082fb4a8e4da414a1b93c58c4cf7bfb5ea8454b5b88dac3b065a0b`; [cleanup record](../../.qualification/ts-orchestrator/20260926-managed-member-serving/run-03-cleanup-record.json) `394af082cbb5a5a9ad6e15533d4d9e7f0607f979ba058831fc2ab14c32636359` records clean teardown. This qualification used orchestrator `22ec45f9` and TerraBase `12850214`, not the current published source snapshot. |
| Three-VM restart fixture | **FAIL before bootstrap.** Run-02 stopped at `ntp-synchronized`: the guest reported `NTPSynchronized=no` and packet count 0, so bootstrap/controller services failed by dependency. The [report](../../.qualification/ts-orchestrator/20260926-production-restart/outputs/run-reviewed-run-02/driver-artifacts/report.json) is SHA-256 `de33ea855ba5037518fad9899751eae641400bdc41afed577a5bb3095a5289e1`; its [OCI audit](../../.qualification/ts-orchestrator/20260926-production-restart/outputs/run-reviewed-run-02/driver-artifacts/oci-audit.json) records no requests, overflow, or unknown sources. Cleanup reported no errors and no OCI resources were created. This run used source `c4f56f050e7d916e18df5bc64df4547474c9cfcf` and an older artifact. The three-file namespace fix is now published in `dafce2e4`; a new VM build and rerun have not started. |
| CI and release gates | Runs [612](../../.qualification/ts-orchestrator/ci-45ac459a/run-612-job-24137.log) and [614](../../.qualification/ts-orchestrator/ci-984b8405/run-614-job-24139.log) failed in the ordinary test gate. Run 612 hit NATS stream-not-found 404/10059 and host-session 503/10008; its log SHA-256 is `20cb4585fd890e3519292c06ebba94caafb6754f3071fb092cdec71f9891f07e`. Run 614 had host-session and authority-startup 503/10008 failures, with no 10059 in that run; its log SHA-256 is `360730adc9d515b45cfb30a81cbeaa9adb6973caebb7e742c5c45cbbaf8ba175`. Run [615](../../.qualification/ts-orchestrator/ci-984b8405/run-615-job-24140.log) on `984b8405` passed Python and ordinary `go test ./...`, then failed the race-test gate on host-session 503/10008. Its log SHA-256 is `7e30e3095373561e01f0978255bdca9c2e952fd560f05eac7a2e9d155bf9b832`. The host-session fix was later published; full final CI on the updated source is unverified, and the release-artifact stage did not run. |

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
high-availability and multi-region qualification. The OCI work remains
plan/simulator-only; no cloud resources were created. Qualification work is
paused pending the next CI/tool-status update.
