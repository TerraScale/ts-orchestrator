# F1 immutable evidence packet

Final candidate: 61aa29d6b4226953308819a62bc5eb341c53b69d.
Tree: d96ac15185a481ee057543347fc1cfc7c98b59f5.
Sole parent: 18b3ac46a269480ee74273259031c8dd47fb02ca.
Original base: cbfa626ac257e2c404e3581da1735f8494fabc64.
Worktree: /tmp/ts-qa-attempt-status-current-nodes (clean).

Final result: PASS, four requested integration leaves, one granted corrected invocation. Wall5.514s / package0.273s. Source and modules unchanged before/after. Final selector: ^TestPhaseStatusThroughSignedOCISDK$.

## Evidence order

1. 01-original-source-handoff: initial narrow production correction and connected real OCI SDK HTTP scenario, exact patch and initial source hashes. Its source-only validation status predates both runner grants.
2. 02-historical-build-failure: initial grant on 18b3ac46 failed compilation after81.419s because common.ServiceError did not satisfy error; zero test leaves ran. No concealed retry occurred.
3. 03-interface-correction: separate source-only grant changed only the generic target to an interface embedding error and common.ServiceError. Exact replacement proof, sole-parent proof, correction.patch and complete base-to-final candidate.patch are included. Every other test byte and the production correction were preserved.
4. 04-corrected-pass: separately granted single invocation on61aa29d6, exact argv, raw JSON, test leaf events/outcomes, session/tool IDs, identical before/after source/module/commit/tree/status hashes and terminal receipt.
5. source: final changed source and module snapshots. commit-parent-tree.txt records both candidate commits and their exact parent/tree chain.

Each evidence component retains its verified checksum manifest. Top SHA256SUMS covers every nested artifact and manifest. Packet files and directories are made read-only after verification. The sibling tar.gz has a detached SHA256 checksum.

## Verified behavior and limits

Actual Attempt.Phase("status") reaches PhaseStatus and production sdkCloud through actual OCI Go SDK Compute/ObjectStorage HTTP clients pinned to localhost with existing PinHost. Temporary real config/plan files and freshly generated local RSA credentials are used; every GET signature verifies. SFO/GRU current and retained names, foreign/data/terminated/malformed current exclusions, unchanged arbitrary legacy-prefix behavior, both compartment page chains, all bootstrap object prefixes and wrapped second-page service errors in each compartment are asserted.

No full-suite, race, live OCI, scheduler, deployment or performance claim is made. No production seam/configuration, naming migration, source delete, push or source mutation during either runtime grant occurred.
