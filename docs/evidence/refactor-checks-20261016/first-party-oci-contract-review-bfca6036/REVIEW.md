# Bounded OCI contract review

Frozen HEAD: `bfca60368f60d2da67f9016d1d489317ae8749c8`
Frozen tree: `7b0b97136b7225c4897917bf600f76d5c069560f`

**One concrete defect:** reachable bootstrap status omits current SFO node names. The three reviewed contracts have source evidence for narrower boundaries; execution and integration-only closure remain unknown.

Scope: three primary contracts, their selected entry/caller/helper/owner sites and runner policy. Hash coverage: 39 source files / 66 selected declarations. Hashing a file does not mean every declaration was audited.

## Findings and smallest corrections

### F1 — P2: Bootstrap status omits current SFO controller names

An SFO attempt with a non-TERMINATED ts-sfo-1 instance returned by OCI ListInstances.

PhaseStatus constructs sfo-1 and filters strings.HasPrefix(displayName, "sfo-1-"); it emits no status row for ts-sfo-1.

**Reachability:** main -> cli.Run case oci-region -> runOCIRegion case attempt -> attempt.Run -> Attempt.Phase("status") -> Attempt.PhaseStatus.

**Production witness:** Checked-in SFO plan -> Engine.seedLaunch -> controllerName -> Cell.ControllerSlot -> ts-sfo-1 -> SeedLaunchDocument.displayName. This is a source-derived witness, not a live OCI observation or executed reproduction.

GRU remains intentionally different: `Cell.ControllerSlot` retains `gru-1-ctl-N`, whereas SFO uses `ts-sfo-N`. `Cell.Node`/`IsNode` support current node names and naming tests cover both formats. A naming migration inferred from comments alone is not the basis of this finding.

**Disposition:** Retained infrastructure observation correction; no evidence authorizes deleting this live CLI or retaining the entire mixed-purpose attempt package.

**Smallest correction:** Accept existing naming.IsNode(displayName, cellRegion) as well as the supported legacy cell prefix, keeping the existing TERMINATED exclusion. Preserve the intentional GRU ControllerSlot legacy mapping; do not rewrite generic task/scheduler phases.

**Meaningful regression scenario:** Drive PhaseStatus (or its retained CLI owner) with production sdkCloud backed by real OCI SDK clients talking HTTP to a local OCI protocol simulator. Return paginated current and legacy node rows; assert status output and page requests, current-data-name/foreign-region/TERMINATED exclusions, and propagated later-page errors. Do not replace Cloud with a canned ListInstances fake or mirror the string predicate in an isolated test.

Use the existing production SDK adapter, not a fake `Cloud`: `ociclient.New(...).Compute()` plus SDK ObjectStorage clients can target a localhost simulator through the existing `PinHost` test pattern. Back the attempt plan/state with real temporary files and supply signed/local test credentials. Serve the actual ListObjects calls before the control/workload Compute lists. Verify page query, requested compartments, decoded display names and emitted rows. Keep production configuration free of new knobs.

The minimum predicate addition uses existing `naming.IsNode(name, region)` with the supported legacy prefix. `IsNode` rejects `ts-sfo-1-data`, foreign regions and invalid indices. The existing TERMINATED test remains outside that disjunction. OCI ListInstances never returns block-volume resources; the scenario should still include a current data-name row to detect a broad `ts-*` shortcut. Preserve intended legacy instance support; do not infer that legacy data-volume names become valid instance identities.

Evidence declarations:

- `internal/attempt/attempt.go:1410` — `Attempt.PhaseStatus`
- `internal/cli/cli.go:220` — `runOCIRegion`
- `internal/ociregion/seed.go:110` — `Engine.seedLaunch`
- `internal/ociregion/seed.go:148` — `controllerName`
- `internal/naming/naming.go:93` — `Cell.ControllerSlot`

### F2 — review-gate: Required negative cases still include isolated helper/fake-API checks

TestPeerPortOpen calls a test-only predicate on locally constructed rule maps. The three observer cases construct an observer over in-memory fake Compute/Network APIs. No service, network, persistent store or runtime boundary is crossed by those cases.

**Disposition:** Bounded behavior-based unit-case finding under REFACTOR:1054-1095. It is not a classification of their files or helpers used by real boundary scenarios.

**Smallest next correction:** Move NSG failure cases into the owning SDK/API-backed observation scenario and observer rejection cases into the existing signed-packet/SDK/simulator flow with the production observer variant; retain safeguards and remove old cases/helpers only after replacement evidence exists. Do not delete shared packet SDK/simulator infrastructure.

Evidence declarations:

- `internal/terrabase/oci_live_test.go:241` — `TestPeerPortOpen`
- `internal/bootstrapstart/oci_observer_test.go:78` — `TestOCIObserverRejectsNetworkOwnershipAndRegionMismatch`
- `internal/bootstrapstart/oci_observer_test.go:127` — `TestOCIObserverRequiresExactAttachedPrimaryVNIC`
- `internal/bootstrapstart/oci_observer_test.go:142` — `TestOCIObserverRejectsMissingPrimaryAndCandidateMismatch`

### F3 — closure-gap: Passing live selectors need not witness hosts or instance readback

The TerraBase entry explicitly returns successfully after regional checks when no matching hosts exist; with one host, no ordered peer pair is checked. The attempt entry asserts GetInstance/naming only inside returned-row loops and requires no row or matching-prefix witness. Both entries are absent from the seven image qualification selectors and skip on missing fixtures in ordinary runs.

**Disposition:** These are source-proven limits, not a claim that their documented regional/read-only purpose is itself a production bug. No passing suite receipt can be inferred.

**Smallest next correction:** Define the retained live acceptance witness, assert its required nonempty identities/counts, and route that dedicated selector through an owner-supplied qualification fixture with no selected skips. Keep offline protocol evidence distinct; do not add another switch or broaden this task into cloud execution.

Evidence declarations:

- `internal/terrabase/oci_live_test.go:37` — `TestLiveOCITerraBaseHostsReadOnly`
- `internal/attempt/cloud_live_test.go:17` — `TestLiveReadOnlyCellInstancesFollowTheNamingScheme`

## Contract boundaries, in requested review order

### C1 — `tests/firecracker/production/fixturegen/compute_inventory_sdk_test.go`

Signed three-slot packet/file material -> real instance-principal OCI SDK federation and signed service reads -> project Simulator API -> decoded instance/VNIC/subnet fields. Under fixturetest, the same SDK clients also enter production OCIInstanceObserver.ObserveInstance.

**What the source asserts:**

- The caller writes/reads a signed packet with synthetic executable bytes and three completed histories, checks floors/lock/files/routes, invokes the SDK helper per slot, and verifies the embedded image receipt.
- The helper requires instance ID/ETag/identity presence and lifecycle; exactly one attached VNIC; primary VNIC identity/IP/lifecycle; separate network compartment and expected subnet/VCN; all audited requests listed/200 and a bounded exact Compute request count.
- The fixturetest helper compares the production observer result against expected instance, ETag, control compartment, image/AD/FD/shape, subnet/primary VNIC/IP/lifecycle and NSGs. Default helper returns zero and performs no observer assertions.

**Existing negative evidence:**

- Adjacent simulator tests inspect wrong session key, changed signed query, write method, tampered federation and stale signature rejection. These are source assertions, not execution receipts.
- Observer rejection tests inspect wrong VNIC/subnet ownership, wrong/missing VCN, unavailable subnet, foreign attachment, missing primary and candidate mismatch; these use in-memory fake APIs and require migration under integration-only policy.
- A separate transport test actually uses localhost HTTP redirect/target servers and inspects no-proxy cloning, timeout and redirect rejection. Its source existence prevents a claim that transport coverage is absent repository-wide.

**Remaining gaps:**

- This scenario dispatches directly into Simulator.ServeHTTP through httptest.NewRecorder: no socket, DNS, TLS, real OCI account or normal OCIInstanceObserver constructor/transport is exercised.
- The positive packet has one attachment page; duplicate primaries, repeated/nonempty continuation tokens, over-64 attachments, API transport/error response and deadline cases are not asserted in this selected entry/helper path.
- Packet observations are generated from the same signed recipe used for expectations. This verifies protocol/model and binding consistency; it is not independent evidence of live cloud truth or a complete admission decision. Gate.observe/AdmitRestart enforce further signed identity/lifecycle comparisons.

**Runner exposure:** Default root T0/T1 reach the entry subject to compilation/discovery. T1 ci-verify adds fixturetest-check to reach the production observer tag variant; PR excludes that target. Neither variant has an explicit seven-suite T2 image selector.

**Disposition:** Offline real-component protocol/store scenario with a helper; no whole-file classification.

**Status:** bounded source inspection complete; execution unknown; integration closure not established.

### C2 — `internal/terrabase/oci_live_test.go`

OperatorConfig-backed OCI SDK read APIs -> regional A1 shape/quota/image evidence -> selected running-host attachment/VNIC/NSG evidence -> ParsePeers and ingress-rule predicate.

**What the source asserts:**

- Requires compartment fixture and API success; checks a matching A1 shape/Ampere description, minimum profile options, summed quota availability and at least one Ubuntu image.
- For matching hosts with primary attached VNICs, checks A1 shape, parseable peer addresses, fault-domain separation when member count <=3, unique parsed peer names/addresses and an allowed ingress rule per ordered distinct-name pair.

**Existing negative evidence:**

- The separate TestPeerPortOpen rejects a mismatching destination port, wrong sender group and unrelated CIDR; it supplies in-memory maps to a test-only helper.
- API errors and observed mismatches fail through assertions; no controlled live-API negative fixture is selected here.

**Remaining gaps:**

- Zero members return success explicitly; one member tests no pair. Default prefix targets the documented legacy GRU database hosts and does not establish coverage of every colocated/current node.
- peerPortOpen checks source CIDR/NSG and destination-port allowance, not an actual connection, egress, route table, security lists or application listener; it ignores TCP source-port constraints. Static ingress allowance is the strongest supported claim.
- Shape/image/instance/VNIC/NSG lists make individual bounded requests without exhausting continuation pages in this test. Optional numeric Shape option pointers are dereferenced without individual nil guards; malformed/partial model responses can panic.
- ParsePeers proves serialization/uniqueness, not signed runtime identity, ready state, actual peer handshake or replicated data behavior.

**Runner exposure:** Direct tier.Qualification requires TS_OCI_LIVE_COMPARTMENT_ID: ordinary missing fixtures skip even in full runs; qualification missing fixture fails. Not selected by the seven-suite image runner. TestPeerPortOpen is independently discoverable without the fixture.

**Disposition:** Live read-only SDK entry when fixtures exist, plus a distinct isolated helper case; no whole-file classification.

**Status:** bounded source inspection complete; execution unknown; integration closure not established.

### C3 — `internal/attempt/cloud_live_test.go`

Operator SDK cloud -> paginated OCI ListInstances -> GetInstance readback -> legacy-GRU-prefix naming validation. Connected production owners include bootstrap PhaseStatus, waitRunning and adoptMember.

**What the source asserts:**

- newSDKCloud creates the shared OperatorConfig-backed production SDK adapter in GRU. ListInstances follows page tokens up to maxPages=256; the test GetInstance checks ID/display-name agreement for every returned row.
- Only non-TERMINATED rows beginning gru-1- enter naming.Validate. API errors or mismatched readback fail; the entry never mutates cloud resources.

**Existing negative evidence:**

- Naming package examples include current ts-gru/ts-sfo nodes, foreign/invalid name cases, and intentional legacy GRU controller names; the live selector covers only its GRU legacy prefix.
- Connected adoption tests use launchCloud to reject retained-launch mismatches. They do not exercise the production SDK HTTP/pagination boundary or fix the PhaseStatus output gap.

**Remaining gaps:**

- Empty lists require no GetInstance or naming witness. New-format GRU names and other regions do not enter this test naming guard, including invalid current-format strings with that different prefix.
- A naturally occurring fixture does not force multiple pages, later-page errors, repetition/page-bound exhaustion, normalization mismatches or cancellation. Those outcomes are unknown from this entry.
- The test never calls PhaseStatus or asserts CLI output. Production SFO status omission therefore survives this read-only adapter/naming check. It also does not establish launch/adoption safety or create-key/material identity.

**Runner exposure:** Direct tier.Qualification requires TS_OCI_LIVE_COMPARTMENTS; ordinary missing fixtures skip. Not selected by the seven-suite image runner. Root ordinary execution and all fixture results remain unknown.

**Disposition:** Live read-only SDK/naming entry when supplied; no execution or complete integration claim.

**Status:** bounded source inspection complete; execution unknown; integration closure not established.

## Ownership and deletion decision

REFACTOR:206-237 permits read-only observations and retains OCI capacity/resources, regional/bootstrap and CLI. :243-251 requires caller/responsibility disposition; :1054-1104 requires integration-only migration and real boundary scenarios before deletion. No attempt-specific package disposition was found in REFACTOR.

Correct only the retained reachable OCI status observation boundary after owner review; migrate isolated negative cases into owning SDK/API scenarios before any deletion. Do not expand or permanently retain superseded attempt service/scheduler phases.

PhaseStatus is a read-only infrastructure/bootstrap inventory: its selected body calls object/instance list APIs and prints observations. It contains no task assignment, Machines planner or native task-execution call. This narrow fact does not clear other phases in the same package. Removing this command requires a replacement CLI/API caller migration and retained observation scenario; that evidence is absent here.

The packet SDK helper, controlled protocol simulator and production-observer fixture serve a real connected scenario. They are not shown to be unit-only infrastructure. Conversely, the inspected TestPeerPortOpen and fake-API observer cases are isolated by their actual bodies and need migration under the explicit integration-only policy. Never delete the complete mixed-purpose files on these local classifications.

## Hashes and reproducibility

`files.tsv` records full file SHA-256 and Git blob OID for all source references. `declarations.tsv` records exact selected declaration SHA-256 with source/end lines. Declaration hashes cover UTF-8 bytes from the `func` token through the matching body closing brace, excluding leading comments. The method is lexical, not compiler discovery; accepted inventory declaration hashes were checked wherever available.

| Primary declaration | File SHA-256 | Declaration SHA-256 |
| --- | --- | --- |
| `tests/firecracker/production/fixturegen/compute_inventory_sdk_test.go:40` / `assertPacketComputeSDK` | `3b4fea33b7a26fbaf46b80b422528069afee9b0ed5d3e4f5bae503ae84534afd` | `49a2dff13932d0b46e311c2fc13c8f0fd31b9fc3e117794430f4334eda0445a8` |
| `internal/terrabase/oci_live_test.go:37` / `TestLiveOCITerraBaseHostsReadOnly` | `37bec5810a8b0311375e86bb3d9e405df9ddbce7de7b489640bce63717396f1c` | `213d1ad6ce597d54f2a9296e13e23208cee2605c0e54e9a0a81190e35346967a` |
| `internal/attempt/cloud_live_test.go:17` / `TestLiveReadOnlyCellInstancesFollowTheNamingScheme` | `3ac1d7fb3eeb35c599c2bc819ed6174347fdcf7602ccc74d863a5fa9633be09c` | `9646d80c0a9342f698d302f583d4c5d22b48a09e4a8caa7573822689a59252be` |
| `internal/attempt/attempt.go:1410` / `Attempt.PhaseStatus` | `fd8b58b8bd266d57ae5f7c878a818204fbb21a09d9d4b5c74d6df6ce44cd3ca0` | `d792acffd097bdabdeef128c8efcf0bb02a9346dcad0f04721f9f8572db8c661` |

`collect.py` reads immutable Git blobs and hashes selected lexical declarations. `verify.py` independently reconstructs declaration bytes from physical line spans and rechecks all scoped Git file bindings; its receipt is `verification.json`. `render.py` renders these notes and structured `review.json`. All write only alongside themselves in `/tmp`. `SHA256SUMS` seals all artifacts except itself. The accepted inventory/proposal artifacts were preserved.

**Not performed:** source edits, Go runners, builds, lint/race, cloud calls, exhaustive source review, deletions or integration-only closure. No runtime success is implied by a source assertion.

Next: have the OCI/bootstrap owner apply F1 only at the retained status boundary and qualify its real-SDK HTTP/pagination scenario before considering deletion of superseded dependents.

The complete original packet is retained in `review.tar.gz`. Extract it to a temporary directory and run `sha256sum -c SHA256SUMS` there. Referenced packet files are inside that archive; this presentation normalizes trailing Markdown spaces only.
