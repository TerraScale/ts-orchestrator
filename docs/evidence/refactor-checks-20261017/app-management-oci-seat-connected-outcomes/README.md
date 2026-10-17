# APP, management, OCI and DATA seat connected outcomes

Evidence-only publication packet for `docs/evidence/refactor-checks-20261017/app-management-oci-seat-connected-outcomes`. The four pinned independent reports control accepted scope and limitations. Packaging does not rerun or extend qualification, adopt source, retire tests or change prior failures.

## Exact outcomes

| Scope | Source commit / tree | Accepted outcome |
| --- | --- | --- |
| APP d0b | `d0b972460a0d6413aaa948a967a2c2406b407a4b` / `9603fd5ec7d35ebb02e7839d7e3521528cae116e` | Exact local connected `TestGenericRuntimeSignedManagerIntegration` root and internal/app package PASS. Root 164.12s, package 164.196s. Explicit vet off, non-race. |
| Management 2d158 | `2d15811884db8036d4c2348cbf1adaa6af1422f3` / `89edb76c39969780081df545e6f6f4bf9759086d` | NOT_QUALIFIED: internal/swarmruntime package FAIL after 1.423s; 24 named run/terminal identities, 21 PASS and 3 FAIL; 26 expected identities, 2 missing. |
| OCI64 runtime | `64a55bb2fc0034279732cfb8a99c06b75cf90d6a` / `430c89f4408d37377f6492f7d827c58f2578cb89` | NOT_QUALIFIED: `TestFoundationRecordsPersistAndFenceConcurrentWriters` and child `provision_originals` both FAIL. Zero PASS/SKIP. Native runtime exit 1 in 2.109s; one copied-binary execution, zero original compile-binary executions. |
| DATA seat70c03 | `70c03e8ca01a9bbe667e489608eb48f62c8762af` / `ac1551c89f7e52e4d956727800279cc35d3f1a39` | Exact internal/seatrollout whole-package PASS: 21 named PASS (12 roots, 9 leaves), package 0.769s. Default vet, non-race. |

### APP: connected PASS with simulated execution

This exact source runs one authenticated local NATS/JetStream broker and three actual managers, with simulated executor/native execution and external recipient adapter. Ordered authenticated setup/rejection, scale/repair, release ordering, authority/removal and retained-evidence assertions completed within one named root PASS. Inline assertions are not separately named passing tests. Election follows zero replicas, and probeClient continues to reference the original manager; this is no live-workload failover or HA qualification.

The corrected test preserves strict current-role refusal after removal, then compares exact original native role/profile/provenance KV bytes and sequences and archived verified signed claim envelope bytes. All five reference categories are traversed; the seeded fixture uses Spec provenance. Admission record revision/metadata is not directly compared. Native artifact bytes are reverified by authenticated digest/size. This does not claim coverage of every alternate provenance form or unrelated record. Production authentication remains unchanged. Narrow source snapshots include the exact d0b root plus duration fingerprint implementation/regression as source context; their presence grants no separate runtime result.

Accepted raw lifecycle is 830 events: 1 start, 1 run, 826 output, 2 pass(root+package), with no fail/skip/extra identity. Deliberately failed tasks/rejected releases, unavailable network support and shutdown/session/peer errors stay in raw logs. Earlier APP ce04 timeout, aa0 duration failure and 6aab manager failure remain historical failures; this d0b PASS does not relabel them. Prior evidence packets are referenced by original reports, not recopied as new outcomes.

### Management: three failed roots, partial named passes only

`TestManagementIntegration` fails at management_integration_test.go:148: ordinary pause receives PermissionDenied. The fixture starts its node without AdmitNode, leaving required manager-owned region/instance placement labels absent. Production guards remain intact; the redacted raw error does not independently identify the exact rejected guard branch. Later pause, service/resource/CAS/release/public-projection/revocation assertions and wrong_UID/wrong_service subtests are unreached.

`TestManagementObservationIntegration` fails at management_observation_integration_test.go:74: broad upstream Watch returns Unimplemented instead of expected PermissionDenied. The service is not registered; this is a status-contract mismatch, not exposure of broad Watch. Scoped snapshot/live actions, handoff, replay, persistent restart and final revoked-stream assertions are unreached.

`TestManagementObservationGRPCBlockedSend` fails at management_observation_send_test.go:127 because its first 1 MiB SendMsg completes before the blocked-send precondition check. The raw fixture does not retain that SendMsg return error, so success versus error completion is not separately established. Overflow/cancellation/release assertions are unreached; failure does not establish broken production cancellation. Separate manual blocked-send tests are among partial named PASS results.

Independent raw review retains 285 events, 24 RUN/terminal identities, 21 PASS / 3 FAIL plus package FAIL, 2 missing expected children (wrong_UID and wrong_service), and no malformed/extra/scope/order events. It grants no 26-outcome or whole-package qualification. Wall 127.783s includes compilation/startup; package 1.423s ended by assertions, not 120/180s timeout. No retry or timeout extension is inferred. Supplemental gRPC-cache source reads in the independent explanation lie outside the sealed 4,208-source execution pins and are not promoted into those pins.

### OCI: fixture setup and writer reload fail

The `provision_originals` leaf fails at foundation_provision_integration_test.go:114 because signed worker policy omits an approved role or architecture. SignFoundationDiscovery fails during fixture authority setup before its TLS fixture server and before its first ProvisionFoundationBundle call. The leaf provides no actual provisioning/recovery/IAM launch execution credit.

The parent continues its local signed SDK/disk-CAS fixture but fails at foundation_integration_test.go:179: original pending launch lost because original home writer checkpoint is invalid. Later original ID/policy checkpoint and corrupt-policy assertions do not finish. The eight raw verbose lines preserve two RUN/two FAIL identities and standalone FAIL. Runtime failure does not rewrite the earlier region-only compile PASS, aggregate 620 compile failure or any earlier failure. It does not establish a production repair or live provisioning result.

### DATA seat: exact local whole-package PASS

The accepted raw lifecycle contains 106 events: 1 package start, 21 run, 62 output and 22 pass (21 tests plus package). All expected identities, parent/child order and active output scopes match, with no missing/extra/duplicate/fail/skip/malformed events. The accepted wall time is 55.775s, package 0.769s. Default vet was requested and accepted for this exact source; no race check ran.

Fixtures use 19 successful sequential embedded NATS/JetStream brokers, at most one concurrently, each with a localhost ephemeral TCP listener, temporary store and one client. The test broker is local unauthenticated NATS; this grants no production credential/ACL or authenticated-broker fixture credit. One incompatible-bucket case intentionally uses memory KV. Controller inputs are in-memory desired generations, host reports and backend health with simulated time. Tests call Tick rather than Controller.Run. No real TerraBase/native restart, cloud/HTTP action, APP seat gate/load/reconcile adapter, production replication or multi-node JetStream failover is exercised.

The narrow store.go and reader_test.go Git blob text snapshots preserve the exact owned change and new reader assertions. Complete package and repository identities remain in source manifests and the independent report. This result does not connect the APP and DATA scenarios or qualify production caller wiring.

## Retained provenance and historical states

All files under the seven selected roots are mapped and copied except the OCI ELF runtime copy. Its original SHA256 is 446596085ee51b95485a2076d3575dfa9141ceac09c0b561373e55016167333a, size 62,893,977 bytes, mode 0600; MANIFEST.json records those exact values and the exclusion reason. No ELF bytes, symlinks, archives or direct .go package inputs are included.

APP retains actual surfaced result-only launch/six polls/terminal objects: session 93142, outer PID 659458, terminal 4ee6e5 exit 0. OCI retains result-only launch/terminal/resource objects: session 40740, PID 672723, terminal native receipt exit 1. These objects do not manufacture missing tool-call arguments; separately retained request/preflight/started argv are supporting evidence. Management retains actual tool arguments/results for launch and ten polls: session 60404, PID 673367, terminal ee16e2 exit 1, with no retained-object truncation. These are retained surfaced objects, not independent backend/OS syscall records.

DATA retains actual launch and three poll tool arguments/results: session 87822, child PID 686331, terminal 8730db exit 0, with no retained-object truncation. Its original FINAL-SEAL.json and native/raw result records are preserved unchanged. The independent report verifies 3,795 source entries and 11 tool pins; retained release/resource observations are historical and this packager does not re-probe them.

Original source-only request states and seals remain byte-for-byte unchanged; terminal/final-runtime seals and independent terminal reports are separate records. Management final-seal, owner full-event-review and all raw outputs remain originals. Accepted reports preserve retained release evidence. Management child absence and GENERAL/GATE unowned were independently observed read-only at report time, with no comprehensive descendant inventory. This packager did not probe processes or locks and does not make a current availability claim.

## Layout and verification

All payloads are flat exact copies. MANIFEST.json maps every original absolute path/directory to a copied filename, retains size/SHA256/original mode, and identifies byte-identical deduplicated aliases. Copied payload modes are 0644. Original internal absolute paths are not rewritten, and historical patch bytes would remain exact. Source manifests preserve complete source pins; only 18 narrow source snapshots are copied, from immutable Git blobs at each exact clean frozen HEAD. Every source snapshot ends in .go.txt and maps repository path, commit, tree, Git blob ID/mode, source-manifest pin and SHA256. These text copies are evidence, not package compilation inputs.

SHA256SUMS directly hashes every copied payload plus README.md and MANIFEST.json; it excludes itself to avoid recursion. Run `sha256sum -c SHA256SUMS` from this directory. Deduplication checks actual byte equality in addition to SHA256 and size. Every copied mapping was rehashed against its original after copy; source snapshots were also compared with Git blobs and pinned manifests, and excluded binary identity was rehashed.

Packaging performs read-only metadata/Git/blob/hash operations and writes only fresh /tmp artifacts. It executes no Go/build/test/runner/binary, changes no feature/source/index/shared worktree, acquires no grant/lease/lock, and makes no retry, commit, push, publication or cloud call. This packet grants no source adoption, retirement, canonical/main/global/full-suite/race, connected APP-OBS-DATA, native/containerd/cloud/OCI/IAM production or independent OBS qualification.
