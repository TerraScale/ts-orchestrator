# Direct QA evidence: three bounded scopes

Publish these files as evidence only. The packet grants no execution, source adoption, retirement or live-production credit. No archive or executable binary is included.

1. producer8f3: PASS for 17 named tests and one package. Commit 8f3e9ec45991b63e713c807cf0e0d0764dc915a3; tree 6ec6d2d06799ab93c6fc3e2386dfe4def2749d8f. Three roots cover loopback OCI SDK preparation, temporary-file offline signing, and production SDK publication replay/refusals. Default vet and tags; non-race. Package 0.962s; total 142.806787s.
2. customer67bc: PASS for TestCustomerEnvelopeFilesystemBoundary and Success, WrongRecipient, FlippedCiphertext, AlternatePartition; one package pass. Commit 67bc9eea1b118c7beff0c62914f20a53c3d3483d; tree e5d3f47d33441ff8b3e54a97fc98614151cd7f79. Local filesystem-envelope boundary; explicit -vet=off and non-race. Package 0.085s; total 115.058567s.
3. OCI78e: NOT_QUALIFIED compile-only. Commit 78e86dd4332cf79ba8eb3dd7bccfd8e62f5c4f44; tree 80089250684b1ee89b7ec37460be1363b909fdbc. bootstrapmaterial test import cycle and ociregion/foundation.go:556,557 undefined statement cause exit 1. Four partial ELFs exist; region.test, rootociread.test, bootstrapmaterial.test and cli.test are absent. No init/test/output-binary execution. Total 105.586881s. Binary contents are excluded; exact hashes, sizes, modes and reason are retained.

## Names, bytes and history

manifest.json lists every actual named test outcome. Every original absolute path and directory maps to one flat copied_name, SHA256 and byte count. Byte-identical originals share a single copy with explicit alias mappings. All raw receipts, outputs, manifests, native objects when retained, and .patch files remain byte-exact. Original internal paths/checksum files remain unchanged; use the mapping to locate flat copies. Go source snapshots use .go.txt; source-name-mapping.json gives the repository path. No source is adopted.

Earlier producer 96960 compiler failure, 11a5 runtime failure and 3e50 runtime failure remain separate and unchanged. Their receipts are copied as history only; all original raw evidence remains at its original directory. These failures are never combined with 8f3 PASS. Customer 7a69 predecessor requests and proofs remain preserved; its packet was unused due to the compile prerequisite. The accepted runtime result belongs only to 67bc. Retained original tests remain retained; no retirement credit.

## Provenance and scope limits

Producer has nine actual surfaced native tool-result objects, without call input arguments. Session, PID, output and terminal exit agree; no independent broker record or OS lifecycle audit is claimed. Customer retains actual surfaced launch/poll/terminal objects; its independent native supplement confirms exit 0 with the exact receipt. OCI native metadata is explicitly manual owner conversation transcription; no standalone raw native results were retained. The original OCI final-seal.json remains a source-only seal; the later metadata index is a separate convenience record, not recovered native evidence.

Immutable prelaunch request/seal labels remain unchanged; later runtime artifacts and reviews carry actual outcomes. No race diagnostics do not establish race-detector coverage. Disclosed initializer uncertainties remain limits. The customer lexical closure contains one public upstream zmap/zcrypto build-ignore RSA test-helper fixture, pemPrivateKey; it is not an operational credential. Its provenance is recorded in manifest.json and the audit bytes remain unchanged. No operational secret files or executable binaries are copied.

No live OCI, production credential-loading success, protected-writer nonoverwrite, live provisioning, production image qualification, native/identity runtime, global initialization proof, global regression, production readiness, source adoption or retirement is claimed. This is a publication packet, not a new execution grant.

## Verify

Run `sha256sum -c SHA256SUMS` in this directory. It covers every other direct file, including manifest.json, and excludes itself. manifest.json covers every copied original and generated README/source mapping/exclusion file; it excludes itself to avoid recursion. Every copy was rehashed against its original after preparation. All originals remain unchanged. No Git or shared-worktree file was written.
