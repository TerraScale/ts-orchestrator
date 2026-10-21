# Scoped vendor execution evidence

Selected source: `67ec90a3934a5613384a34432a47893d80fbf6fc`; tree
`fa86bfa050dae4aca48cf88544bd994a66e4b9cd`. The source manifest is included
unchanged, SHA256 `9b636279f8f93010e340abb50f449deae92cc0bc454091bd6b97cf81969e8cc8`.

1. Trace3, Short-B66522: three roots and all16 leaves PASS; package0.474s.
2. Latency, Short-A33125: sampling root/all27 rows PASS; service-latency
   root FAIL at accounts_test.go:821, ServiceLatency>=25ms. The preceding
   request-start<=5ms assertion passed. Actual failing duration was not logged.
   Package0.069s, exit1.
3. Authentication, Short-B94366: rejected-auth root/all4 rows PASS;
   successful-auth diagnostics root/all5 rows FAIL at client_test.go:5836,
   Missing production PING trace. Later diagnostic assertions were not reached.
   Package0.269s, exit1.

Each added run includes exact argv, dispatcher receipt, individual root/subtest
outcomes and output, and a byte-exact raw JSONL archive (gzip mtime0). All used
canonical five tags, pinned Go1.27.1/unset GOROOT, GOMAXPROCS2/p2/nice19, readonly
modules, count1, test120s/outer180s and nonblocking lane locks. Historical
execution postchecks verify clean exact HEAD/tree/manifest/all21 hashes; leases
are released. No execution or source changes occurred while assembling this packet.

Prior6d receipts, failures, repaired67 expiry/eviction receipts and archives are
preserved byte-for-byte. Original README and checksum index are retained as
`.before-extension` history. Prior receipts are snapshot-specific. Constructor
admission, original wildcard routing and all private contract gaps retain their
previous dispositions. These are scoped observed execution outcomes; no central
equivalence closure, deletion, full-suite, race or production qualification.

`evidence-manifest.json` indexes every payload artifact with SHA256 and size.
`SHA256SUMS` additionally checks the evidence manifest. No unexecuted source
bodies were added to this packet.

The complete original packet is preserved in `evidence.tar.gz`. Extract it to a temporary directory, then run `sha256sum -c SHA256SUMS` there. Paths mentioned above are inside that archive. The presentation README normalizes trailing Markdown spaces; the archive retains exact originals.
