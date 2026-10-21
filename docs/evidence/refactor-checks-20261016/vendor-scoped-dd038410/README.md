# Corrected-only vendor execution evidence

Source `dd03841025c65c0a6c3350b3e8ad7c4d27eea77d`, tree
`bac4b5eae4c69633777f8f89291cc032ea69b68c`; source manifest SHA256
`5eb590536c7455b40e78c68eed885efbea05f1e146557b0814c00f5fd94379a7`.

1. Short-A49007: only TestAccountServiceLatencyOverTCP PASS0.04s; package0.049s.
   Start<=5ms, service>=25ms, actual responder RTT bound and every assertion
   remain intact. Exclusive timing window; Short-B/GATE idle until terminal.
2. Short-B55780: only TestClientTCPAuthenticationDiagnosticsIngress PASS0.15s;
   all5 previously failed user/token/nkey/none/combined rows PASS0.03s each;
   package0.161s. No rejected-auth row or other passing case was repeated.

Each receipt includes exact argv/cwd, individual outcomes, released session,
byte-exact raw log archive (gzip mtime0), and identical before/after bindings
for clean HEAD/tree/manifest/all21 files and relevant module/helper/plan hashes.
Both runs used pinned Go1.27.1/unset GOROOT, GOMAXPROCS2/GOFLAGS-p2/nice19,
canonical five tags, readonly modules, count1, test120s/outer180s and nonblocking
locks. No retry followed either corrected-only run.

The two-body patch/proof, original-body integrity, source handoff and RTT proposal
are exact historical source-preparation artifacts. Their source-only/ungranted
status text records preparation time; the two runtime receipts above record the
later, explicitly granted executions. No source artifact was rewritten.

`historical-evidence-links.json` binds every byte of the unchanged sibling
`../ts-vendor-scoped-evidence-67ec90a3` packet, explicitly retaining A33125's
service-duration failure and B94366's five PING-trace failures. It links every
prior scoped receipt and vendor terminal-event/log reference with individual
observed passes/failures. All27 sampling, all4 rejected-auth, trace16, repaired
expiry/eviction, earlier6d and all other prior passes remain excluded and
snapshot-specific. Historical failures and unexecuted distinctions stay intact.
The proof preserves1923of1925 bodies and every byte outside the two corrections;
no historical pass is relabeled as a new run.

`integrity-checks.json` records packaging checks; `evidence-manifest.json` hashes
all payloads, and `SHA256SUMS` also hashes that manifest. Both lanes remain idle.
This packet makes no equivalence-closure, full-suite, live, race or production
qualification claim. No runners, source/feature Git mutations or push occurred
while preparing it.

The complete original packet is retained in `evidence.tar.gz`. Extract it to a temporary directory and run `sha256sum -c SHA256SUMS` there. Referenced packet files are inside that archive; this presentation normalizes trailing Markdown spaces only.
