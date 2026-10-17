# NetBird public HTTP contract and isolated retirement

Public `NewAPI` → `ReadInventory` passed one root and four leaves without skips on qualified source `44fccacf`. Authenticated GET /api/groups refused an HTTP→HTTPS redirect with zero destination requests, hid secret error bodies, and preserved five rejected and three accepted constructor origins.

Retirement `9bd689bd` removes only the mapped 29-line / 1,181-byte private API test declaration. All remaining source bytes and the new public test match their qualified snapshots. True `go test -c` passed once in 6.20 seconds; its 30,660,181-byte binary was never executed. Runtime was not repeated for adoption.

The runtime and compile folders preserve exact raw logs, sealed requests/wrappers, receipts and actual tool launch/poll/terminal results. Original checksum files are retained; compile binary bytes alone are omitted, with their identity recorded in `adoption-review.json`. Root `SHA256SUMS` covers all included files.

Scope: local public HTTP client contract and isolated duplicate retirement. No real NetBird manager, production transport, IPv6 connection, whole-union runtime, or global migration claim. All five REFACTOR categories remain open; main is unchanged.
