# Write-budget control delivery

The GRU global factory loads the explicitly admitted billing snapshot, retains
its account revision/checksum/generation, and opens the write-budget journal
under the exact current global lease. Initial snapshots and authenticated
billing updates use the same canonical allowance, cutoff, rate, and accrued
non-write charge decoder. A configured policy listener requires `policy_tls`
certificate, private-key, and trust-bundle file references and serves TLS 1.3;
billing-key and body-HMAC authentication remain required.

Before reservation, runtime validation reads accepted current database placement
and lifecycle authority. Organization, selected Regions, admitted writer,
writer epoch, and configured placement proof must match. Deleted or stopped
resources, stopped usage streams, followers, and pending placement are refused.
The same bindings are checked again before regional delivery. A static policy
snapshot does not authorize a new placement incarnation.

Delivery uses the existing GRU-only host installation NATS subject. Its distinct
JSON envelope is `{"write_budget_allocation": <SignedAllocation>}`. The host
checks local holder/Region, then forwards the enclosed signed allocation to
`POST /internal/v1/databases/usage/allocation` on the existing engine Unix socket.
The host verifies the socket peer UID. The engine verifies the signature,
placement, organization/database, policy/consent/writer epochs, and expiry before
SQLite persistence. Only an empty HTTP 200 response produces `installed`.
Retries preserve signed payload bytes; randomized ECDSA signatures may differ.

## Remaining request contract

This delivery path does not introduce a public allocation endpoint or authorize
caller-selected quantities. The existing engine consumer looks up a grant by
exact public operation ID and requires the grant operation ID to match the
write. No production request/refill producer currently supplies those grants.
Synchronously calling GRU for every write would make new writes dependent on
control availability and does not meet the admitted-service requirement.

A refill extension requires coordinated engine/orchestrator work before it can
be exposed:

- Authenticate the admitted member through its existing private host and
  broker identity; never trust a request's holder field as authentication.
- Bind organization, database/branch, immutable selected Regions, residency,
  placement proof and writer epoch to accepted authority. Derive logical units
  from bounded trusted engine demand; reserve Region-multiplied units once.
- Separate durable grant identity from local operation identity. Persist the
  member's assignment of budget units to the exact authorized operation and
  scope together with its commit/idempotency state, preventing double spending
  after restart, failover, or an uncertain response.
- Bind signed grant bytes, policy/consent epochs and deadlines to that durable
  reservation. An exact retry must not change allocation scope or add spend.
- Keep already-delivered capacity usable during a control outage within its
  admitted bounds. Exhausted capacity must fail without minting new authority;
  quantify refill headroom and expiry/revocation propagation before claiming
  availability or spending-cap behavior.

The operation-specific consumer, static per-organization policy snapshot, and
member policy-epoch refresh must be extended together. The current transport
and journal tests establish their local boundaries, not a complete customer
write journey or VM/OCI qualification.
