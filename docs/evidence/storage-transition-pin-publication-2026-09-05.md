# Storage transition pin publication, 2026-09-05

Implemented `transitionreceipts.PublishPlanPin` for create-only publication of
an existing durable signed host acknowledgement. The signed plan fixes the
regional bucket, ownership observation, host, and object key. Every attempt
reads the remote bytes and rechecks ownership before reporting success.

Validation uses a local HTTP server through the production OCI signer,
transport, and bounded object reader. Synthetic receipts cover the source,
a separate GRU destination, SFO, and FRA. Cases include initial creation,
identical retries, a closed connection after persistence, server error after
persistence, conflicting bytes, falsely matching digest metadata, ownership
changes before and after PUT, future receipts, wrong host, cancellation,
redirects, and missing objects after failed uploads.

`go test -race ./src/orchestrator/transitionreceipts` passed.
`make check` results are retained in the adjacent portable log.

This is local protocol validation. Automatic host invocation and credential
acquisition are not connected yet. It does not qualify live OCI behavior,
real host persistence, storage preparation, or source retirement.
