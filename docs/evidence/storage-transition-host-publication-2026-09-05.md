# Host storage transition publication, 2026-09-05

`ts-node` now publishes its durable acknowledgement after first pin admission
and restart recovery. It recovers the original signed bytes before acquiring
instance-principal credentials in the plan's host region. A one-minute context
bounds the attempt; the identity is closed afterward. Failures preserve the
private pin and receipt for startup or command retry.

Production uses the official OCI metadata/federation flow without a private
API key. An optional owner-signed `ociQualification` descriptor selects the
existing mTLS fixture. Its private credential path must be separate from all
plan, receipt-key, storage, and admission paths. Unconfigured delivery bytes
are preserved by omitting this optional field.

The isolated root tests use a private tmpfs mounted at /var/lib and the actual
host journal, official SDK federation, HTTP signatures, and regional object
publication against the mTLS fixture. They verify source and destination
publication, exact remote/private bytes, restart without the receipt signer,
missing federation credentials after durable acknowledgement, unchanged retry
bytes, and no provider access for invalid local evidence. Existing source
retirement and candidate epoch-admission barriers remain closed. The candidate
suite also exercises recovery after original bootstrap expiry.

Validation:

- `go test -race` for controltransition, initialgrant, transitiongrant,
  hostbootstrap, and transitionreceipts.
- Isolated root/race host tests, retained in the adjacent root-race log.
- `make check`, retained in the adjacent portable log.

These are local integration tests, not OCI IAM or live-provider qualification.
Remote plan/key provisioning, a background retry worker, automated collection,
the complete preparation barrier, phase execution, and six-host qualification
remain unfinished.
