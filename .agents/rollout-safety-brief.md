# Rollout safety qualification gaps

Scope: upgrade/rollback integrity and recovery beyond health observation.
Source inspected: `src/orchestrator/delivery/rollout.go`, `delivery/api.go`,
`delivery/journal.go`, `hostcontrol/client.go`, and the production-operation
inventory. No builds or code changes were made.

## Gap 1: crash after a partial host rollout has no durable per-host recovery

`Rollout.rollHosts` keeps `touched` only in the in-memory call stack
(`delivery/rollout.go:361-398`). The durable delivery journal stores an
`Operation` while running and writes one terminal `Receipt` only after
`deliver` returns (`delivery/api.go:430-460`). A process loss after one or
more `Converge` calls therefore leaves no durable host progress or prior
artifact record. `RecoverUnknown` deliberately closes the operation with an
unknown failed receipt without compensating provider work
(`delivery/journal.go:516-590`). The existing fake rollout tests prove reverse
order rollback in one uninterrupted call, but do not cover process loss,
restart, or a six-host real control path.

Executable qualification: inject a host control that terminates the rollout
owner after the canary and one additional host have converged, persist the
operation journal, then let a successor acquire the expired lease. Assert the
successor either resumes a durable per-host rollback plan or records an
explicit blocked/unknown state that prevents further candidate traffic; it
must never report `rolled_back` without receipts proving every touched host
returned to the exact prior digest. Inject a lost reply after each forward
and rollback mutation and verify idempotent receipt replay, generation fence,
reverse ordering, and no duplicate host mutation.

Acceptance evidence: durable records bind operation ID, candidate digest,
prior digest/manifest, host, phase and mutation receipt; restart recovery
preserves the RF=2 floor; every touched host has an exact prior-digest receipt;
an unresolved host yields `RollbackFailed`/unknown remediation rather than
success. This directly closes inventory OP-13's “lost-master recovery” and
“durable per-host prior digest and receipt” gap.

## Gap 2: rollback target integrity is only exercised through fakes

The request validator checks rollback identity shape and that it differs from
the candidate (`delivery/contract.go:536-552`), while `rollbackTouched` builds
a plan from the request's rollback digest and calls `HostControl.Converge`
(`delivery/rollout.go:588-614`). The rollout seam returns only `error`; its
tests' fake control records the digest but cannot prove the host activated the
matching prior manifest, launch configuration, architecture, or installed
bytes. `hostcontrol.Client.Rollback` validates a typed host receipt, but no
production six-host qualification composes that receipt path with a failed
gate and every touched host. The inventory explicitly records real six-host
upgrade and per-Region rollback as missing.

Executable qualification: stage signed candidate and prior artifacts on six
real test hosts (two per Region), run the canary/one-host-at-a-time rollout,
force each gate class to fail at canary, middle host, and final Region, and
capture the signed host `DeployReceipt` for every forward and rollback
mutation. Verify each rollback receipt binds the requested prior artifact and
manifest digests, installed launch arguments/configuration, architecture, and
actual current version; tamper one receipt, substitute a same-shaped digest,
and return a lost/ambiguous reply to prove fail-closed behavior. Confirm no
host outside the touched prefix is mutated and no rollback success receipt is
issued until all touched hosts are verified.

Acceptance evidence: raw host receipts and artifact/signature digests are
retained per host; candidate and rollback identities are exact; tampered or
ambiguous readback produces a failed rollback receipt; the final receipt is
`rolled_back` only when every touched host has verified prior state. This
closes the upgrade/rollback security and integrity gate without relying on
health reports alone.

## Existing boundaries

`RolloutFenced` checks the operation fence before each injected mutating call,
and the API fences rollback recovery (`delivery/api.go:568-611`), but those
checks do not make host mutation progress durable. Existing local tests cover
ordering, fake gate failures, receipt schema validation, and fence rejection;
they do not establish the real host, restart, lost-reply, or per-host receipt
evidence above. Provider/Cloudflare live behavior and VM qualification remain
separate gates.
