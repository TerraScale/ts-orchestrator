# Storage transition plan and durable admission evidence

The signed plan is implemented in `controltransition`. The existing
`nodeauthority.EpochStore` now has separate admission and recovery APIs for its
immutable private pin. See
[the plan contract](../contracts/control-transition-plan.md) for the fields,
trust boundary, lifetime rules, and remaining execution work.

The new tests cover:

- owner signatures and signature-domain separation from candidate preparation
  and preliminary transfer;
- canonical JSON v2, malformed/unknown/duplicate fields, foreign keys, payload
  tampering, lifetime boundaries, and immutable verified inventories;
- incomplete or conflicting hosts, accounts, streams, consumers, routes,
  storage paths, certificate/receipt keys, ownership references, and limits;
- source admission with the existing original R1 publication and admitted
  regional command, plus refusal without that command or after its expiry;
- failure after the private pin rename, exact retry, receiver restart, and
  byte-identical recovery of the original pin;
- plan recovery after R1 retirement without reopening original admission;
- destination refusal without bootstrap admission or after ordinary authority;
  and
- conflicting replacement plans, corrupt/private-file violations, changed host
  identity, canceled recovery, and refusal to replace an expired pinned plan.

`go test -race ./src/orchestrator/controltransition ./src/orchestrator/nodeauthority`
passed. `make check` passed formatting, vet, build, and all portable race tests.
The full output is retained in `storage-transition-portable-2026-09-05.txt`.

`FuzzVerifyPlan` ran with a valid signed seed and malformed seeds for ten seconds
with two workers. It completed 1,240 executions without failure. Output is in
`storage-transition-fuzz-2026-09-05.txt`. This is bounded fuzz evidence, not an
exhaustive parser or cryptographic audit.

The journal tests invoke trusted `EpochStore` APIs with fixture admission and
command authorization. They do not exercise external plan delivery, the original
bootstrap-key reader, or a complete signed host-command transport. Inspection of
`hostagent.applyManifest` confirms that future source pin admission must occur
before `RetireForReplacement`; the handler currently retires R1 before recording
the replacement manifest. That composition has not been changed here.

The new pin is agreement evidence only. No preparation receipt or storage effect
is enabled, and no existing permission, epoch admission, election, or initial
retirement guard is weakened. Phase journals, signed chained receipts, trusted
plan delivery, and pre-NATS recovery remain required before a transition executor
can use it. Engine membership and real guest readiness remain unresolved; this
change supplies no new VM or production-readiness evidence.
