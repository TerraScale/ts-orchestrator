# Rotation and deletion inventory verification

`GOFLAGS=-p=4 make check` passed at source
`bd33c57ebbd99a1c1d42228ecce4cc939daceb7a`, with a clean source worktree.
The gate ran formatting, vet, build, and the complete uncached race suite.

Service-identity delivery now consumes the durable rotation roster and checks
every recipient against the independently configured host inventory before
sending secrets. Enrollment validates that inventory before changing the
journal. Production construction supplies its bootstrap roster and no longer
reads the coordinator's CAS session as a separate trust source. Astra review
confirmed the constructor and authorization fixes after correction.

Deletion inventory now reports `preparing`, `stopping`, `edge_pending`, and
`cleanup_pending`. A regression verifies that beginning deletion changes the
inventory revision immediately, before any host preparation receipt. Astra
review identified that earlier gap. The corrected fixtures retain production
preparation ordering, all three encryption key purposes, valid placement
targets, and quorum readiness after NATS restart.

This is portable verification. Host admission and withdrawal still need to
call rotation enrollment and retirement through the authoritative lifecycle.
The configured trusted inventory currently requires controller reconstruction
to admit newly provisioned endpoints. Production composition, guest fault
qualification, real-provider rotation, and launch gates remain unfinished.
