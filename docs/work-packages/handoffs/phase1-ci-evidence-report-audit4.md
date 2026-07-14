# Phase 1 CI evidence report accepted-output audit 4 handoff

## Proven gap and correction

Two otherwise accepted gate calls could supply different well-formed evidence subjects, matching expected-subject contexts, and the same claimed payload digest. Both passed policy and signature verification, yet their decisions compared equal because `EvidenceDecisionSubject` retained only that digest.

Accepted decision subjects now also retain the exact validated `EvidenceSubject` reference. Their value equality uses the digest plus the subject's existing canonical structural comparison; their hash remains digest-based. This preserves equality for independent exact reconstructions and canonical collection permutations while distinguishing a same-digest report whose accepted content differs. The subject remains construction-closed, getter-only, opaque in string formatting, and available only through the accepted decision. `PreDeploymentEvidenceGate.Verify` remains the sole public engine origin. Holds still carry no subject.

## Proof coverage

- The original executable counterexample varies the accepted tree identity while holding the claimed digest and authorization scope constant.
- Independent accepted variants cover every report leaf with an admissible distinct accepted value, including IDs, digests, architecture assignment, suite and trace counts, fuzz evidence, model corpora, L0C, toolchain, approver, content-reuse fingerprints/change, exclusions, and collection counts.
- Result leaves that have only one accepted value are exercised by the accepted baseline and gate-policy suite; changing them necessarily produces a hold and therefore cannot form an accepted-output collision.
- Exact independently reconstructed reports replay equally across Turkish, Arabic, and Japanese cultures.
- Two-entry permutations cover every report collection, including the paired suite/model domain inventory. Mutation of every caller-owned source array after construction cannot alter the retained report.
- Reflection pins public decision, decision-subject, authorization-scope, numeric-trace, evidence-subject, and collection-projection routes; immutable record clones and accessors are explicit, and no public decision-subject constructor, setter, deconstructor, clone, or alternate factory exists.

## Verification

- Focused audit tests: 3/3 passed.
- Evidence-prefixed tests: 21/21 passed.
- Accepted-output construction-closure tests: 2/2 passed.
- Release solution build: passed with zero warnings and errors.
- All five test executables: 878/878 passed (ControlPlane 651, Contract 29, Model 44, Protocol 70, Scheduler 84).

## Honest boundary

The retained report is exact accepted in-memory evidence, not proof that the caller's canonical digest was independently recomputed, that any artifact or suite actually ran, or that a signer, verifier, CI runner, credential release, deployment, or production environment is qualified. Policy objects, verifier implementation identity, and opaque signature bytes remain outside this audit. No external I/O or mutation occurs.
