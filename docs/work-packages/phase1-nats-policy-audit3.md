# Phase 1 NATS policy accepted-observation audit 3

## Boundary

- Audit the pure Messaging/NATS replacement decision and its typed observation intent.
- Prove that an accepted observation request retains the exact replacement operation that authorized it.
- Preserve existing validation, error and trace catalogs, precedence, numeric boundaries, and replacement progression.
- Perform no NATS, network, process, credential, filesystem-administration, VM, cloud, or deployment operation.

## Proven counterexample

Two otherwise valid replacement operations could share operation ID, cluster, and observation sequence bounds but
carry different authority epochs. Both were accepted, yet both emitted an equal `ObserveClusterIntent` because the
intent retained only those four shared projections. Operation generation, plane, cell, authority epoch,
configuration generation, failed-store identity and generation, failed and replacement peer identities, and
replacement placement were discarded at the executable boundary.

The collision applied both to the initial observation request and to the re-observation branch for an active
surviving-store attachment whose membership or replica view remained incomplete.

## Required correction

- `ObserveClusterIntent` retains the exact accepted `ReplacementOperation` as `Replacement`.
- Existing `Operation`, `Cluster`, `MinimumSequence`, and `MaximumSequence` members remain derived projections for
  consumers of the previous surface.
- Identical semantic replay remains equal; substituting any retained replacement-operation field produces a
  distinct output and canonical replay fingerprint.
- The output remains construction-closed and can be produced only by the pure policy engine.

## Evidence

- Pin the exact retained replacement reference and every replacement-operation field.
- Prove the original authority-epoch collision and sensitivity to every other retained field.
- Cover initial observation and surviving-store re-observation, including observation-order permutation.
- Prove invariant canonical fingerprints across cultures and update every Messaging replay serializer that handles
  the observation intent.
- Preserve holds, rejected/default inputs, no-intent completion, trace order, and all unrelated decisions.

## Nonclaims

The correction binds accepted replacement-operation provenance only. It does not retain or authenticate a cluster
observation, surviving-store proof, rejected evidence, response, NATS server, or complete selection/authorization
context. It does not verify response authenticity or qualify NATS/JetStream behavior. The planned real-NATS L0C
inventory remains unexecuted and supplies no acceptance evidence.
