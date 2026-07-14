# Phase 1 snapshot policy completeness handoff

## Result

The audit found one accepted-output anti-rollback defect. `SnapshotSignedMaterial.Generation` was authenticated and copied into an authorizing restore plan, but validation had no current accepted generation and therefore accepted a lower state generation hidden behind a later signed stream position.

`SnapshotValidationContext` now requires `CurrentAcceptedGeneration`. Validation reports `GenerationRollback` only when the candidate generation is lower. Equal generation remains accepted when the stream position advances and all remaining gates pass. The deterministic precedence is epoch, stream position, generation, state digest, then signature after the pre-existing scope and schema gates. `GenerationRollback` is appended at numeric value 15, preserving every pre-existing validation-code value.

## Evidence

- The pre-fix focused regression failed because generation 2 produced a restore plan over accepted generation 3 at a later stream position.
- The paired regression proves equality is intentionally valid and asserts the exact restore plan.
- A 1,000-case independent oracle varies epoch, stream position, generation, digest, schema compatibility, and signature outcome. Every accepted case checks snapshot ID, generation, restored epoch, replay start, and digest exactly under four cultures and deterministic replay.
- Precedence tests prove compatibility and signature delegate call counts, exact schema arguments, and suppression at earlier denials.
- Catalog tests pin all three schema outcomes, both signature outcomes, 16 validation codes, four restore-plan codes, 11 material codes, invalid/default accepted generation, and construction-closed authorizing outputs.

## Deliberate limits

Snapshot generation is not required to advance for every new snapshot. A later journal checkpoint may retain the current state generation. The caller still owns canonical serialization, digest calculation, signature policy, schema compatibility, durable accepted baselines, snapshot content retrieval, replay execution, and atomic persistence.

No real signature, snapshot bytes, journal, NATS server, filesystem, process, network, cloud resource, VM, container, or deployment was exercised. This evidence does not claim L0/L0C completion, the required fuzz budget, mutation score, persistence correctness, or production qualification.
