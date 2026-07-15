# Phase 1 TerraBase accepted upgrade output audit 3 handoff

## Proven gap and correction

Two fully successful upgrades on the same evidence scope but with different exactly matched current and target releases produced equal `Verify / Release / Completed` decisions. The equivalent post-apply health-observation branch had the same collision. Both branches discarded the `TerraBaseUpgradeIntentSubject` already constructed after exact scope and release-pair validation.

The planner now reuses that same construction-closed subject for post-apply `Observe / Application / NextStep` and terminal `Verify / Release / Completed` outputs. Upgrade, rollback, rollback observation, and rollback completion already retained it. No input contract, enum numeric, action, target, code, trace, validation, or precedence changed, and all hold decisions remain subject-free.

Tests pin exact scope/current/target instances on both corrected branches, independent current and target inequality, identical replay equality and hash stability, subject-free holds, culture-stable 1,000-case output oracles, and deterministic release-pair fingerprinting.

## Honest boundary

This closes only accepted upgrade release-pair provenance. It does not authenticate application-health evidence, execute a TerraBase upgrade, qualify a TerraBase administrative API or runtime adapter, or provide VM, cloud, deployment, L3S, L4, or production evidence. No external I/O occurs.
