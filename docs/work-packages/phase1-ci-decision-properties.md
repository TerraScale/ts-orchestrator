# Phase 1 CI trust-zone decision property shard

## Goal

Add deterministic property and replay evidence for the existing pure CI job scheduling decision in `DeliveryEngine.DecideJob`, with independent trust-policy, runner-selection, retry, and failure-precedence oracles.

## Allowed paths

- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/CiDecision*`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
- `docs/work-packages/phase1-ci-decision-properties.md`
- `docs/work-packages/handoffs/phase1-ci-decision-properties.md`

## Required evidence

- At least 1,000 explicit cases per property family.
- Closed job-kind/trust-zone/capability matrix independent of the production switch.
- Deterministic fresh compatible runner selection across permutations and cultures.
- Exact retry/attempt precedence and preservation of job, tree, generation, attempt, and idempotency identities.
- Duplicate, stale, unavailable, wrong-zone, and capability-missing runner evidence precedence.
- Strict byte-bounded whole-file-pinned replay with exact input-derived fingerprints.
- Construction-closed accepted decisions and intents.

## Exclusions

No runner process, Forgejo, Git, network, filesystem runtime, signing, secrets, package/tool selection, deployment, NATS, cloud/provider, or sibling repository changes. This shard is pure unit/property/replay evidence and cannot claim L0 or deployment qualification.
