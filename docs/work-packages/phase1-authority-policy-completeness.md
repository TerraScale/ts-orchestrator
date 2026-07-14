# Phase 1 authority policy completeness shard

## Base and scope

- Base: central `chore/phase0-bootstrap` after reviewed provider and delivery integration.
- Production scope: `src/TerraScale.Orchestrator.ControlPlane/Authority/AuthorityEngine.cs`.
- Evidence scope: `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/AuthorityPolicyCompletenessPropertyTests.cs` and the matching handoff.

## Goal

Prove that replay cannot regress below already persisted epoch or KV-revision
truth and that a completed request identity cannot start an authority action whose
result handling would necessarily treat it as an old duplicate. Preserve the
existing status, identity, structural-validation, lease, recovery, renewal,
release, and read precedence.

The deterministic shard independently covers epoch-only, revision-only, and
combined replay regressions; exact high-water equality; independent monotonic
advancement; structural-error precedence; all four initiating commands; exact
fresh intents/events; the closed authority vocabulary; and culture-stable
decisions.

## Evidence boundary

This is bounded pure-decision evidence. It performs no NATS, clock, filesystem,
network, process, cloud/provider, VM, deployment, or sibling-repository action.
It does not claim full-domain 100,000-case evidence, mutation coverage, L0/L0C,
adapter conformance, deployment qualification, or production authority.
