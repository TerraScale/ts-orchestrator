# Phase 1 scheduler deterministic property/replay shard

## Goal

Exercise the existing scheduler and availability pure cores with deterministic generated valid and invalid inputs. This shard is scheduler-only test evidence; it does not change production behavior or select a property-testing package.

## Scope

- `DeterministicScheduler.Schedule`, all placement hard constraints, least-waste ranking, and the public constructors/checked arithmetic that validate scheduler inputs.
- `AvailabilityPolicyEvaluator.Evaluate`, placement/maintenance/drain evidence gates, quorum/minimum/disruption/topology/anti-affinity/reserve rules, and all availability input validators.
- Explicit deterministic seed ranges with at least 1,000 generated cases per property.
- A strict, bounded, content-addressed embedded JSON replay corpus containing minimal adversarial seeds for hard constraints, caller safety holds, availability floors, conflicting evidence, and reserve boundaries.

## Required properties

- Identical decisions and traces across replay, candidate/observation permutation, and `tr-TR`/`ar-SA` cultures.
- Checked resource and availability-count conservation, exact remaining capacity, and overflow/underflow rejection.
- Capacity, architecture, node class, labels, trust/network/secret zones, failure-domain, affinity, anti-affinity, ports, safety-cap, and caller-veto enforcement, with a scalar/BigInteger weighted-score/tuple oracle independent of production subtraction and explicit ordinal identity ties.
- Minimum availability, quorum, disruption budget, one-per-host, distinct failure-domain, and per-resource reserve enforcement.
- Incomplete, duplicate, or conflicting availability evidence holds before policy arithmetic. The placement core has no generation/epoch input; stateful stale/fencing rejection is therefore asserted only through its explicit closed caller veto boundary.
- Non-vacuous invalid-generator distribution across every enumerated validation family and every hard-constraint family.
- Construction-closed availability decisions/reasons and closed observable enum values.

## Boundaries

No filesystem, network, process, cloud, environment, wall clock, global randomness, or external property package is permitted. Seed generation is a small deterministic local sequence and corpus entries are fixed embedded resources.

The audit found unbounded caller enumeration in placement candidates, availability observations, and nested scheduler facts/ports/labels/score dimensions. The narrowly expanded production change adds shared maximum-plus-one technical snapshots with named public limits. These are denial-of-service/input-safety bounds, not business placement, replica, or allocation caps.

This feature shard does not claim full-domain property coverage, a full L0/L0C run, 100,000 full-lane cases, mutation score, fuzzing, model exploration, or deployment authority.
