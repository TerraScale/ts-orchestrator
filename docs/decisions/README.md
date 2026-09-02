# Phase 0 owner decision and SLO packet

> Historical decision packet. The 2026-08-29 workspace `GOAL.md` supersedes
> choices that require permanent TerraBase R3, Project-level Region placement,
> standalone Platform or Authentication workloads, mandatory product NATS, or
> the old service catalog. The machine-readable packet remains intact as
> evidence of what was accepted in July.

See also the consolidated documentation index in [`../README.md`](../README.md).

Status: owner choices 1A–10A accepted on 2026-07-16 with reliability first; measurable targets and later implementation selections remain pending.

The machine-readable packet is `owner-decision-packet.json`. Its validator binds each decision to the exact table row in `docs/architecture/orchestrator.md`, including Markdown semantics, source line, and SHA-256 over the four cells joined by ASCII unit separator. The recorded `answer` must match the explicit owner response; the `recommended` field is historical decision context only.

## Owner questions (exact source text)

| # | Question | A — selected | B |
|---|---|---|---|
| 1 | Regional control topology | Three controller candidates plus three control-NATS servers in **each** region: 9 of each across GRU/SFO/FRA, with independent regional JetStream R3 consensus | Three total controllers/NATS servers, one per region; this creates a WAN quorum and requires rewriting the regional-autonomy invariants |
| 2 | GRU/WAN outage deployments | Regions keep serving, healing, replacing/scaling nodes, expanding storage, and renewing existing identities; freeze new global releases/policy changes | Allow each isolated region to accept independent releases/policy changes |
| 3 | Vault authority | Built-in policy/PKI/lease/rotation service with ciphertext/root protection in OCI Vault/KMS initially | Store envelope-encrypted authoritative ciphertext in a dedicated, isolated vault JetStream account/stream from v1; never ordinary subjects or plaintext |
| 4 | Runtime defaults | Native systemd for TerraBase; containers for Platform/Auth/Dashboard initially; both supported where useful | Choose a different default split |
| 5 | Elastic data cleanup | Never shrink; retain permanent disks; quarantine a removed elastic TerraBase disk for 7 days after verified backup | Immediately delete explicitly disposable elastic disks after safe topology removal |
| 6 | Provider implementation timing | Finish OCI plus a provider-neutral contract first; OCI's catalog must expose at least 20 usable regions, while GRU/SFO/FRA are the first activated/qualified cells; add another adapter when needed | Require a second complete cloud adapter before the first production deployment |
| 7 | CI/CD bootstrap exception | Keep one minimal independent Forgejo workflow/runner solely to build and recover the orchestrator; all product CI/CD is orchestrator-native | Require even orchestrator recovery CI to run inside the orchestrator, accepting the circular outage dependency |
| 8 | “Dedicated NATS” meaning | Dedicated means independent clusters/processes/security/cgroups/stores; both planes may share benchmarked compact-profile hosts | “Dedicated” meant separate physical compute nodes for control NATS and product NATS, increasing the regional floor |
| 9 | Telemetry during long GRU outage | Export all three OTel signals, spool to a fixed encrypted disk budget, then drop oldest/sample with explicit data-loss alerts; product traffic never blocks | Never drop telemetry, requiring another durable regional telemetry store and an explicit maximum outage/cost design |
| 10 | Container count during autoscaling tests | Nine seed node containers are the exact steady-state topology; explicit tests may add temporary `*-elastic-*` containers and must converge back to 3/cell | Nine is a hard ceiling; replacement can be tested, but real scale-out beyond three cannot be demonstrated in the full-region lab |

## Readiness boundary

Questions 1–10 are resolved as A. Cost, per-member storage performance/latency, regional RPO/RTO, security, memory/density, audit retention, and maximum disconnected regional-survival targets remain null until Phase 0 evidence supports honest values. They block the affected deployment and production qualification gates, while pure contracts model them as explicit inputs.

Team size and desired first-production date are Phase 0 planning inputs requested “when available”; they are not falsely promoted to architecture choices. Artifact/evidence signing, DNS, VPN, operator identity provider, regional artifact mirror, ARM64 host image, and NATS N/N-1 policy are explicitly segregated as later Phase 0 implementation selections. They remain null and do not masquerade as answers to the owner questions.

The ADR mappings use the canonical 1–24 IDs from `docs/architecture/orchestrator.md:1681-1704` and match the Phase 0 readiness map. Gate labels name the specification’s contract freeze, Phase 0 exit, and acceptance layers; they indicate downstream impact, not evidence that a gate passed.

## Recorded owner response

The explicit response governing this packet is:

```text
all A; reliability first
```

Unknown numeric values are filled only from approved evidence. Until then, cost policy may stop non-safety growth but cannot reduce availability, durability, backup, storage-integrity, or security floors.

## Validation

```text
go run ./tools/orchestrator-tooling owner-decisions
go run ./tools/orchestrator-tooling test
go run ./tools/orchestrator-tooling json-format docs/decisions/owner-decision-packet.json
git diff --check
```

The adversarial fixtures prove rejection of decision drift, a missing question, an invalid option, a changed unit, exact specification semantic drift, and accidental selection of a later implementation dependency.
