# Phase 0 owner decision and SLO packet

Status: awaiting explicit owner input; no recommendation, answer, target, or implementation selection has been accepted.

The machine-readable packet is `owner-decision-packet.json`. Its validator binds each question to the exact table row in `ORCHESTRATOR.md`, including Markdown semantics, source line, and SHA-256 over the four cells joined by ASCII unit separator. The `recommended` field records which source column is labelled recommended; it never supplies `answer`.

## Owner questions (exact source text)

| # | Question | A — recommended | B |
|---|---|---|---|
| 1 | Regional control topology | Three controller candidates plus three control-NATS servers in **each** region: 9 of each across GRU/SFO/FRA, with independent regional JetStream R3 consensus | Three total controllers/NATS servers, one per region; this creates a WAN quorum and requires rewriting the regional-autonomy invariants |
| 2 | GRU/WAN outage deployments | Regions keep serving, healing, replacing/scaling nodes, expanding storage, and renewing existing identities; freeze new global releases/policy changes | Allow each isolated region to accept independent releases/policy changes |
| 3 | Vault authority | Built-in policy/PKI/lease/rotation service with ciphertext/root protection in OCI Vault/KMS initially | Store envelope-encrypted authoritative ciphertext in a dedicated, isolated vault JetStream account/stream from v1; never ordinary subjects or plaintext |
| 4 | Runtime defaults | Native systemd for TerraBase; containers for API/Auth/Dashboard initially; both supported where useful | Choose a different default split |
| 5 | Elastic data cleanup | Never shrink; retain permanent disks; quarantine a removed elastic TerraBase disk for 7 days after verified backup | Immediately delete explicitly disposable elastic disks after safe topology removal |
| 6 | Provider implementation timing | Finish OCI plus a provider-neutral contract first; OCI's catalog must expose at least 20 usable regions, while GRU/SFO/FRA are the first activated/qualified cells; add another adapter when needed | Require a second complete cloud adapter before the first production deployment |
| 7 | CI/CD bootstrap exception | Keep one minimal independent Forgejo workflow/runner solely to build and recover the orchestrator; all product CI/CD is orchestrator-native | Require even orchestrator recovery CI to run inside the orchestrator, accepting the circular outage dependency |
| 8 | “Dedicated NATS” meaning | Dedicated means independent clusters/processes/security/cgroups/stores; both planes may share benchmarked compact-profile hosts | “Dedicated” meant separate physical compute nodes for control NATS and product NATS, increasing the regional floor |
| 9 | Telemetry during long GRU outage | Export all three OTel signals, spool to a fixed encrypted disk budget, then drop oldest/sample with explicit data-loss alerts; product traffic never blocks | Never drop telemetry, requiring another durable regional telemetry store and an explicit maximum outage/cost design |
| 10 | SmolVM count during autoscaling tests | Nine seed VMs is the exact steady-state topology; explicit tests may add temporary `*-elastic-*` SmolVMs and must converge back to 3/cell | Nine is a hard ceiling; replacement can be tested, but real scale-out beyond three cannot be demonstrated in the full-region lab |

## Readiness boundary

Questions 1–10 require explicit A/B owner answers before contract freeze. Cost, per-member storage performance/latency, regional RPO/RTO, security, memory/density, audit retention, and maximum disconnected regional-survival targets also block the affected contract/ADR tranche. Their exact units and validation constraints are in the packet, and every value is null.

Team size and desired first-production date are Phase 0 planning inputs requested “when available”; they are not falsely promoted to architecture choices. Artifact/evidence signing, DNS, VPN, operator identity provider, regional artifact mirror, ARM64 host image, and NATS N/N-1 policy are explicitly segregated as later Phase 0 implementation selections. They remain null and do not masquerade as answers to the owner questions.

The ADR mappings use the canonical 1–24 IDs from `ORCHESTRATOR.md:1709-1732` and match the Phase 0 readiness map. Gate labels name the specification’s contract freeze, Phase 0 exit, and acceptance layers; they indicate downstream impact, not evidence that a gate passed.

## Compact owner response

Replace every `_` for which a value is approved; leave unknown values as `_`. Do not use `all A` unless that is an intentional answer to every question after reviewing each option.

```text
1=_ 2=_ 3=_ 4=_ 5=_ 6=_ 7=_ 8=_ 9=_ 10=_; team-size=_ people; first-production-date=_; maximum-cost=_ BRL/day; storage-iops=_ IOPS; storage-throughput=_ MiB/s; storage-read-p95=_ ms; storage-read-p99=_ ms; storage-write-p95=_ ms; storage-write-p99=_ ms; regional-rpo=_ seconds; regional-rto=_ minutes; security-revocation=_ seconds; certificate-ttl=_ hours; certificate-renewal-lead=_ hours; break-glass-ttl=_ minutes; security-critical-remediation=_ hours; orchestrator-rss=_ MiB; compact-post-failure-utilization=_ percent; audit-hot-retention=_ days; audit-immutable-retention=_ days; regional-survival=_ hours
```

## Validation

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- owner-decisions
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format docs/decisions/owner-decision-packet.json
git diff --check
```

The adversarial fixtures prove rejection of accidental recommendation defaulting, a missing question, an invalid option, a changed unit, exact specification semantic drift, and accidental selection of a later implementation dependency.
