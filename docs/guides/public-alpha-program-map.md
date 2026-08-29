# Public Alpha program map

> Historical snapshot. This issue map predates TerraBaseV2 native replication,
> the C# Database API, Dashboard-owned Better Auth and MCP, database-level
> Region selection, and removal of the standalone Auth, Payments, Platform,
> and MCP services. It does not define current ownership or launch readiness.

Forgejo issue `TerraScale.Orchestrator#2` is the cross-repository launch index.
Its child index covers 52 deliverables in 11 repositories. This snapshot makes
the ownership boundary reviewable without treating local code as proof that an
external launch gate passed.

| Repository | Child issues | Count | Launch responsibility |
| --- | --- | ---: | --- |
| TerraBase | #3–#6 | 4 | Engine runtime, mutations, consistency, replication, and conflict evidence |
| TerraBase.Benchmark | #1–#2 | 2 | Decision-grade performance and claim evidence |
| TerraScale.Deploy | #1–#3 | 3 | Immutable candidate, retained rollback bytes, and activation handoff |
| TerraScale.DevHost | #3–#4 | 2 | Local customer journey, isolation, metering, notifications, and monitoring |
| Terrascale.Documentation | #2–#6 | 5 | Product, API, legal, status, security, and support documentation |
| TerraScale.DotNet | #2–#4 | 3 | .NET 10 SDK contract, package, and live qualification |
| TerraScale.Internals | #5–#22 | 18 | Plans, identity, billing, routing, metering, residency, export, and launch journey |
| Terrascale.Landingpage | #2–#5 | 4 | Pricing, registration, availability claims, and canonical launch links |
| TerraScale.MCP | #1–#3 | 3 | Mutation parity, distribution, and live qualification |
| TerraScale.Orchestrator | #3–#7 | 5 | Global activation, customer gates, regional routing, receipts, and readiness |
| TerraScale.TypeScript | #2–#4 | 3 | Runtime support, regional APIs, package, and live qualification |
| **Total** |  | **52** |  |

## Orchestrator child coverage

| Issue | Enforced here | Evidence that must still come from outside this repository |
| --- | --- | --- |
| #3 | Immutable three-region prepare, one activation barrier, exact-target rollback, partial-progress convergence, durable receipt events | Production-shaped prepare, activation, restart, and rollback rehearsal |
| #4 | Pre- and post-activation health, error, latency, isolation, replication, billing, and customer-journey gates | Exact-candidate raw API, .NET, TypeScript, and MCP observations |
| #5 | Canonical global and strict endpoints, DNS/HTTP/TLS/certificate/freshness checks, regional identity, six regional tests, selected-region routing | External probes and live regional test reports |
| #6 | Candidate-bound evidence links, current and rollback identity, append-only events, redaction checks, compare-and-swap journal recovery | Receipt persistence in the deployed R3 journal and retention proof |
| #7 | Candidate-bound readiness evidence for restart, duplicate delivery, partition, stale metrics, expired credentials, provider failure, security, observability, operator surfaces, runbooks, soak, and audit closure | Production drill receipts, published customer surfaces, seven-day soak, and an audit with no launch blocker |

The readiness gate also carries the program-level publication, registration,
payment, regional rehearsal, customer journey, manual QA, and final audit
obligations from issue #2. A named final approval cannot override any failed or
missing technical evidence.

Forgejo remains authoritative for ticket state. Backup and recovery-region
design remains deferred by the parent issue.
