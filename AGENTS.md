# TerraScale.Orchestrator agent rules

Read the workspace `../GOAL.md`, root `../AGENTS.md`, and
`docs/architecture/orchestrator.md` before changing architecture or
production behavior.

## Ownership

Orchestrator owns:

- Region and host lifecycle;
- workload scheduling and failure-domain spread;
- TerraBase Member and replica identity allocation;
- customer placement intent and capacity admission;
- certificates, workload identity, trust bundles, and rotation;
- repair and rebalance orchestration;
- Dashboard and Database API global deployment;
- immutable delivery, candidate admission, and promotion;
- cloud and storage-provider integration;
- internal observability infrastructure; and
- optional NATS infrastructure.

It does not own:

- database mutations, CRDT merge, causal progress, membership acceptance,
  replication, anti-entropy, reactive sync, or usage accounting;
- Better Auth, Organizations, Projects, Users, Payments, entitlements, or MCP
  product policy;
- public SDK behavior; or
- a customer data proxy.

## Product workloads

- Dashboard is one full-stack Vinext TypeScript project. It owns Better Auth,
  Organizations, Projects, Users, Payments, Streamable HTTP MCP, and customer
  workflows.
- `TerraScale.Database` is an independent C#/.NET 10 ASP.NET Core service and
  sole QUIC TBEP gateway.
- TerraBaseV2 is the private Rust engine.
- Dashboard and Database API deploy in every available production Region with
  at least two instances of each across independent failure domains.
- The Dashboard system Project uses `all-available-regions`, immutable backup,
  PITR, reserved capacity, and `GlobalDurable` for critical state.
- The standalone Authentication, Payments, Platform, and
  `TerraScale.MCP` workloads are removed after direct cutover qualification.

Dashboard uses `@terrascale/sdk` and public TerraScale APIs exactly like a
customer Project. Orchestrator cannot grant it a direct TerraBase path,
Dashboard-only database route, special header, tenant bypass, or private SDK.

## TerraBase placement

- A customer database selects one through twenty active Regions, initially GRU,
  SFO, and FRA.
- Every selected active Region stores every logical Partition and is writable.
- Production seats two active Members per Region and Partition.
  `RegionalDurable` requires both.
- Backup is an independent optional read-only, non-voting copy.
- A database starts with one logical Partition. TerraBase splits and merges by
  measured engine need.
- Orchestrator schedules accepted placement but cannot appoint a data leader,
  owner, primary, or permanent coordinator.
- Membership changes use TerraBase's durable overlapping epoch protocol.
  Control-plane intent or lease expiry alone cannot grant a vote or retire a
  causal actor.

NATS may advertise accepted configuration or discovery. It never carries
database data and never decides commit, membership, replication, repair,
reactive sync, usage, or billing correctness.

## Region catalog admission

A Region cannot enter the customer catalog until it has:

- admitted hosts and failure domains;
- Dashboard and Database API instances;
- system Project TerraBase replicas caught up and Merkle verified;
- workload identity and rotated trust;
- public and strict routing;
- Better Auth and Database API authorization;
- TerraBase replication and recovery;
- observability and capacity protection; and
- exact failure and restore receipts.

Catalog admission requires explicit policy and owner authorization until the
workspace owner accepts a fully automatic publication rule. Discovery alone
cannot publish a Region.

Removing a Region fences routing, drains sessions, completes data-retention and
deletion obligations, retires replica actors, and records receipts.

## Bootstrap trust

Orchestrator provisions fixed Dashboard system Organization, Project, and
database identities, a short-lived X.509 workload identity, a local rotated
trust bundle, and a signed `BootstrapGrant`.

The grant is:

- certificate-bound and audience-bound;
- short-lived and replay-protected;
- limited to idempotent operations on fixed system Project identities;
- unusable for customer Projects; and
- audited.

Steady-state Dashboard uses a rotated ordinary workload credential through the
public SDK. Bootstrap is not a permanent root path.

## DevHost and validation limits

- Local development always uses GRU/SFO/FRA RF=1. Do not add profile switches
  or reduced topologies.
- RF=1 results prove regional routing and convergence only. They do not prove
  production quorum, host loss, systemd, cloud, or destructive storage.
- Preserve fixed public tailnet ports `18445` for Dashboard-owned Better Auth
  and `18446` for Dashboard.
- The new Database API needs one fixed tailnet and loopback route recorded
  atomically across DevHost, Orchestrator, root instructions, SDKs, and docs.
  Do not invent a floating port.
- Keep local container and test work at or below 24 GiB RAM, reserving 4 GiB
  for host and tools. Owned lab processes may use at most 20 GiB.
- Run test executables sequentially with bounded TUnit parallelism. Do not run
  two labs or a lab and test module concurrently.
- Hold the repository validation lease for environment-affecting evidence. Do
  not edit the checkout while the lease is held.

## Architecture rules

- Pure decisions and contracts do not depend on NATS, OCI, D-Bus, containerd,
  filesystems, sockets, environment variables, or wall-clock APIs.
- Adapters translate typed persisted intent and observation. Business policy
  does not hide in infrastructure adapters.
- No arbitrary workload kind, executable path, unit text, privileged
  container, host path, secret, or cloud ownership may be inferred from tags.
- Existing serving Regions continue database reads, writes, and replication if
  Orchestrator or NATS is unavailable.
- Autoscaling is not a noisy-neighbor safety mechanism. TerraBase and Database
  API enforce admission and backpressure before capacity arrives.
- Dashboard Payments uses the official Better Auth Stripe plugin. Orchestrator
  binds secret references and workload configuration only. It does not own a
  payment provider or state machine.
- Dashboard Streamable HTTP MCP replaces the first-party MCP workload. Remove
  old workload and deployment references only after replacement receipts pass.

## Quality and security

- Build with warnings as errors and nullable enabled.
- Keep requirement, invariant, error, state-machine, and security IDs stable.
- Never emit secrets, private keys, cookies, tokens, payment data, customer
  content, or raw provider responses to Git, NATS, logs, traces, metrics, tests,
  fixtures, or reports.
- A live provider, cloud, deployment, or destructive-storage action requires
  explicit user authority and an exact target-scoped lease.
- Release evidence binds source revision, owned paths, immutable artifact and
  configuration identity, test result, lease outcome, and known gaps.

## Git

- Work directly on `develop`. Fetch and fast-forward before the first write.
- Claim exact paths, inspect status before every write and stage, and preserve
  unrelated changes.
- Stage named paths only.
- Commit coherent work often and push to `origin/develop` after a final fetch.
- Do not create feature branches, worktrees, pull requests, releases,
  deployments, or sibling-repository edits unless explicitly requested.

## Agent skills

See `docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`, and
`docs/agents/domain.md`.
