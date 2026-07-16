# TerraScale.Orchestrator

TerraScale.Orchestrator is the greenfield, TerraScale-specific control plane described in [ORCHESTRATOR.md](ORCHESTRATOR.md). The repository is executing Phase 0 evidence work and pure Phase 1 contract tranches in parallel, without deployment authority.

Owner choices 1A–10A are accepted with reliability first. Numeric cost, database-storage, RPO, and RTO targets remain evidence-derived deployment gates; they do not justify weakening R3 state, single-node-failure tolerance, backups, storage integrity, or security. The repository must not start a system-under-test VM or mutate cloud infrastructure before exact-tree L0/L0C evidence authorizes it.

## Baseline validation

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

All repository validators, generators, audit utilities, conformance checks, and
their tests are implemented in C#. The dependency-free tooling executable
replaces the former Python scripts and exposes named commands for each domain:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- adr-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- nats-readiness
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- supply-chain
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-validate
```

Run the executable without arguments to list every command. The translated
test suite also fails if a Python source file is reintroduced.

The repository produces one operational Orchestrator binary, a dependency-free policy/evidence tool, and a test executable. The `check` command exercises the production controller startup path against a real JetStream-enabled NATS server, then exits cleanly. The `lab` command is the native development adapter used by DevHost; it does not weaken or replace the SmolVM production-parity lab.

## Run

The orchestrator requires NATS with JetStream enabled. `check` reconciles the regional control resources, verifies the NATS service endpoint through request/reply, and exits. `run` performs the same checks and keeps the discoverable service online until shutdown.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
dotnet run --project src/TerraScale.Orchestrator -- check

dotnet run --project src/TerraScale.Orchestrator -- run

dotnet run --project src/TerraScale.Orchestrator -- \
  operator status --cell gru --nats-url nats://127.0.0.1:4222 \
  --nkey-file /run/credentials/terrascale/operator-read.nk \
  --tls-ca-file /run/credentials/terrascale/ca.pem \
  --tls-cert-file /run/credentials/terrascale/operator.pem \
  --tls-key-file /run/credentials/terrascale/operator.key.pem
```

`operator status` is a read-only NATS request/reply operation. The regional
service validates and returns its cell, controller instance, R3 configuration,
exact build, start/observation times, and implemented capability inventory.
It also reports the current regional authority state, fencing epoch, KV
revision, and lease expiry. The CLI rejects a response from another cell, an
expired lease, contradictory leader state, or an invalid/unready projection.
The optional `--nkey-file` (or `TS_ORCH_NATS_NKEY_FILE`) must be an existing,
bounded owner-private seed file; raw key material is never accepted on the
command line.
The TLS CA, certificate, and key options (or matching
`TS_ORCH_NATS_TLS_*_FILE` variables) are atomic: all three must be present,
the PEM identity must match its owner-private key, and TLS is required rather
than opportunistically negotiated.

Use `TS_ORCH_REPLICAS=3` with a production regional NATS cluster. Startup reconciles the `CELL_SPEC`, `CELL_OPERATIONS`, and `CELL_EVENTS` file-backed JetStream streams, the `ORCH_LEADERS` and `ORCH_RUNTIME` KV buckets, the `CELL_BUNDLES` Object Store, and the cell-scoped NATS health service. It writes and reads the versioned protocol package through Object Store, whose retrieval verifies the stored digest, before accepting the bytes. Runtime registration is revision-fenced: startup creates and watches a unique `starting` entry, compares-and-swaps it to `ready`, observes that revision, and conditionally deletes it during shutdown. The health endpoint is distributed through a cell queue group; readiness verifies its standard NATS service discovery metadata and request statistics. The orchestrator also publishes a deduplicated startup event with protocol/cell/correlation headers, receives it through a bounded durable pull consumer, validates the metadata, and explicitly acknowledges delivery.

The three regional controller candidates share one NATS service queue group
and contend for one `ORCH_LEADERS` lease using exact KV compare-and-set
revisions. The production authority state machine advances the fencing epoch,
binds the lease identity, and grants a mutation permit only to the exact CAS
winner. Followers remain available for read-only operator traffic. The winner
renews every three seconds with a fifteen-second lease; a renewal conflict or
uncertain authority result fences the candidate and terminates it for an
external supervisor restart. DevHost exercises this election on each real R3
cell, but its single-host clock/loopback transport is development evidence and
does not replace the real multi-host clock, partition, mTLS, and NATS-JWT gates.

## DevHost three-cell profile

`lab plan` is a pure operation and prints the fixed `devhost-three-cell-r3` topology. It contains GRU, SFO, and FRA cells. Every cell has three Orchestrator controllers, three control-plane NATS members, three product-plane NATS members, three TerraBase members, Authentication, API, and Dashboard. Email and Stripe emulators are shared development fixtures.

```bash
dotnet run --project src/TerraScale.Orchestrator -- lab plan
dotnet run --project src/TerraScale.Orchestrator -- lab status \
  --state-file "$HOME/.local/share/terrascale-devhost/orchestrator/state.json"
```

`lab up` is intentionally fail-closed. DevHost first invokes `development-attest`, which requires a clean Orchestrator checkout, runs the solution and policy test suites, and writes short-lived evidence outside the repository for the exact source commit and executable assembly. Only then can the Orchestrator start workload processes or mutate persistent lab state.

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- \
  development-attest \
  --output /tmp/terrascale-orchestrator-evidence.json \
  --binary src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator

src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator \
  lab up \
  --workspace /workspaces/TerraScale \
  --data-directory "$HOME/.local/share/terrascale-orchestrator/devhost" \
  --evidence /tmp/terrascale-orchestrator-evidence.json \
  --watch
```

The native adapter persists independent control NATS, product NATS, TerraBase, and backup data per cell. It publishes atomic resource and endpoint projections for DevHost. Killing the foreground Orchestrator tears down its entire child process tree; persisted data remains for the next generation.

DevHost creates stable, owner-private credentials beneath its Orchestrator data
directory. Every controller has a distinct NKey identity, and each cell has a
separate read-only operator NKey that can request only regional status and
receive its inbox reply. Control NATS denies anonymous clients; every
controller proves that denial during startup before advertising the
`nats-nkey-authenticated` capability. Product NATS uses an independent random
per-cell username/password consumed by the existing product queue client.
Control and product planes have separate development PKI roots, one regional
intermediate per cell, SPIFFE-like leaf identities, mandatory client mTLS, and
separate server/route certificates. NATS configuration files are mode `0600`,
contain public controller/operator NKeys but never their seeds, and are
isolated from product credentials. This closes anonymous DevHost messaging and
intra-cell plaintext transport; NATS operator/account JWTs, cross-cell gateway
mTLS, and rotation/revocation remain separate production qualification gates.

After startup, Orchestrator continuously probes every planned process and its
role-specific health surface: NATS client ports, TerraBase HTTP and native TCP,
Authentication/API readiness, regional Dashboard stack views, and emulator
readiness. A failed probe is projected as degraded immediately; three
consecutive unhealthy observations fail the foreground generation so DevHost
can re-attest and recover the graph.

Every DevHost state projection is also evaluated by the production typed
reconciliation engine. The graph is not accepted as ready unless all 47
allowlisted resources have exact generation/digest observations and converge
in dependency order. Startup progress is written to the resource-state file,
but the endpoint map used for DevHost cutover is withheld until one complete
health pass—including each controller's instance-specific authority endpoint—
and 47/47 typed convergence succeed. This prevents a starting generation from
being mistaken for a deployable candidate.

## Nine-machine SmolVM profile

The deployment-shaped `regions-smol` profile owns exactly three persistent
seed machines in each of GRU, SFO, and FRA. It requires commit-bound evidence,
the verified v1.5.0 installation closure, an immutable base artifact and digest,
an explicit egress scope, and a short private runtime data root. Each reconcile
executes `/bin/true` inside every guest before reporting it ready.

When the lab is hosted by systemd, `KillMode=mixed` is required so the stop
signal reaches the Orchestrator first while its child SmolVM API remains alive
for deterministic machine deletion. The remaining cgroup is reaped after the
Orchestrator exits:

```bash
systemd-run --user --unit=terrascale-regions-smol --collect \
  --property=Type=exec --property=KillMode=mixed \
  --property=KillSignal=SIGINT --property=TimeoutStopSec=180s \
  --property=Restart=no -- \
  terrascale-orchestrator lab up --profile regions-smol \
  --workspace /workspaces/TerraScale --data-directory /var/tmp/ts-smol-state \
  --smolvm-installation /opt/terrascale/smolvm/v1.5.0 \
  --base-artifact /opt/terrascale/testlab/base.smolmachine \
  --base-digest <sha256> --socket /run/user/1000/ts-regions-smol.sock \
  --smolvm-data-root /var/tmp/ts-smol-regions \
  --allowed-cidrs 10.0.0.0/8 --evidence /var/tmp/regions-smol-evidence.json
```

Landlock enforcement is the qualifying default. Disabling it requires the
explicit `--allow-unqualified-smolvm-host` acknowledgement and is recorded as
a host-hardening gap rather than production-parity evidence.

## Closed production role catalog

The executable exposes the exhaustive v1 production role catalog as JSON:

```bash
src/TerraScale.Orchestrator/bin/Debug/net10.0/linux-x64/terrascale-orchestrator catalog
```

All production-shaped DevHost resources project to one of these built-in
descriptors. API, Authentication, and Dashboard retain the production OCI
default; TerraBase, both NATS planes, and Orchestrator retain their native
systemd defaults. Email and Stripe emulators are explicitly development-only
fixtures and cannot be admitted as production workloads.

`runtime plan` resolves a role and artifact digest through that catalog into a
typed host execution plan. It never accepts an executable path, image
repository, unit directive, host path, capability, privileged flag, or secret:

```bash
terrascale-orchestrator runtime plan \
  --role api \
  --allocation gru-api-1 \
  --digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Native plans derive an immutable artifact path and hardened systemd
properties. OCI plans derive a digest-pinned internal-registry reference,
non-root identity, read-only root filesystem, no-new-privileges policy,
drop-all capabilities, seccomp profile, cgroup, and resource ceiling. Plan
generation is pure; applying it remains fail-closed until the selected
systemd/containerd host adapter and its pinned runtime are qualified.
