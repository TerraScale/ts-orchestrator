# ADR 0034: Auto-forming cells and leaderless host convergence

| | |
| --- | --- |
| Status | Partially superseded; historical design intent, not deployment evidence |
| Date | 2026-09-18 |
| Context | [ADR 0033](0033-gru-global-authority-and-regional-autonomy.md), the deploy path in `ControlPlane/Delivery`, `Runtime/AdmittedRoleCatalog` |

## Current implementation status — 2026-09-21

The startup and cached process-lifetime admission descriptions below are
historical. They do not prove automatic OCI cluster formation or authorize
deployment. `ts-infra` controls supported regions and the first GRU seed;
signed first boot, seed ownership handoff and regional resource reconciliation
remain open. Topology provisioning requires its separate infrastructure identity.
Host execution now requires renewing session authority, protected credential
expiry and local ownership/recovery; production host startup still needs
composition. Desired state, reports and artifact delivery use restricted signed
protocols. Durable backoff and regional replacement-lease transport remain open.

Use the [readiness record](../evidence/oci-readiness-2026-09-20.md),
[bootstrap contract](../operations/control-bootstrap.md),
[host authentication](../operations/host-session-authentication.md) and
[artifact publication protocol](../operations/artifact-publication.md) for the
current constraints and qualification evidence.

## Decision

1. **Cells self-form.** A `run` controller converges its own regional controller topology
   (streams, KV stores, object stores, consumers) idempotently at startup, before opening it.
   The first instance in a cell creates the topology; later instances join with no operator
   step, and concurrent bootstraps converge because every provisioning call is
   create-or-update. `TS_ORCH_AUTO_PROVISION=0` pins provisioning back to the infrastructure
   identity for deployments that want it. The infrastructure-only `ORCH_OPERATIONS` journal is
   never auto-provisioned by controllers.

2. **Deploys ship through NATS end to end.** Artifacts live in the regional
   `ORCH_ARTIFACTS` NATS object store, named `sha256-<hex>` by their own content digest.
   `operator artifact-push` publishes; every host fetches by digest with a content check on
   install. The immutable publisher now enforces same-digest retry through verified
   prefixes and conditional writes; naming objects by digest alone is insufficient.

3. **Hosts converge leaderlessly (Anna-style).** Admission of a new digest stays fenced
   behind the regional authority lease; *serving* the admitted state does not. Each host
   process configured with `TS_ORCH_HOST_ROLES` reconciles the durable desired digest in
   `ORCH_DELIVERY` (`direct.target.<hash>.<hash>.<hash>`, written by the delivery target
   adapter), installs the verified artifact under
   `/opt/terrascale/artifacts/<key>/sha256-<hex>/`, and converges the admitted systemd unit
   through the existing fail-closed `NativeSystemdRuntimeAdmission` boundary. This applies
   the Anna paper's split — coordination only where strictly needed (admission), monotone
   convergence everywhere else — so deploys keep flowing while leadership churns.
   (Principles from Anna / "Eliminating Boundaries in Cloud Storage with Anna": epoch-fenced
   membership, coordination-free serving, join/leave without consensus.)

   The `IHostAdmissionGate` contract is the required first-boot boundary for OCI hosts.
   Production `run` composes the signed regional enrollment verifier, grant policy checks,
   credential-bundle digest check, and durable regional KV replay/generation fence. A
   production host role without that configuration fails startup before NATS or OCI mutation;
   an admitted result is cached for the process lifetime so the five-second convergence loop
   does not consume the same grant repeatedly.

   Binary replacement is stop-then-recreate: a transient systemd unit's `ExecStart` is fixed
   at creation, so a converge that would change the executable stops the existing unit first
   (a stopped transient unit disappears, the next converge recreates it bound to the new
   digest). Per-role configuration ships as one environment file —
   `TS_ORCH_HOST_ENV_DIR/<artifactKey>.env` is copied to the exact path the unit's
   `EnvironmentFile` property names — and the state layout root (`TS_ORCH_HOST_STATE_ROOT`,
   default `/var/lib`) and artifact root are deployment parameters of the canonical plan.
   `LoadCredentialEncrypted` is opt-in on the plan until a secrets pipeline provisions
   encrypted credential files; systemd refuses a unit whose encrypted credential is absent,
   so the default plan omits it.

4. **Stateful replacements serialize through an expiring KV lease.** Roles whose catalog
   entry has `MinimumReplicas > 1` (TerraBase members, orchestrator, control NATS) acquire a
   cell-scoped `host.replace.<service>` compare-and-set lease before replacing their unit. A
   crashed holder's lease is taken over after expiry, so replacement never wedges and a cell
   never replaces two members at once.

5. **A failed replacement rolls back to the exact previous digest.** Artifact directories
   are immutable and never deleted, so the previous binary is always on disk. A converged
   unit that fails its post-replacement observation restores the previous digest's unit and
   reports `rolled-back`; a corrupt or missing artifact never executes and reports `failed`.

6. **One command deploys.** `terrascale-orchestrator operator deploy` composes the canonical
   handoff manifest, signs it with the operator's P-256 key, and submits it to the regional
   signed direct-delivery endpoint. The manifest payload kind carries no lease claims — the
   controller injects its own live authority — so the operator never races the lease. Retries
   with the same operation id replay the durable record. Production provenance additionally
   requires a durable signed artifact-evidence record; `operator evidence-record` writes it
   with the CI-artifact role key, so a day-one cell (before the global CI chain exists) can
   admit deploys without inventing a trust path.

7. **The emulated estate runs on Firecracker.** The live VM lane boots one microVM fleet per
   region on its own subnet and bridge (`SubnetThirdOctet` 77/78/79 = GRU/SFO/FRA), each with
   its own regional database and member cluster. The lane proves region isolation (one
   region's hard loss leaves the others serving) and regional self-healing, on real microVMs
   on one host.

## Consequences

- `provision-journal` remains for the infrastructure identity and `ORCH_OPERATIONS`; it is no
  longer required before a controller joins a cell.
- The operator deploy key is an independently revocable command identity: the controller's
  `TS_ORCH_COMMAND_TRUST` must carry its public key, and `TS_ORCH_DELIVERY_ADMITTED_TARGETS`
  must admit the `service:environment:region` triple it deploys.
- Host convergence observations are durable (`host.<instance>.<artifactKey>` in
  `ORCH_RUNTIME`) and best-effort telemetry on the agent observation subject.
- The TerraBase drain/catch-up topology planner (ADR 0018) remains the authority for
  membership-safe operations; the replace lease bounds concurrent binary replacement but
  does not replace replication-aware drain.
