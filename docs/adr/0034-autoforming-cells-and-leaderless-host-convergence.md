# ADR 0034: Auto-forming cells and leaderless host convergence

| | |
| --- | --- |
| Status | Accepted |
| Date | 2026-09-18 |
| Context | [ADR 0033](0033-gru-global-authority-and-regional-autonomy.md), the deploy path in `ControlPlane/Delivery`, `Runtime/AdmittedRoleCatalog` |

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
   install. Republishing identical bytes is a natural no-op; a name can never change meaning.

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
   with the same operation id replay the durable record.

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
