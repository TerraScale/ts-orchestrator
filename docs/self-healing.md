# Self-healing and automatic maintenance (TS-568)

ts-orch keeps itself and every host healthy without an operator. Each region
repairs itself, renews what expires, patches hosts in place and corrects
drift. `ts-orch doctor` shows the result in one command. This note records
the design and the order of the slices. Each slice states what it delivers
and what is still missing.

## Principles

- **Detect, decide, act, verify.** A watcher reports facts. The regional
  authority leader decides and acts under its authority epoch (fenced like
  every mutation), then checks that the fact changed. Every action is
  recorded in the decision journal (`docs/decision-journal.md`).
- **Updates never destroy servers.** Credentials, OS packages and binaries
  are changed in place. Only a host that is dead may be replaced, and only
  through the node pool.
- **Quorum first.** Changes to quorum roles (NATS controllers, TerraBase
  members) run all at once only when quorum still holds afterwards. Otherwise
  they run one member at a time, with a health check after each member and
  automatic rollback.
- **A missing observation is not a recovery.** If a member or input cannot
  be read, the problem it last reported stays open (the `insights` blind
  inputs).
- **Reuse.** Insights, the decision journal, the rollout executor
  (`rolloutexec`), the OCI reconcile (`ociresource`), `hostpool` and the host
  credential renewal already exist, and the slices build on them.

## Boundaries with sibling work

| Concern | Owner |
| --- | --- |
| Machine restart policy, rescheduling machines off a lost host | TS-563 (scheduler/runtime) |
| Config hot reload, cross-region NATS fabric | TS-562 |
| Node pool growth and shrink for load | TS-565 |
| Release consumer and health-gated binary rollouts | TS-560, `rolloutexec` |
| Everything below | TS-568 |

## Slices

1. **Credential expiry watch (done).** Every controller lists the
   certificates and NATS JWTs it runs with in its `MemberSnapshot`
   (`credentials`): NATS client, server, route and interregion TLS and CAs,
   operator, account and user JWTs, the host TLS issuer and the TerraBase
   member CA. `maintenance.Scan` reads the files again on every snapshot
   (cached for 3 s), so a renewed file shows up without a restart. Because
   the cell-wide snapshot gathers every member's list, the
   `certificate_expiring` insight warns 14 days before any controller's
   credential expires and turns critical 3 days before. Each member's
   credentials are shown separately. Each entry also carries `not_before`,
   so renewal can act on the fraction of the lifetime that is left. The gauge
   `ts_orch_credential_expiry_timestamp_seconds{name,kind}` lets an external
   alert fire even when no dashboard is open. A file that cannot be read
   marks that member's `credentials` section failed and is logged once by
   role and path. The files that could be read are still reported. A member
   that does not answer, or whose section failed, keeps its open expiry
   insights; only a renewed credential resolves them.
2. **`ts-orch doctor`.** The leader answers a signed, read-only `fleet.doctor`
   request on the operator path (the same path as `get` and `rollout status`)
   with the ranked insights, the unavailable inputs and the health checks of
   each member. The command prints a table and exits non-zero on a critical
   insight. CI and humans can use the same command.
3. **Controller credential renewal.** Today all bootstrap material, including
   the CA, the operator and account JWTs and the controller leaves, expires
   together after at most 30 days (`bootstrapmaterial.MaxValidity`). The
   signing keys (`issuer-ca.key`, the operator and account seeds) stay with
   the owner. A renewed leaf or user JWT cannot outlive its CA or account
   JWT, so renewing leaves alone does not remove the cliff. Proposed design:
   a long-lived CA and operator with a shorter-lived issuing CA and account
   signing key that controllers can read from OCI Vault. Controllers reissue
   their own TLS leaves and NATS user JWTs once a third of the lifetime
   remains, write the files atomically and hot-reload them (TS-562). The
   issuing material is rotated the same way, one level up. Hosts already
   renew their own credentials (`internal/app/host_credential_reload.go`).
   Expiry thresholds then become relative to each credential's lifetime.
   Which keys may live in Vault is the owner's decision, and this slice
   needs that decision before it starts.
4. **Host repair.** If a host stops reporting for longer than a grace period
   and its OCI instance is stopped or terminated, the leader replaces it in
   its node pool through `hostpool`, and the new host enrolls again. A host
   is never replaced while its volume is attached to a serving member.
5. **In-place OS patching.** Signed package-set receipts (like release
   receipts) are applied by the host agent. Hosts are patched all at once
   where quorum allows, otherwise one at a time. The agent reboots when the
   set requires it, checks health and rolls back to the previous set when the
   check fails.
6. **Drift.** The OCI reconcile already corrects NSG, security list, route
   table, NLB backend and bucket drift. Cloudflare DNS, Origin CA and load
   balancer listener drift come next. They start in report mode (an
   insight), and enforce mode is enabled per resource after review.
7. **SLOs.** SLO rules over the metric history publish NATS events and
   GlitchTip alerts. When a release breaches an SLO within its soak window,
   the leader rolls it back through `rolloutexec`.
