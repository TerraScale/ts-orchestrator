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
  (`rolloutexec`), the OCI reconcile (`ociresource`), `nodescale` and the host
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
3. **In-place material renewal.** Root-signed material generations renew
   controller credentials under the accepted deployment and broker identity.
   Restart uses the root-owned accepted identity and current generation, not
   initial manifest expiry or a founder continuity proof. Existing cells are
   preserved. [In-place identity re-key](identity-rekey.md) separately replaces
   retired deployment/cluster identities and installs current grants.
   Renewal uses these steps:
   1. **NATS TLS hot reload (done).** `natscell.ReloadingTLS` serves the
      broker bridge, the NATS routes and the host-enrollment listener. At
      most every 5 seconds, one handshake reads the certificate, key and CA
      files and compares their digests; the others serve the current set
      without I/O. A changed set is used only if the key matches and the leaf is
      current, has its role's usages, chains to both the new and the
      current bundle, and keeps its subject and names. Otherwise the last
      good set stays, which covers a renewal caught between its renames.
      Startup makes the same checks, so a controller whose leaf expired
      while it was down renews it before NATS starts (step 4). Live
      connections keep their material and session tickets are off. The accepting side of every listener
      reloads the CA bundle too. The dialing side of a route keeps Go's
      built-in check, address included, against the bundle it started with,
      because a custom check cannot see the dialed address. A renewed leaf
      therefore needs no restart, but a CA rollover restarts each controller
      in place once. Interregion leafnode TLS still loads once.
   2. **Material generation.** The owner's root signs a generation document
      for one cell and deployment: a generation number and its
      predecessor's digest, the CA bundle, the issuing intermediate
      certificate and the Vault reference of its key, the controller account
      signing key's public key and Vault reference, the operator and account
      JWTs, and the maximum leaf lifetime. It is published in KV and kept on
      every controller next to the root chain (#185).
   3. **Admission pins the generation.** Accepted restart admission accepts renewable files (leaves and their keys, user creds,
      the CA bundle, account JWTs, the host issuer) when they are valid under
      the newest root-verified generation the controller holds, instead of
      matching the manifest digests. Founder, response, ticket and route
      secrets keep their digest pins. Initial formation pins its original material; accepted restart uses the
      verified installed generation.
   4. **Leader-coordinated renewal.** The leader publishes the current
      generation and rollover phase under its authority epoch. Each
      controller issues its own TLS leaf and NATS user JWT with the
      generation's issuing key once a third of the lifetime remains, and
      before NATS starts if the leaf already expired. It writes the files
      atomically and step 1 picks them up. Issuance runs on
      the member itself: a controller whose leaf expired while it was down
      cannot reach the leader, and every controller already holds the issuer
      keys it needs to lead. Hosts keep renewing through the enrollment
      listener.
   5. **Hosts follow the bundle.** The leader pushes the CA bundle over the
      host session, signed with the controller response key that hosts pin.
      Hosts write `ca.pem` atomically, and their dialer reads it on the next
      dial. The launch-metadata bundle is used only for first contact.
   6. **CA rollover and acceptance.** A rollover runs in four steps:
      1. The bundle gains the new CA.
      2. Every controller restarts in place once. The leader waits until
         each one reports the new CA in its dialing trust.
      3. Leaves move to the new CA.
      4. The old CA is dropped.

      Acceptance: a lab cell survives two leaf expiries and one CA rollover
      with no re-found. Leaf lifetimes are then shortened.
4. **Host repair.** If a host stops reporting for longer than a grace period
   and its OCI instance is stopped or terminated, the leader replaces it in
   its node pool, and the new host enrolls again. A host
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
