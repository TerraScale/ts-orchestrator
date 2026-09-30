# Continuous delivery to running cells

Status: the opt-in TerraBase automation entry point is implemented; no live
timer, signing grant or rollout is enabled by this change. Orchestrator
replacement is a proposed follow-up requiring runtime changes and review.

## Mechanism and trust boundaries

Use one operator-host timer per deployed TerraBase placement, with a reviewed
inventory covering every placement in each cell. Poll every minute; a
publication notification can wake the same timer sooner. CI only publishes
inputs. The operator host reaches Forgejo and controllers through existing
TLS/Bastion access, holds the narrowly scoped online operator keys, and runs
the single orchestrator binary. Controllers and hosts need no Forgejo route.
Do not put operator, compatibility, release-leaf or root keys in Actions.

Publication is not deployment authorization. Forgejo metadata and assets are
untrusted inputs until their source lineage, qualification and byte digests
are checked. The existing operator signature admits a TerraBase artifact;
the independent compatibility signature certifies the exact old/candidate
pair and durability profile. Controllers enforce the grants, authority epoch,
placement/seat pins and serving proofs. Hosts accept the signed desired
state. The operator-host journal prevents release switching and repeated
automatic attempts; controller state remains the authority for seat progress.

For ts-orchestrator, use **rolling replacement from signed images**. The
existing trust chain qualifies the binary, then binds its signed receipt to
an image, base, kernel, region and exact OCI image OCID. A binary receipt alone
does not authorize overwriting a running installation. Replacement preserves
that chain and the image's systemd, enrollment and volume-init environment.
There is currently no supported running-cell replacement executor:

- `attempt.py` signs new deployment manifests, founder plans and selections;
  it is a bootstrap tool, not an upgrade tool.
- Founder install continuity authorizes read-only restart of an **exact
  accepted install**. It cannot authorize another image, instance or manifest.
- Managed TerraBase placement holds a lost host without replacing it
  (`internal/placement/controller.go`). Image promotion or changing the
  image for future launches cannot upgrade existing hosts.

## Signing and approval sequence

| Input/action | Authority and gate |
| --- | --- |
| TerraBase publication | CI publishes tested binaries, `qualification.json` last, and must additionally publish the accepted `source-digest.json` bound to that qualification and server. Git tree SHA-1 is not the prepared-source SHA-256. |
| TerraBase automation grants | Human authorizes new root-bound signed controller config: update actor with `can_place_terrabase`, `can_update_terrabase_runtime`, repository/role/environment limits; separate compatibility actor with `can_certify_terrabase_compatibility`. Installing this config is a separately reviewed operation. |
| TerraBase per-seat Prepare | Online update key and independent compatibility key on the operator host, only after the approved compatibility policy has been satisfied. Existing `terrabase-update` signs both statements. |
| Orchestrator binary receipt | Human reviews exact qualified main source/run/job attempt and bytes; offline root issues source/architecture/environment-scoped delegation; local leaf owner runs `ts-release sign-binary`. |
| Orchestrator image receipt | Existing image workflow builds and qualifies; authorized operator imports; offline root narrows the delegation to the cell/image OCID; local leaf owner signs and verifies the image receipt (`promote-image.py`). |
| Running-cell replacement plan | Proposed new offline-root-signed authorization pins predecessor install/instance, successor manifest/image receipt, same cell/deployment/slot, increasing generation, credentials/config digests, validity, resource budget and explicit rollback target. Existing continuity does not supply this authority. Root private keys stay offline. |

Forgejo has no authenticated protected-environment reviewer gate here
([releases.md](releases.md)). Retain independent review evidence externally.
Immediate automatic delivery of *arbitrary* orchestrator publications is
incompatible with the present per-source/per-image human signing gates.
Automatically discover and prepare candidates, then automatically execute
only the exact signed promotion and replacement authorization. Removing
those gates would be a new trust decision, outside this change.

## Implemented TerraBase entry point

After the decisions below, provision a full TerraBase checkout via `fj repo
clone`, the pinned admission `fj` extension from
`scripts/ci/prepare-fj-admission.sh`, operator config/keys and an existing
Bastion forward on the operator host. Invoke this command from a one-minute
timer with a one-hour service deadline longer than `--timeout`:

```sh
terrascale-orchestrator operator terrabase-sync \
  --config /var/lib/terrascale-operator/operator.json \
  --state /var/lib/terrascale-operator/terrabase-preview-p1 \
  --source-checkout /var/lib/terrascale-operator/terrabase-source \
  --compatibility-actor COMPATIBILITY_ACTOR \
  --compatibility-key /var/lib/terrascale-operator/compatibility.key \
  --nats-forward 10.251.0.11:4222=127.0.0.1:14222 \
  --wait 20m --timeout 55m
```

The command checks the checkout's origin, fetches main without force,
discovers non-draft `ci-<sha>-run-<id>` releases with `fj`, and selects the
newest published descendant of the completed source on main. Commit ancestry,
not run ID, determines newness. Rebuilds of identical source are ignored.
Multiple publications can coalesce before a rollout starts; an active rollout
is always completed before considering another release. A partial or unfinished
newest publication causes a retry on the next tick, with no admission.

It downloads the qualification, ARM64 server and `source-digest.json`, uses
the existing release verifier, and requires the matching successful
`fast.yml` run, successful Fast and publish jobs, and the publish log's exact
qualification-digest marker. Missing source digest fails closed; no source
claim is manufactured. It pins the qualification/binary/source digests in
`cd-active.json` before calling the existing signed updater end to end.

An owner-only state directory and kernel file lock serialize sync invocations
for a placement. Synced, immutable `cd-complete-<generation>.json` receipts
advance its source baseline only after both seats serve. Cancellation/timeouts
leave the active pin for resume. Changed assets, bad provenance, unreachable
Forgejo or unavailable forwarding never allow a different active candidate.
Input failures before admission retry without creating a stop marker.

The updater waits for a fresh serving proof from each seat before its peer.
A candidate that fails or exceeds the controller's 15-minute proof deadline
is held, then the existing updater returns that seat to its predecessor and
fails. Any non-cancellation updater error writes `cd-blocked.json`; later
ticks perform no rollout or discovery. Alert on nonzero exit and stale active
pins. After diagnosis, the authorized operator may archive/remove the stop
marker to resume the **same** active pin. A rejected candidate must be
withdrawn deliberately by disabling the timer, reconciling controller state
and archiving the active pin; never silently discard a pending operation.
Disable the timer before manual updates or journal maintenance. Binary
rollback requires the older release to read the persistent format.

## Proposed orchestrator replacement executor

Keep the cell/deployment identity, regional ledger and customer data. A durable
operator journal and controller authority CAS fence each predecessor and
successor. Run at most one controller replacement per cell, B then C then A
(seed last), requiring the other two controllers healthy and JetStream quorum
current. Fence the old process/instance before reusing its slot/IP/credentials;
transfer the seed's founder selection floor explicitly, never reset it. Admit
the successor through the new root-signed plan, wait for route/TLS/clock health,
all replicated authority/delivery state caught up and a fresh signed version
proof, and only then advance. Retain the old boot volume and install evidence
for the rollback window. A successor install needs its own root-signed restart
continuity; the predecessor's proof must never be reused.

Next replace managed hosts one seat per TerraBase partition at a time, with
the peer serving. Preserve volume/member/incarnation/material identities;
stop and fence the old runtime, detach its retained data volume, enroll the
successor from the signed image, reattach exclusively, advance host/session/
attachment/desired pins, and demand a fresh TerraBase serving proof before
the next seat. Do not create another database or format an existing volume.
Completion requires inventory and signed version proofs for **all three
controllers and every managed host**, including idle hosts. Newly enrolled
hosts use the approved image. A failed or ambiguous replacement stops the
cell; reconcile readback before retry, preserve the healthy quorum/peer, and
restore only the explicitly authorized predecessor with new fencing/generation
values. Never lower a selector floor. NATS/state-format changes require tested
mixed-version support and a proven rollback window; otherwise halt for a
reviewed migration. TerraBase and orchestrator rollouts must not overlap.

This executor requires changes to bootstrap admission/founder state, controller
host replacement and OCI fencing/volume handoff. None is implemented here;
`internal/bootstrapstart`, `internal/oci`, `deploy/systemd` and
`deploy/oci-region` are unchanged.

## Human decisions needed

1. Approve the update/compatibility key owners, separate actor identities,
   cell/repository/role/environment grants, expiry and revocation process;
   sign and install the updated controller config. Current GRU grants lack
   these capabilities. No key is generated or enabled by this PR.
2. Decide whether all eligible main releases assert mixed-version replication,
   client-data and persistent-format read/write compatibility with the
   deployed predecessor, including rollback. The implemented entry point
   relies on that explicit policy because the existing updater signs those
   assertions. If release-specific tested evidence is required, add and verify
   it before enabling automation; qualification success alone is insufficient.
3. Approve/publish TerraBase's accepted prepared-source digest recipe and
   release asset, and authorize trusting that producer. It is absent today.
4. Approve automatic rollout scope: cell/placement inventory, canary to
   production promotion, coalescing/skipping intermediate releases, one-minute
   polling, soak time (currently serving proof only), maintenance windows,
   pause/alert owner and rollback policy. Install timers/forward supervision
   only after approval; no repository secret or CI-to-cell access is needed.
5. Review the orchestrator replacement authorization schema, root/leaf owners,
   source/image signing gates, budget, admission/fencing and seed-floor handoff,
   state-format compatibility and rollback criteria. Approve a separate runtime
   implementation PR before any running-cell orchestrator replacement.
