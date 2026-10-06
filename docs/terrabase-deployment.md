# TerraBase deployment into a running cell

This is the operator workflow for the C# TerraBase binary. The regional
bootstrap attempt (`ts-orch oci-region attempt`) brings a cell up end to
end: controller material that includes the cell's member CA, signed
controller configs that carry the member CA and the TerraBase workload
profile, three controllers, the database hosts, and the first release. One
operator command verifies a published release, admits it, deploys it to
every member, waits for readiness and rolls back a release that fails. The
binary and host contract are in
[TerraBase runtime contract](terrabase-runtime-contract.md); the exact gru-1
command sequence is the [bring-up runbook](#gru-1-bring-up-runbook).

| Command | Effect |
| --- | --- |
| `ts-orch oci-region attempt --config F PHASE` | Runs one resumable bring-up phase; see the [runbook](#gru-1-bring-up-runbook). |
| `ts-orch oci-region preview cell-plan --plan F --inventory F [--profile F]` | Read-only: prints the cell's static names, placement and cost estimate against the plan ceiling. |
| `ts-orch oci-region preview member-launch --plan F --inventory F --admission F --slot member-a --image-ocid OCID --host-enrollment F --owner-ssh-public-key F --out F` | Writes the launch input of one database host (`gru-1-db-1`); creates nothing. |
| `ts-orch bootstrap render-controller-config ... --terrabase-profile F --terrabase-profile-sha256 H --out F` | Deprecated: renders `controller.workloads.terrabase` into the signed config. A cell gets the profile as a root-signed [cell spec](cell-spec.md) `terrabase` entry instead; the renderer always sets the member CA paths when the material holds the CA. |
| `ts-orch operator terrabase-release --config FILE [--nats-forward ...] --binary F --sha256 F --source-checkout DIR --commit SHA --environment ENV --profile F [--wait 10m]` | Verifies, admits and rolls out one release to all members; see [Run](#run). |
| `ts-orch terrabase data-volume --plan FILE --member NAME (--instance OCID \| --grow-gb N) [--compartment OCID] [--apply]` | Prints the resolved data volume request as one JSON line. With `--apply`, creates and attaches the member's volume `NAME-data` (`{"step":"attached", ...}`) or grows it (`{"step":"grown", ...}`) through the operator's `~/.oci/config` DEFAULT profile; see [gru-1 runbook](#gru-1-live-deployment-runbook) step 7. |
| `ts-orch terrabase restore-volume --plan FILE --member NAME --scratch-instance OCID [--backup OCID] [--compartment OCID] [--apply]` | Prints the resolved restore request. With `--apply`, restores the newest AVAILABLE backup of `NAME-data` (or `--backup`) into a new volume `restore-NAME-data` and attaches it to the scratch instance (`{"step":"restored", ...}`); see [Restore drill](#restore-drill). |
| `ts-orch terrabase restore-check --plan FILE --restored-volume OCID --binary F --organization ORG --document PATH --scratch-instance OCID [--compartment OCID] [--ready-path P] [--wait D] [--apply]` | On the scratch host, as root: prints the plan. With `--apply`, verifies the exact restored OCID and restore tag, mounts it, and reads `PATH` through TerraBase in a loopback-only network namespace (`{"step":"verified", ...}`); see [Restore drill](#restore-drill). |
| `ts-orch operator hosts --config FILE [--nats-forward ...]` | Prints each host's registration, session and latest reports, including each member's digest and state. |
| `ts-orch terrabase member-ca --cell CELL --out DIR` | Creates a standalone member CA for a lab controller config. A bootstrapped cell gets its CA from its controller material instead. |

On the operator host the installed binary is `terrascale-orchestrator`; it
exposes the same commands. The operator config is
`/var/lib/terrascale-operator/operator.json`. Add
`--nats-forward CONTROLLER_IP:4222=127.0.0.1:PORT` only when reaching a
controller through an OCI Bastion forward.

## Prerequisites

1. **Orchestrator revision.** Controllers, host agents and the operator CLI
   run a revision that contains this contract (the `terrabase-peer` host
   operation, `host.terrabase_root`, `controller.terrabase_ca_*` and
   `operator terrabase-release`). Signed command and artifact claims change
   between revisions, so a CLI from another revision can be rejected by the
   controllers; `ts-orch oci-region attempt operator` verifies the cell's
   qualified CLI and prints its path.
2. **ARM64 release asset.** OCI hosts are ARM64. TerraBase CI publishes only
   `terrabase-linux-amd64` today; it must also publish
   `terrabase-linux-arm64` and its `.sha256` before an OCI deployment.
3. **Member CA on every controller.** Any controller may be the authority
   leader that signs member certificates, so each needs the files named by
   `controller.terrabase_ca_cert_file` and `controller.terrabase_ca_key_file`.
   `bootstrap generate-controller-material` creates the cell's CA as
   `terrabase-member-ca.pem` and `terrabase-member-ca.key` (host-issuer
   material). They are published to Vault and installed into
   `/var/lib/terrascale-orchestrator-secrets` on every controller with the
   rest of its material, and `render-controller-config` points the two keys
   at them. Without them member certificate requests are refused and
   members never start.
4. **Workload profile.** The cell spec carries the `terrabase` entry, from
   the reviewed profile file, which a root signs; `oci-region attempt`
   applies it in its `services` phase. A cell whose signed controller config
   was rendered with `--terrabase-profile` keeps that profile as generation
   0; see [Workload profile](#workload-profile). The signed placement sidecar
   (`placement.json`) must not use `terrabase` as its `member_role`: that
   role belongs to the C# delivery path, and signing refuses the overlap.
5. **TerraBase hosts.** The hosts named in `TERRABASE_PEERS` are registered
   in the target environment with role `terrabase`, without `managed_oci`,
   `managed_placement` or `managed_member` bindings, with a current host
   session and capacity for the profile's `resources`.

   On OCI such a host is a static database host. `preview member-launch`
   (attempt phase `members`) launches `<cell>-db-<n>` in the workload
   compartment at its plan address, from the cell image, with a static host
   descriptor (`{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-1"}`),
   the public enrollment bundle and the tags `terrascale-owner`,
   `terrascale-resource=terrabase-host` and `terrascale-host-node`. On boot
   its `host-setup` enrolls with the controllers on port 8443. A controller
   accepts it only when its signed profile lists the node at the host's
   direct private address and OCI shows a `RUNNING` instance of the
   regional fleet (compartment, availability and fault domains, image, boot
   size, subnet and NSGs) that carries that exact descriptor and node tag
   and no managed launch identity. The registration has role `terrabase`,
   the profile's `resources` as capacity, and no managed binding;
   `host-setup` writes `terrabase_root` `/srv/ts-managed/terrabase`,
   `terrabase_data_volume: true` and the recorded
   `terrabase_data_volume_id` into `host.json`. The trusted registration
   carries the same volume OCID. The member's data is stored on its
   retained OCI block volume, mounted before TerraBase starts; a missing or
   mismatched volume fails closed. A replacement instance at the same
   address registers the next generation with its own keys. It cannot take
   over a live member: enrollment refuses new keys while the node holds a
   host session, and the controller grants the new generation a session
   only after the previous generation's session has expired. Launch rights
   in the workload compartment are therefore part of the cell's trust
   boundary. `operator host-enrollment-revoke --instance-id` disables a
   static host's grant: it can neither renew nor enroll again, and its
   issued credentials expire within 48 hours.

   The regional fleet pin covers static hosts too: they must boot the
   fleet's image, or one the cell spec's `host_images` allows, with its
   boot size and VPUs. Changing `image_id` in the
   signed `oci-region.json` replaces the database hosts; their retained
   data volumes are reattached to replacement instances. Hosts that
   self-enroll through a managed placement seat register a `managed_oci`
   binding and cannot run C# members.
6. **Network.** The workload NSG allows the peer port (9443) between member
   IPs and the client port (9465) from clients and the Bastion endpoint.
   The admin port (9464) is loopback-only and needs no rule. Hosts reach
   controllers on 4222 (NATS).
7. **Operator grant.** The operator's signer grant lists role `terrabase`
   and the target environment; if it lists repositories, it includes
   `https://git.terrascale.tech/TerraScale/terrabase`.

## Workload profile

The profile is `controller.workloads.terrabase` in the signed controller
config, and the same JSON is passed to `--profile`. The controller compares
the configuration digest of `args` and `env` and rejects a rollout whose
profile differs. For cell `gru-1` with two members:

```json
{
  "resources": {"cpu": 1, "memory_bytes": 4294967296, "disk_bytes": 21474836480},
  "env": {
    "TERRABASE_REGION": "gru-1",
    "TERRABASE_PEER_PORT": "9443",
    "TERRABASE_CLIENT_PORT": "9465",
    "TERRABASE_PEERS": "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443"
  }
}
```

`TERRABASE_REGION` is required outside Development starting with
[TerraBase #18](https://git.terrascale.tech/TerraScale/terrabase/pulls/18).
Without it the binary exits before opening storage. Use `gru-1` in both the
signed controller profile and the operator's `--profile` file; the host
preserves this environment setting when adding the member's local paths.

The `resources` values are an example; a static database host registers
exactly this capacity. gru-1 uses the two-member
[`deploy/oci-region/terrabase-gru-1-profile.json`](../deploy/oci-region/terrabase-gru-1-profile.json).
A rendered controller config also names the member CA from its material:

```json
"terrabase_ca_cert_file": "/var/lib/terrascale-orchestrator-secrets/terrabase-member-ca.pem",
"terrabase_ca_key_file": "/var/lib/terrascale-orchestrator-secrets/terrabase-member-ca.key"
```

`TERRABASE_PEERS` is a proposed setting that the current binary ignores; see
the [runtime contract](terrabase-runtime-contract.md#workload-profile).

## Release files

```sh
TAG=ci-<commit>-run-<run id>   # or v<Version>
COMMIT=<full 40-character commit of the release>
WORK=$(mktemp -d) && cd "$WORK"
fj -H git.terrascale.tech release asset download -r TerraScale/terrabase "$TAG" terrabase-linux-arm64
fj -H git.terrascale.tech release asset download -r TerraScale/terrabase "$TAG" terrabase-linux-arm64.sha256
sha256sum -c terrabase-linux-arm64.sha256
fj repo clone -H https://git.terrascale.tech TerraScale/terrabase "$WORK/terrabase"
```

Keep the asset file names: the command checks them. `--commit` must be a
full lowercase commit SHA present in the checkout; for a `v<Version>` tag
use `git -C "$WORK/terrabase" rev-parse "v<Version>^{commit}"`.

## Run

A green TerraBase `main` CI releases TerraBase to every region with no human
step ([automatic service releases](continuous-delivery.md#automatic-service-releases-ts-610));
the region's leader runs the gate and rollback below. Run it by hand only to
release outside CI:

```sh
F=(--nats-forward 10.251.0.11:4222=127.0.0.1:14222)   # Bastion only
sudo terrascale-orchestrator operator terrabase-release \
  --config /var/lib/terrascale-operator/operator.json "${F[@]}" \
  --binary "$WORK/terrabase-linux-arm64" --sha256 "$WORK/terrabase-linux-arm64.sha256" \
  --source-checkout "$WORK/terrabase" --commit "$COMMIT" \
  --environment canary --profile /var/lib/terrascale-operator/terrabase-gru-1-profile.json \
  --wait 10m
```

The member count is the number of `TERRABASE_PEERS` entries. The command:

1. Verifies the asset name (`terrabase-linux-amd64` or `-arm64`), ELF magic,
   size (at most 512 MiB) and SHA-256 against the `.sha256` asset. That
   digest is pinned for the rest of the run.
2. Builds the source claim: the TerraBase repository, `--commit`, and the
   SHA-256 of `git archive --format=tar <commit>` in the checkout.
3. Reads the members' reports in `--environment`: the digest the `running`
   members serve (it refuses when they disagree) is the rollback target, and
   the command resolves its admitted artifact before changing anything. The
   next generation is above every committed `terrabase` desired, withdrawals
   included.
4. Pushes the binary and obtains the signed artifact admission; prints
   `{"step":"artifact", ...}` with the digest and the previous digest.
5. Submits the signed delivery intent for one member per peer; prints
   `{"step":"deploy", ...}` with the digest and generation once accepted.
6. Waits for the readiness gate: every replica in `--environment` reports
   the new digest `running` within `--wait` (default ten minutes, or five
   minutes per member when that is longer). A `failed` member, including one whose
   process exited, fails the gate at once; read errors are retried until
   `--wait`. Prints `{"step":"ready", ...}` with the member count.
7. On a gate failure, rolls back: a new intent with generation + 1 and the
   previous digest, which must pass the same gate. It does so whenever the
   release may have written members or may still write them. A submit that
   failed before the intent was signed and published changed nothing and is
   not rolled back. After any later submit error, an interrupt, or a
   delivery still undecided at `--wait`, the intent may have been
   published: the command reads the durable operation back (once more on a
   fresh context after an interrupt), gates it like any release when it was
   accepted, and rolls back unless a receipt proves that no member changed:
   `rejected`, or held because placement never planned it (for example a
   listed host is unavailable). The rollback's higher generation also keeps
   a late original from landing. The rollback runs on a fresh context with
   its own deadline, so it completes after Ctrl-C or SIGTERM. The command exits non-zero either way and says whether the
   rollback succeeded. A first deployment has no previous digest and is not
   rolled back. A failure to write progress to stdout never counts as a
   gate failure; the command reports it when it exits.

By default all members switch together: the delivery path writes every
host's desired at once, so every member restarts on the new binary. With
`controller.terrabase_seats` enabled they restart one at a time instead
(TS-571, [zero-downtime rollouts](terrabase-zero-downtime-rollouts.md)): a
host holds its member's restart, reporting it `waiting`, until the leader's
seat controller permits it, and with `oci_reconcile.public_lb` the seat is
drained on the public load balancer first and returns once it serves again:

```json
"terrabase_seats": {"enabled": true, "drain_grace_seconds": 15, "settle_seconds": 10}
```

Both durations are optional (0 to 300 seconds). Enable it on every
controller of the cell together: the host restart gate is served by the
authority leader. The controller never drains the last healthy seat, so a
cell whose load balancer serves one member (gru-1 until TS-561) must keep it
off, or every release waits out its gate and rolls back. Old binaries stay
installed on the hosts, so a rollback reuses the cached file. A member's data
lives on its host (on the data volume attached to it when
`terrabase_data_volume` is set), so the controller replaces a failed member in place
instead of moving it to another host, which is what lets the rollback land on
the hosts the failed release took over. When members
report different digests, for example after a failed rollback, the command
refuses until they agree.

Until replication exists (TerraBase TS-464), each member is an independent
database: a write to one member is not on the others.

### Restart hold

A cell without seats (gru-1: its signed controller configs predate them)
can still restart replicas one at a time, by hand, behind load balancer
drains (TS-578). A release writes every replica's desired at once, for
TerraBase members and for reconciled roles such as ts-auth alike. While the
file `<role>-restart-hold` exists in a host's state root
(`/var/lib/terrascale-orchestrator-host/state`), for example
`terrabase-restart-hold` or `ts-auth-restart-hold`, the host keeps that
role's running workload on its current generation and reports the new one
`waiting`, which the release gate waits for. It never holds a stopped
workload or a withdrawal, and a restarted host agent starts its workloads on
the current desired.

1. `sudo touch /var/lib/terrascale-orchestrator-host/state/terrabase-restart-hold`
   on every host whose member serves.
2. Run the release with a `--wait` long enough for every step below, and
   keep it running: a gate that times out rolls back every member at once.
3. For one held host at a time: drain its backend on the load balancer,
   wait for in-flight requests (15 s), set it offline (a drain alone keeps
   the load balancer's pooled connections), remove its hold file, wait for
   its `/readyz` and for `operator hosts` to show it `running` at the new
   generation, then return the backend to rotation and wait until every
   load balancer node's latest health check is OK before draining the next.

A hold is for minutes: a held TerraBase member renews no certificate. With
write-wait (TerraBase TS-575), a member that restarts with new peers sends
them its whole journal first and its writes wait for their acknowledgements
until they catch up: keep it out of rotation, and out of ts-auth's
endpoints, until `terrabase_replication_sender_durable_lag` is 0.

## gru-1 bring-up runbook

**Prepared, not executed.** Every step marked **LIVE** creates or changes OCI
or cell state and runs only after COS relays the user's approval for that
step. Blast radius: the new `gru-1-*` resources of
[the rebuild proposal](evidence/gru-rebuild-plan-20261004.md); TerraBase
members of `gru-1` start, or restart, on the new binary at once. There is no
terrabase-rust data to migrate. Run each phase on its own; do not use
`attempt up` for a live cell. Every phase is resumable: rerunning it after an
interruption reuses its retained records.

Inputs, outside Git except where named:

- `plan.json`: [`deploy/oci-region/plan.json`](../deploy/oci-region/plan.json)
  with the phase-1 foundation OCIDs recorded after their confirmed creation
  (compartments, Vault, key, VCN, subnet, both NSGs, security list, route
  table, service and local peering gateways, controller and host dynamic
  groups, controller and Object Storage key policies, NetBird secret and
  policy). The host LiveS3Credential secret and `host_policy` stay `null`,
  and the public API resource IDs stay `null` until TS-486 creates them.
- `placement.json`: the signed placement sidecar with
  `"environment": "canary"` and a `member_role` other than `terrabase`, for
  example `"retired-tb-server"`.
- The operator grant lists role `terrabase` and environment `canary`.
- `attempt.json`: the existing attempt settings plus

  ```json
  "base_plan": "/ABSOLUTE/PATH/plan.json",
  "placement_config": "/ABSOLUTE/PATH/placement.json",
  "terrabase_profile": "/ABSOLUTE/PATH/deploy/oci-region/terrabase-gru-1-profile.json",
  "terrabase": {"tag": "<TerraBase release tag>", "commit": "<its full 40-character commit>", "environment": "canary"}
  ```

  The release must publish `terrabase-linux-arm64` and its `.sha256`
  (TerraBase TS-483).

`A` below is `ts-orch oci-region attempt --config /ABSOLUTE/PATH/attempt.json`.

1. **Dry run (read-only).** `$A plan` captures a fresh inventory of
   `base_plan` (or of the attempt's plan once `material` wrote it) and prints
   the phase-2 plan: image `gru-1-arm64`, controllers `gru-1-ctl-1..3`
   (`10.251.0.11-13`, fault domains 1-3), database hosts `gru-1-db-1..2`
   (`10.251.0.21-22`, fault domains 1-2), `terrabase_peers` checked against
   the profile, and the native estimate with `ceiling_usd` 200. It exits
   non-zero when the estimate exceeds the ceiling or the profile's peers
   differ from the plan. Attach the output to the approval request.
2. **Material — LIVE (Vault secrets).** `$A material` generates the
   controller material, including `terrabase-member-ca.pem` and
   `terrabase-member-ca.key`, inspects the foundation (`preview
   inspect-foundation`; it no longer needs LiveS3 or public API
   resources), and publishes the material to Vault. Review the generated
   secret names and count before approving publication. Use a new attempt
   directory: material generated before the member CA existed (32 files
   instead of 34) still loads and renders, but without the CA, and a
   controller config with a TerraBase profile is refused without it.
3. **Release and image — LIVE (image import).** `$A release` then `$A image`
   verify the orchestrator release and import the qualified image as
   `gru-1-arm64`, tagged `terrascale-qcow2-sha256`. An import resumes a live
   image of that name only when the tag matches its QCOW2; retire an older
   `gru-1-arm64` first.
4. **Sign (local).** `$A sign` renders each controller config with the
   cell's identity, material and member CA paths only, and signs the
   manifests and founder plan.
5. **Controllers — LIVE (gru-1-ctl-1; it then forms ctl-2/3).** `$A launch`,
   `$A complete`, `$A continuity`, then `$A operator`, which installs the
   operator material and prints the qualified operator CLI path. Check three
   healthy controllers, then run `$A services`: it applies TerraBase's
   profile (`terrabase_profile`, root-signed) and ts-auth as the first cell
   spec, which member enrollment reads.
6. **Database hosts — LIVE (gru-1-db-1, gru-1-db-2).** `$A members` takes a
   fresh cost admission per host, writes `launch/gru-1-db-N-launch.json`
   with `preview member-launch`, launches it with a retry token bound to
   the file and waits for `RUNNING`. A rerun after an interruption adopts
   the one live instance of a host's name only when it is exactly the
   launch of the retained launch input; any other instance of that name
   stops the phase for reconciliation. Each host enrolls itself within
   about a minute of boot and sets `terrabase_data_volume: true`. Confirm
   with `sudo terrascale-orchestrator operator hosts --config
   /var/lib/terrascale-operator/operator.json`: both nodes registered with
   role `terrabase`, no `managed_*` binding and a current session.
7. **Member data volumes — LIVE (create and attach).** Dry run each member
   first; it prints the resolved request and makes no OCI call:
   `ts-orch terrabase data-volume --plan deploy/oci-region/plan.json --member gru-1-db-1 --instance <instance OCID> --compartment <gru-1 workload compartment>`.
   Check the size (`data_gb` for the member slot; `member-a` is
   `gru-1-db-1`, `member-b` is `gru-1-db-2`; the plan has no third member
   slot, so `gru-1-db-3` is refused until it does), availability domain,
   VPUs and compartment, then rerun with `--apply` and expect
   `{"step":"attached", ...}`. The volume carries the cell's backup policy
   `gru-1-db-data` before it is attached. Record the printed `volume_id` in
   `plan.json` `resource_ids.data_volumes.<slot>` and in both the trusted host
   registration and `host.json` as `terrabase_data_volume_id`: from then on the command
   never creates that member's volume again, and a missing one fails with a
   restore instruction. `--compartment` is needed while the plan's
   `resource_ids.workload_compartment` is null. The host mounts the volume
   on its next poll, formatting a new one only with the member's one-time
   first-format grant; the member does not start before that. To grow a
   volume later, run the same command with `--grow-gb <N>` instead of
   `--instance`, dry run then `--apply`; the host grows the filesystem after
   the block volume grows. Retired volumes remain retained and are never
   reused for a new node-name incarnation. Deletion or detachment requires
   a separate explicit action.
8. **Read-only host check.** Take the peer list from the log line of
   `TS_OCI_LIVE_COMPARTMENT_ID=<gru-1-workload OCID> go test -count=1 -v -run '^TestLiveOCITerraBaseHostsReadOnly$' ./internal/terrabase`
   and confirm it equals the profile's `TERRABASE_PEERS`. It fails when a
   host is not A1, two hosts share a fault domain, an NSG keeps a member
   from another member's peer port, or no A1 core is left in the region.
9. **TerraBase release — LIVE (rollout).** `$A terrabase` downloads
   `terrabase-linux-arm64` and `.sha256` for the configured tag into
   `terrabase/<tag>/` of the attempt directory, verifies them in-process
   (name, ELF64 aarch64, size, digest), checks the commit in a TerraBase
   clone (fetched when it already exists), requires it to be the commit the
   tag names (from a `ci-<commit>-run-<id>` tag, or `git rev-parse` of a
   version tag), and runs `sudo <qualified operator CLI> operator
   terrabase-release --config /var/lib/terrascale-operator/operator.json
   --binary … --sha256 … --source-checkout … --commit <commit> --environment
   canary --profile <terrabase_profile> --wait 10m` as described in [Run](#run).
10. **Verify.** The release prints `{"step":"ready", ...}` with two
    members, and `operator hosts` shows a `terrabase` report `running` with
    the new digest on `gru-1-db-1` and `gru-1-db-2`. Capture the evidence in
    `docs/evidence`. `running` proves process liveness only; replication
    acceptance waits for TerraBase TS-464/TS-469.


## Restore drill

**Prepared, not executed. Every `--apply` step changes OCI or a host and
requires human confirmation.** The drill proves that a member's OCI volume
backups restore: SQLite's WAL makes a crash-consistent volume backup
restorable, and the drill shows it with a real document read. It never
touches the member, its volume or its host.

1. Launch a scratch instance in the gru-1 workload compartment and
   availability domain, from a plain Ubuntu ARM64 image, with consistent
   volume naming and no orchestrator enrollment metadata. It must not be
   named like a member (`gru-1-db-N`) and must not have
   `/etc/terrascale-orchestrator/host.json`.
2. Dry run the restore on the operator host; it makes no OCI call:
   `ts-orch terrabase restore-volume --plan deploy/oci-region/plan.json --member gru-1-db-1 --scratch-instance <scratch OCID> --compartment <gru-1 workload compartment>`.
   Without `--backup` the newest AVAILABLE backup of the member's volume is
   restored. A named backup must be of the member's current volume, or of
   its recorded volume in plan.json when the volume is gone.
3. Rerun with `--apply` and expect
   `{"step":"restored","backup_id":...,"volume_id":...,"attachment_id":...,"device":"/dev/oracleoci/oraclevdz"}`.
   Save the output `volume_id` as the restored copy's OCID for step 5.
   The restored volume `restore-gru-1-db-1-data` gets no backup policy and
   attaches only to an instance that is not a member and holds no other
   volume, at `/dev/oracleoci/oraclevdz`, a device no member volume uses.
   The command reads the scratch instance's attachments back before and
   after attaching.
4. Copy the release assets `terrabase-linux-arm64` and
   `terrabase-linux-arm64.sha256` (see [Release files](#release-files)) and
   the `ts-orch` binary and plan to the scratch host. Configure the operator's
   OCI DEFAULT profile there for the read-only provenance check. Pick a document that existed
   before the backup was taken and its organization ID.
5. On the scratch host, dry run:
   `sudo ts-orch terrabase restore-check --plan ./plan.json --compartment <gru-1 workload compartment> --restored-volume <saved restored copy OCID> --binary ./terrabase-linux-arm64 --organization <org> --document /v1/projects/<p>/databases/<d>/collections/<c>/documents/<id> --scratch-instance <scratch OCID>`.
6. Rerun with `--apply` and expect
   `{"step":"verified","ready_path":"/readyz","document":...,"etag":...}`.
   The command re-reads OCI immediately before mounting and requires the
   exact saved OCID and restore tag at the restore device. A swapped volume
   fails before it is read. It mounts the restored volume (never formatting it), starts
   TerraBase on it as a single member with a throwaway certificate, waits
   until client HTTPS `--ready-path` answers 200, creates a `documents:read` API key on
   the loopback admin listener, reads the document over HTTPS, then stops
   TerraBase and unmounts. The API key is written to the restored copy
   only. It mounts only `/dev/oracleoci/oraclevdz`, only on the instance
   whose OCID instance metadata reports as `--scratch-instance`, and refuses
   an orchestrator host, the boot disk, partitions and a mounted device.
   The binary and verification run in a network namespace containing only
   loopback; restored data is unreachable from the host network.
7. Clean up with the OCI CLI or console: detach and delete
   `restore-gru-1-db-1-data`, and terminate the scratch instance. The
   orchestrator has no cleanup command for drill resources yet.

TerraBase `origin/main` `807ad714` serves `/readyz` on the client listener
(`ReadyzEndpoint.cs`, TS-483). It is the default readiness path for the
drill. The document read remains the restore proof.

## Qualification

Unit and real-binary tests are listed in the
[runtime contract](terrabase-runtime-contract.md#qualification).
`make terrabase-release-process TERRABASE_BINARY=<path>` runs the real-binary
deploy, upgrade and rollback test against an in-process controller and host
agent. Nothing in this workflow has run on OCI.

## Retired terrabase-rust managed path

The previous workflow deployed the Rust `tb-server` as a two-member managed
partition with `operator terrabase-deploy`, `terrabase-status`,
`terrabase-update`, `terrabase-sync` and `terrabase-walkthrough`, using
schema-5 placement, controller-prepared member material and retained OCI
volumes. Those commands and their code remain, but they target the retired
binary and must not be used for the C# binary. Git history keeps the full
previous text of this document.
