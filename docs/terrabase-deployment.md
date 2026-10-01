# TerraBase deployment into a running cell

This is the operator workflow after the regional controllers have formed.
One resumable command deploys a two-member TerraBase partition; one command
reports and waits for member state; one command runs the customer walkthrough.
No signed document is written by hand.

The commands are subcommands of the orchestrator binary:

| Command | Effect |
| --- | --- |
| `operator terrabase-deploy --plan FILE --state DIR` | Verifies the release, pushes and admits the artifact, generates identities once, signs the recipient grant, prepares material, opens the customer envelope, renders the schema-5 placement from the signed receipt, and applies it. |
| `operator terrabase-status --state DIR [--wait 30m]` | Prints the controller-signed durable stage of each member, its OCI host, volume and attachment, desired generation, host session, latest host report, and recent placement holds. With `--wait` it reprints only when a member moves and exits 0 once both members serve. |
| `operator terrabase-update --state DIR --qualification F --binary F --source-digest F --compatibility-actor A --compatibility-key F [--wait 20m]` | Rolls a newer TerraBase release across the pair one seat at a time; see [Continuous delivery](#continuous-delivery). |
| `operator terrabase-sync --state DIR --source-checkout DIR --compatibility-actor A --compatibility-key F` | Discovers and verifies a newer published release, then invokes the signed updater; opt-in operator-host timer entry point with durable resume and failure stop. |
| `operator terrabase-walkthrough --state DIR [--forward IP:PORT=127.0.0.1:PORT]...` | Customer scenario over HTTPS: rejected missing, invalid and wrong-tenant credentials, then create, exact retry, cross-member read, update and delete of one disposable document. It uses no controller or NATS access. |

`terrabase-deploy` and `terrabase-status` take the usual `--config
/var/lib/terrascale-operator/operator.json` and `--nats-forward` flags.

## Prerequisites

The deploy command fails closed when any of these is missing; each item names
the step that would hold.

1. **Controller and host image** built from a source that contains the
   workload fixes listed in [Defects fixed for the first deployment](#defects-fixed-for-the-first-deployment).
   Earlier images answer material preparation with a decode error and never
   launch a member.
2. **Controller material IAM.** The controller writes material objects under
   `material/v2/<cell>/...`. The controller policy must grant
   `OBJECT_READ` and `OBJECT_CREATE` on `target.object.name='material/v2/*'`
   in the material bucket. The reviewed statement in
   `ts-orch oci-region preview` still names `material/v1/*`.
3. **Retained-volume device naming.** Placement attaches the data volume
   paravirtualized with PV in-transit encryption, at the lowest free OCI device
   path (`/dev/oracleoci/oraclevdb` for the first data volume), and only to an
   instance that reports consistent volume naming. The image capability schema
   written by `ts-orch oci-region import-image` enables both launch options.
   Inside the guest, `/etc/udev/rules.d/65-terrascale-oci-device-paths.rules`
   (from `deploy/udev/`) links each `ORACLE BlockVolume` disk on the
   virtio-scsi controller to `/dev/oracleoci/oraclevd<x>` by its LUN, as OCI
   assigns them: `a` is LUN 1 (the boot volume), `b` LUN 2, through `af`, LUN 32.
   An image without that rule holds every member at `awaiting-healthy` with the
   device alias missing.
4. **Workload network.** Hosts use the workload-member NSG named in the
   signed `oci-region.json`. Replication uses port 9443 between the two
   member IPs, and the HTTPS client listener uses port 9465 from the Bastion
   endpoint. Hosts reach controllers on 4222 (NATS) and 8443 (enrollment).
5. **LiveS3 credential.** Pin the current Vault secret version. Its content is
   Vault BASE64 of exactly
   `{"version":1,"access_key_id":"…","secret_access_key":"…"}`. Hosts read it
   with instance principals through the host LiveS3 secret policy, and use
   native Object Storage for the `tb-roots/v2/` and
   `tb-object-probes/v1/native-oci-update/` prefixes of the live bucket.
6. **Recipient keys owned by the operator user.** The operator runs as root
   because `operator.json` is root-only, and private keys must be owned by
   the process user:

   ```sh
   sudo install -d -o root -g root -m 0700 /var/lib/terrascale-operator/recipient
   sudo install -o root -g root -m 0600 KEYS/recipient-signer.private.pem KEYS/recipient.private.pem \
     /var/lib/terrascale-operator/recipient/
   sudo install -o root -g root -m 0644 KEYS/recipient-signer.public.pem /var/lib/terrascale-operator/recipient/
   ```

   The recipient signer must be the one pinned by the controllers' signed
   material domain.

## Plan

Members are in placement seat order: the first member is the permanent seat
and must use the controller's first configured fault domain. For the GRU
preview:

```json
{
  "version": 1,
  "placement_database_id": "preview",
  "partition_id": "p1",
  "role": "terrabase",
  "environment": "canary",
  "release": {
    "qualification": "/RELEASE/qualification.json",
    "binary": "/RELEASE/tb-server-linux-arm64",
    "source_digest": "/RELEASE/source-digest-candidate-v1.json"
  },
  "host_profile": {
    "compute": {"shape": "VM.Standard.A1.Flex", "whole_ocpus": 1, "memory_in_gbs": 6},
    "process_memory_bytes": 4294967296,
    "memory_headroom_bytes": 1073741824,
    "cgroup_memory_max_bytes": 4294967296,
    "system_reserve_bytes": 1073741824,
    "allocatable_memory_bytes": 4294967296
  },
  "managed_runtime_root": "/srv/ts-managed",
  "members": [
    {"private_ip": "10.251.0.21", "fault_domain": "FAULT-DOMAIN-1"},
    {"private_ip": "10.251.0.22", "fault_domain": "FAULT-DOMAIN-2"}
  ],
  "replication_port": 9443,
  "client_port": 9465,
  "live_s3": {
    "bucket": "ts-preview-gru-20260926-terrabase-live",
    "region": "sa-saopaulo-1",
    "endpoint": "https://grxnmoqvrcdv.compat.objectstorage.sa-saopaulo-1.oci.customer-oci.com",
    "credential": {"secret_ocid": "LIVE_S3_SECRET_OCID", "version_number": 2},
    "native_oci_root": {"namespace": "grxnmoqvrcdv"}
  },
  "collections": 1,
  "recipient": {
    "signer_key": "/var/lib/terrascale-operator/recipient/recipient-signer.private.pem",
    "signer_public_key": "/var/lib/terrascale-operator/recipient/recipient-signer.public.pem",
    "recipient_key": "/var/lib/terrascale-operator/recipient/recipient.private.pem",
    "grant_validity_hours": 168
  }
}
```

The release files are one TerraBase CI release: its `qualification.json`
(schema `terrascale.terrabase.qualification.v2`, successful Fast run), the
ARM64 `tb-server` whose size and SHA-256 match it, and the accepted
prepared-source digest record for the same revision, qualification and
server bytes. The source digest is the artifact's source claim; the Git tree
SHA-1 is not.

This orchestrator pairs with TerraBase releases that contain `dfa00c40`
(named JSON documents; TerraBase `main` from `b05b0828` onward). Their client
API addresses document fields by name: the walkthrough writes
`{"kind":"live","document":{"title":"…"}}` without a catalog generation,
digest or field ID. Earlier TerraBase releases, such as `743c569` in the R22
preview with orchestrator `7aae8102`, accept only the removed typed write and
reject it. The generation-one deployment catalog is unchanged, so material
and updates do not depend on the pairing, but a state directory written by
an earlier orchestrator holds a version-1 `customer/client.json` that this
walkthrough cannot read. Keep each candidate pair together.
`make terrabase-walkthrough-process TERRABASE_SERVER=<tb-server>` runs this
walkthrough against two local members serving freshly generated deployment
material, with a `tb-server` built from the paired TerraBase revision.

The memory profile is the tightest that TerraBase and the host accept on a
1 OCPU / 6 GB A1 guest: process and cgroup limits of 4 GiB, 1 GiB headroom,
and the image's 1 GiB system reserve. TerraBase replication admission also
requires `memory.current + request + 512 MiB <= memory.max`; page cache
counts toward `memory.current`, so a sustained write burst can defer
replication admission.

## Run

Use the cell's own qualified operator CLI: `ts-orch oci-region attempt operator` verifies it
and prints its path. Signed command and artifact claims change between
revisions, so a CLI from another revision is rejected by the controllers.

```sh
F=(--nats-forward 10.251.0.11:4222=127.0.0.1:14222)
sudo terrascale-orchestrator operator terrabase-deploy --config /var/lib/terrascale-operator/operator.json \
  "${F[@]}" --plan PLAN.json --state /var/lib/terrascale-operator/terrabase-preview-p1
sudo terrascale-orchestrator operator terrabase-status --config /var/lib/terrascale-operator/operator.json \
  "${F[@]}" --state /var/lib/terrascale-operator/terrabase-preview-p1 --wait 45m
sudo terrascale-orchestrator operator terrabase-walkthrough --state /var/lib/terrascale-operator/terrabase-preview-p1 \
  --forward 10.251.0.21:9465=127.0.0.1:19465 --forward 10.251.0.22:9465=127.0.0.1:19466
```

`terrabase-deploy` prints one JSON line per step (`identity`, `artifact`,
`spec`, `material`, `customer`, `placement`, `deploy`) with `generated`,
`signed`, `prepared`, `opened`, `admitted` or `reused`. Rerun the same
command after any failure: completed steps are reused, and the artifact and
placement admissions are idempotent. A different plan with the same state
directory is rejected; deploy a changed plan with a new state directory and
partition ID.

The recipient grant is valid for `grant_validity_hours` (at most 30 days).
Material preparation checks it, so rerun within that window if preparation
has not completed. After preparation the retained reply is used and the
grant is not checked again.

### State directory

The directory and every file are owner-only and written once.

| File | Content |
| --- | --- |
| `identity.json` | Cluster, tenant, database, member, incarnation, filesystem and collection identities plus the plan pins they were generated for. |
| `artifact.json` | The admitted artifact record. |
| `spec.json` | The signed generation-one material spec. |
| `material-reply.json` | The controller-signed preparation receipt and customer envelope. |
| `customer/credentials.json` | The customer API key and HTTPS CA. Secret. |
| `customer/https-ca.pem` | The HTTPS CA. |
| `customer/client.json` | Version 2: tenant, database, shard, member URLs, and for each collection its UTF-8 field names and the catalog generation and digest that its live documents report. |
| `placement-intent.json` | The applied schema-5 placement intent. |
| `placement-receipt.json` | The first admission receipt. |

## Member stages

`terrabase-status` reports the durable placement stage of each seat:
`prepared-host` → `awaiting-host` (instance launched, waiting for host
enrollment) → `prepared-volume` → `prepared-attach` → `awaiting-attach` →
`awaiting-runtime-contract` → `prepared-desired` → `awaiting-healthy`
(desired written; host fetching material, formatting and mounting the
volume, starting TerraBase) → `serving` (a fresh host report carries
TerraBase's serving proof for the exact member, authority and peer). `host`
shows the host's session and latest report for the member; `holds` shows the
controller's recent reasons for not advancing, including reconciliation
errors. The report is signed by the controller response key pinned in the
operator config.

## Continuous delivery

A published TerraBase release reaches both members through signed managed
updates, one seat at a time:

1. `terrabase-update` verifies the release files exactly as deploy does and
   pushes and admits the artifact.
2. For the first seat in placement order that does not run the release, it
   signs a Prepare that pins both seats as the controller reports them, with
   a compatibility statement signed by a separate compatibility signer.
3. The controller writes the candidate desired for that seat only. The seat
   must return a fresh serving proof for the candidate within 15 minutes;
   otherwise, or when the host reports the candidate failed, the controller
   holds it. The peer keeps serving the prior artifact either way.
4. After the canary serves, the command updates the peer the same way, then
   reports `rollout complete`.
5. A held seat is rolled back to the artifact its candidate replaced, and the
   command fails with the held outcome. No held candidate is ever promoted
   to the peer.

The controller keeps every step durable: a later release replaces a served
target and records the artifact and source it replaced, a successor
operation is admitted only after the previous operation's outcome, and a
completed seat stays current for material delivery and volume checks after
later operations. Rerunning the command resumes from that state; a
completed rollout does nothing. A binary rollback is only safe while the
persistent format stays readable by the older release; the compatibility
statement is the assertion that it does.

### Running it on every release

`operator terrabase-sync` implements the timer entry point described below.
See [Continuous delivery](continuous-delivery.md) for its invocation,
provenance/ancestry gates, durable pin and stop marker, rollout policy and
human signing decisions. It is not enabled on any live cell by this change.

The command runs where the operator config and a Bastion forward already
exist. The simplest trigger is a timer on that operator host that, for each
new successful TerraBase `main` release, downloads `qualification.json`,
`tb-server-linux-arm64` and the release's prepared-source digest record with
`fj release asset download`, opens a Bastion forward to one controller, and
runs `terrabase-update`. A Forgejo job cannot do this without holding the
operator's NATS credentials, two signing keys and OCI Bastion credentials in
repository secrets, and the controllers have no route to Forgejo.

This needs three decisions:

- **Update and compatibility signers.** The current GRU operator grant has
  neither `can_update_terrabase_runtime` nor a compatibility signer, so
  managed updates are refused. A new signed controller config must add an
  automation actor with `can_update_terrabase_runtime` and
  `can_place_terrabase`, and a separate actor with
  `can_certify_terrabase_compatibility`. Both grants must list the
  `terrabase` role and the `canary` and `production` environments, and the
  update actor the TerraBase repository. Their private keys live on the
  operator host, owner-only.
- **What the compatibility signature asserts.** Today it would assert that
  every release on `main` keeps mixed-version replication, client data and
  persistent formats compatible with the release it replaces. Either accept
  that as TerraBase policy, or have TerraBase CI publish a compatibility
  result per release that the timer checks before signing.
- **Source digest in the release.** TerraBase CI publishes no
  prepared-source digest record. Its release job should publish
  `source-digest.json` (schema `terrascale.terrabase.source-digest-candidate.v1`)
  next to `qualification.json`, so the timer needs no TerraBase checkout.

## Offline qualification

`internal/app/operator_terrabase_deploy_integration_test.go` runs the real
`operator terrabase-deploy` and `terrabase-status` against an in-process
cell: embedded NATS, the authority log, artifact admission, material
preparation with the controller's signed receipt, placement admission with
material verification, the placement controller, host registration and
sessions, and an in-memory OCI region. It checks both hosts' launch requests,
volume creation and attachment, the desired launch pins, that the controller
delivers exactly the pinned material bytes to each host, that volume
initialization accepts the seat, resume and changed-plan behavior, and that an
instance without consistent volume naming is held before attachment with the
reason in status. It does not run the host's mount, native runner or
`tb-server`; the Firecracker harness and the live hosts cover those.

`internal/placement/managed_update_rolling_test.go` drives the controller's
managed updates against the real authority log: release 2 on the canary
seat, then the peer, release 3 chained on the canary, held at its proof
deadline with the peer serving, promotion refused, and the seat rolled back.
`internal/app/operator_terrabase_update_test.go` runs `terrabase-update`
against the real cell's artifact admission and admission checks, including
resume and rollback of a failing release.

## Defects fixed for the first deployment

These were found by the offline chain and source review. Each needs the
controller and host image rebuilt from a source that contains it.

| Defect | Effect before the fix |
| --- | --- |
| Controller NATS credentials grant no `material.*` subscription | Material preparation, credential rotation and status had no responder. Managed requests now share the granted admission subject. |
| Desired and runtime-target verifiers read member state by TerraBase member UUID instead of placement seat | Every initial managed desired write failed; volume initialization could not verify its seat. |
| Hosts never created the per-attempt member, material and control directories | Material delivery failed on a fresh host; only test harnesses pre-created them. |
| The mount check required one mountinfo entry | Inside the host unit's mount namespace the volume appears once per slave copy of `/srv/ts-managed`; every live mount was rejected. |
| No operator view of placement stages | Launch, volume and attachment progress was only in controller logs. |
| Managed update stopped after one canary seat | A release never reached the peer, a second release could not start, and a held candidate had no recovery. |
| The image had no OCI device-path rule, and the fleet picked `oraclevdaa` | The host never found `/dev/oracleoci/oraclevd*`, so no volume could be formatted or mounted. |
