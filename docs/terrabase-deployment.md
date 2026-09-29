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
   `deploy/oci-region/preview.py` still names `material/v1/*`.
3. **Retained-volume device naming.** Placement attaches the data volume
   only to an instance that reports consistent volume naming, requests PV
   in-transit encryption, and the host resolves the attachment through a
   root-owned `/dev/oracleoci/oraclevd*` symlink. The imported R5 image
   reports both launch options false and ships no OCI naming udev rule, so
   placement holds at `prepared-attach` with a "consistent volume naming"
   reconciliation error in `terrabase-status`.
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

The memory profile is the tightest that TerraBase and the host accept on a
1 OCPU / 6 GB A1 guest: process and cgroup limits of 4 GiB, 1 GiB headroom,
and the image's 1 GiB system reserve. TerraBase replication admission also
requires `memory.current + request + 512 MiB <= memory.max`; page cache
counts toward `memory.current`, so a sustained write burst can defer
replication admission.

## Run

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
| `customer/client.json` | Tenant, database, shard, collections with schema digest and fields, member URLs. |
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

Open items outside this workflow are listed in the prerequisites: material
IAM (`material/v2/*`), image device naming and in-transit encryption, and the
NSG ports.
