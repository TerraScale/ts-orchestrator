# Manual regional bootstrap

This runbook describes setup of a regional foundation and its first
controller, followed by the identity and authority handoff to
`ts-orchestrator`. The current authorized qualification target is GRU
(`sa-saopaulo-1`): the assistant operates this runbook for the foundation,
controller A, and required credential/image prerequisites instead of leaving
those provisioning steps to the user. Use the OCI CLI to get or create required
Vault secrets where they are runbook inputs. Publish generated controller
material through the documented `ts-bootstrap provision-controller-material`
flow, which binds the material to authenticated readback and current cost
admission. After the explicit controller-A handoff, `ts-orchestrator` alone
owns B/C, the ARM workload hosts, and signed TerraBase deployment. The
bootstrap tools accept these fixed cell-to-region
mappings: GRU / `sa-saopaulo-1`, SFO / `us-sanjose-1`, and FRA /
`eu-frankfurt-1`. The checked-in regional plan is a concrete GRU example; a
different mapped cell needs its own reviewed plan populated with that cell's
live resource IDs and signed genesis. This is an operating procedure, not
evidence that a region has been deployed or that the system is
production-ready. See the [workspace GOAL](../../GOAL.md) and the
[shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md)
for current scope and evidence.

## Supported scope and ownership

`generate-controller-material`, the first-seed commands, and the preview
helper validate only the three mappings listed above. The checked-in
`deploy/oci-region/plan.json` remains populated for GRU, including its existing
Forgejo resources. For SFO or FRA, copy it to a separate reviewed plan and fill
the cell, region, tenancy, availability domain, compartments, network, Vault,
key, buckets, IAM identities, host credential secret, resource inventory, and
cell-specific host profiles. Changing only `cell` and `region` is not enough.
The plan and signed genesis must agree on the cell, region, controller
endpoints, image, and launch profiles.
The preview plan currently accepts `VM.Standard.A1.Flex` for its host profiles;
the seed preflight binds controller A to the exact reviewed profile. Other
shapes are outside this procedure.

`render-host-enrollment-public` accepts reviewed material for all three mapped
cells. It derives the public bundle's cell, environment, region, and
controller/NATS endpoints from the material record; the CA comes from its
matching owner-only source and must match the digest in that record. Use a
separate reviewed plan and matching material for each cell; do not reuse the
GRU example for SFO or FRA. See the
[Managed host image](production-role-config.md#managed-host-image) section for
the renderer invocation and image binding. The bundle is public JSON pinned by
SHA-256 during the image build, not a signed envelope. The GRU/SFO
managed-enrollment integration uses local NATS and a fake OCI provider; it is
not live OCI or VM qualification, and rendering a bundle does not show that a
cell has been deployed.

| Resources or action | Owner in this flow |
| --- | --- |
| Regional foundation, bootstrap material, and first controller A | Runbook operator; assistant for the currently authorized GRU qualification, until explicit identity, authority, and inventory handoff |
| Controllers B and C in the admitted cell | `ts-orchestrator` founder after the handoff |
| ARM managed workload hosts, persistent volumes, enrollment, and workload deployment | `ts-orchestrator` through its reviewed runtime path after the required cell-specific enrollment bundle is available |
| Shared Email Delivery | `ts-infra` (four email resources) |

The handoff is a real ownership boundary. Do not launch B or C manually, run a
second resource manager against the same regional resources, or depend on a
`ts-infra` output or Terraform receipt to establish regional readiness. As of
`ts-infra` main commit `e347f13a313ebb2b9d0a0b631ba0aed56af65126`, its guarded
workflow manages only the four Email Delivery resources. The former regional
Terraform definitions and regional workflow were removed from that source.
The preceding state-only handoff removed 24 OCI resource addresses and one
local propagation marker from Terraform state without creating, changing, or
destroying OCI resources; this is ownership bookkeeping, not evidence of
regional resource health or a live controller. For the current GRU lane, the
assistant as runbook operator prepares the regional network, IAM, and bootstrap
inputs and starts controller A; after the
explicit identity, authority, and inventory handoff, `ts-orchestrator` forms
B/C and manages the ARM workload hosts and TerraBase deployment.

## Before creating resources

1. Select one of the three fixed cell-to-region mappings above. Start from a
   reviewed copy of `deploy/oci-region/plan.json`; for SFO or FRA, populate the
   complete mapped-cell plan and do not edit the shared GRU example in place.
   Identify the tenancy, compartments, availability domain, owner, resource
   namespace, and exact IDs. Preserve unrelated and existing resources.
2. Configure the OCI CLI `DEFAULT` profile for the selected tenancy and
   principal. The Python preview helper invokes `oci` without a profile
   argument, so live inventory and readback use that default profile. The Go
   commands below use `--oci-profile DEFAULT`; configure that SDK profile with
   the same identity and target region. The helper passes the plan's region to
   regional OCI commands and records ready subscriptions and live inventory.
3. Before creating the foundation, capture and review current inventory and a
   cost admission:

   ```sh
   python3 deploy/oci-region/preview.py inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   python3 deploy/oci-region/preview.py admit \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --out /ABSOLUTE/PATH/cost-admission.json
   ```

   These commands are read-only. The inventory covers subscribed regions and
   resources in the plan's scoped compartments, including existing buckets and
   retained resources used by the estimate. The estimate is not an OCI spending
   limit. Repeat inventory and admission after foundation creation; admission
   expires after 15 minutes.
4. Prepare an itemized estimate for all required compute, boot and data
   storage, networking, object storage, and retained resources. Include
   quantities and durations, verify free allowances, and keep the combined
   qualification and preview estimate within the combined **US$200/month**
   ceiling. Use a qualified plan and CLI revision whose configured limit and
   validator match this authority; never bypass admission or edit its receipt.
   This ceiling is not a hard spending control and does not replace the current
   GRU authorization or the runbook's remaining gates.
5. Review the foundation and security configuration against the signed cell
   plan. The controller dynamic group must match only instances in the
   controller compartment, for example:

   ```text
   ALL {instance.compartment.id = '<control-compartment-ocid>'}
   ```

   Review the controller's policy scopes against the signed plan:

   | Controller permission | Action and compartment scope |
   | --- | --- |
   | Instance and volume provisioning | `manage instance-family` and `manage volume-family` in the control and workload compartments |
   | VNIC and network configuration | `use virtual-network-family` in the network compartment |
   | Image lookup | `read instance-images` in the control compartment |
   | Controller material | `read secret-bundles` in the dedicated controller/Vault compartment |
   | Bootstrap ledger and encryption | Object Storage and KMS grants scoped to the exact configured buckets and keys |

   Managed workload hosts must not match the controller dynamic group. Give
   hosts a separate dynamic group that matches only the planned workload
   compartment. Select and record both the secret compartment OCID and exact
   `LiveS3Credential` secret OCID explicitly: the signed OCID/version reference
   does not provide the compartment needed to derive that IAM scope. Attach
   this policy to the selected secret compartment:

   ```text
   Allow dynamic-group <host-dynamic-group> to read secret-bundles in compartment id <secret-compartment-ocid> where target.secret.id = '<exact-secret-ocid>'
   ```

   Review attached and inherited policies to ensure hosts have no compute,
   volume, network, Object Storage, or KMS grants. The inspector checks the
   named host dynamic group and exact secret policy, but does not establish
   that no other policy grants access. These are required configuration checks,
   not evidence that OCI has granted or live-tested each permission. Image read
   permission alone does not authorize peer or workload provisioning.

   Also check Vault/KMS and Object Storage access, private routes,
   service-gateway routes, and network security rules against the signed plan.
   The source plan may pin these values, but do not claim an automated check
   for any field unless the frozen inspector actually checks it.
6. A stale inventory, expired admission, mismatched region or resource ID, or
   cost above the ceiling is a stop condition. The ceiling is an admission
   condition and remains a constraint on each resource action.

## Inter-region private networking (future authorization only)

The current GRU qualification requires no inter-region link. Its reviewed plan
uses VCN `10.251.0.0/24` and a local Oracle Services Network service-gateway
route; it declares no DRG, remote peering connection (RPC), peer route, or peer
ingress rule. Do not make another cell or a private link a GRU acceptance
condition, and do not append a DRG route to the GRU example.

For a separately reviewed pair, the `inspect-private-peer` subcommand in
`deploy/oci-region/preview.py` accepts `--pair-intent`, `--left-plan`,
`--left-inventory`, `--left-admission`, the corresponding `--right-*` paths,
and `--out`. It makes read-only OCI CLI calls and writes a hash-bound
configuration receipt. It checks disjoint RFC1918 VCN and subnet ranges,
reciprocal connected RPCs and attachments, exact subnet and DRG routes and
import distributions, scoped peer security rules, and each region's existing
local service-gateway route. This command does not change the GRU-only plan,
provision another region, or gate the current GRU launch.

The receipt reports each regional estimate separately and sets
`budget_admission.status` to `blocked`: the per-region estimates repeat shared
resource baselines and apply free allowances independently, so they cannot
prove the combined USD 200 monthly ceiling. The receipt is configuration
readback only. It does not test private endpoint reachability, verify
application mTLS, or establish signed runtime peer consumption or native
replication readiness. Complete those checks through separately authorized
network testing and the later `ts-orchestrator` runtime ownership path.

Before enabling cross-region member replication or required inter-cell control
traffic, the regional foundation operator owns steps 1–4 through authenticated
OCI readback. After controller A's identity, authority, and inventory handoff,
`ts-orchestrator` owns step 5 through signed runtime state:

1. Confirm that the destination region is subscribed and in the tenancy's
   realm, and review tenancy limits, cost admission, and ownership. Choose VCN
   CIDRs that do not overlap each other or GRU's `10.251.0.0/24`.
2. Attach a DRG to each VCN and create and connect the two named RPCs using
   Oracle's [remote VCN peering procedure for upgraded DRGs](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/scenario_e.htm).
3. Configure each upgraded DRG's route tables and import distributions to
   admit only the approved paired VCN/RPC routes. Add reciprocal rules for only
   the approved peer subnet CIDRs in each VCN's subnet route table, targeting
   that VCN's DRG. Permit only the required replication and control ports from
   the peer CIDRs in the applicable NSG and security-list rules. Keep each
   region's service-gateway route local; do not use the peer as transit for OCI
   services or unrelated networks.
4. Before runtime traffic or handoff, record OCI readback for both VCN/DRG
   attachments, DRG route tables and import distributions, connected RPC state,
   subnet routes, and network security rules.
   Check private endpoint reachability and that unrelated peer paths remain
   denied.
5. Publish the reviewed private peer IP and port and matching trust material
   through the signed runtime ownership path. Keep TerraBase replication mTLS
   and signed member-authority checks: private addressing and OCI's documented
   inter-region MACsec protection between data centers do not authenticate a
   TerraBase member.

Oracle's [VCN FAQ](https://www.oracle.com/cloud/networking/virtual-cloud-network/faq/)
says remote VCN peering has no separate charge; outbound transfer charges still
apply after the applicable allowance. Use the current
[networking price list](https://www.oracle.com/cloud/price-list/#pricing-networking)
to estimate outbound usage from both regions against the allowance and the
combined monthly ceiling. Do not assume an allowance per RPC, pair, or direction,
or a private-peering bandwidth discount. Select peering for private addressing
and the intended network boundary.

## Bootstrap sequence

1. Create the reviewed regional foundation under the selected ownership
   boundary only after the pre-create inventory, capacity, security, and cost
   review passes. Record the exact compartment, network, routing, security,
   Vault/KMS, IAM, and bootstrap-storage identities. Do not rely on an old
   Terraform plan or receipt as proof of current live state.
2. Update the reviewed plan with the exact created resource IDs and capture a
   fresh inventory and cost admission. Inspect that live foundation before
   proceeding:

   ```sh
   python3 deploy/oci-region/preview.py inventory \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --out /ABSOLUTE/PATH/manual-inventory.json

   python3 deploy/oci-region/preview.py admit \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --out /ABSOLUTE/PATH/cost-admission.json

   python3 deploy/oci-region/preview.py inspect-foundation \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --out /ABSOLUTE/PATH/foundation-readback.json
   ```

   The inspector performs live reads for the plan-bound compartments, Vault
   and KMS key, network and rules, buckets and retention, controller dynamic
   group and policy, and the selected workload-host dynamic group and
   `LiveS3Credential` secret policy. It writes a readback bound to the plan and
   inventory hashes, with the tenancy, cell, region, compartment, Vault, and key
   identities and inspection time. It does not create resources, prove there
   are no other inherited or separately attached IAM grants, or authorize a
   write. Keep the exact output and its SHA-256.
3. Create the owner-only local material source with `generate-controller-material`
   as described in [production role configuration](production-role-config.md).
   Hash the reviewed config, then generate the source and public record:

   ```text
   ts-bootstrap generate-controller-material \
     --config /ABSOLUTE/PATH/controller-material.json \
     --config-sha256 CONTROLLER_MATERIAL_CONFIG_SHA256 \
     --directory /ABSOLUTE/PATH/controller-material \
     --out /ABSOLUTE/PATH/controller-material-record.json
   ```

   The config binds the mapped cell and region, deployment and cluster IDs,
   controller slots, addresses, and validity. Keep the local directory
   owner-only and outside the checkout. Its public record and generated PEMs
   do not contain private key bytes.
4. After the live readback and current budget admission pass, publish the
   versioned Vault material and public reference record with:

   ```text
   ts-bootstrap provision-controller-material \
     --directory /ABSOLUTE/PATH/controller-material \
     --manual-readback /ABSOLUTE/PATH/foundation-readback.json \
     --manual-readback-sha256 MANUAL_READBACK_SHA256 \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --inventory-sha256 MANUAL_INVENTORY_SHA256 \
     --cost-admission /ABSOLUTE/PATH/cost-admission.json \
     --cost-admission-sha256 COST_ADMISSION_SHA256 \
     --cost-plan-sha256 MANUAL_PLAN_SHA256 \
     --oci-config /ABSOLUTE/PATH/oci-config --oci-profile DEFAULT \
     --out /ABSOLUTE/PATH/controller-material-references.json
   ```

   The readback must be authenticated and no more than 15 minutes old. The
   supplied readback, inventory, admission, and plan digests must match the
   exact files; the admission must be current and within the US$200/month
   ceiling. The OCI profile's tenancy and region must match the readback. The
   output path must be new and outside the owner-only source directory. Record
   the public reference output and SHA-256 of it and the associated PEM files.
5. Prepare and sign the cell identity, anchor, manifests for controller A/B/C,
   and founder plan from the reviewed target and live resource inventory. Keep
   root signing keys and private controller material in their owner-controlled
   stores; never put secrets in the image, user-data, evidence bundle, or
   command output.
6. Run the read-only seed preflight against the current plan, inventory,
   admission, signed anchor and controller-A manifest, and signed image receipt.
   It verifies the manifest and image through the supplied Go tools, repeats
   live foundation/IAM reads, checks the exact controller-A profile, and writes
   the reviewed launch record. It does not create an OCI instance:

   ```sh
   python3 deploy/oci-region/preview.py seed-preflight \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --inventory /ABSOLUTE/PATH/manual-inventory.json \
     --admission /ABSOLUTE/PATH/cost-admission.json \
     --bootstrap-tool /ABSOLUTE/PATH/ts-bootstrap \
     --anchor /ABSOLUTE/PATH/anchor.signed.json \
     --manifest /ABSOLUTE/PATH/controller-a.manifest.json \
     --identity /ABSOLUTE/PATH/identity.json \
     --bootstrap-root /ABSOLUTE/PATH/bootstrap-root.pub \
     --image-ocid EXACT_IMAGE_OCID \
     --release-tool /ABSOLUTE/PATH/ts-release \
     --image-receipt /ABSOLUTE/PATH/image-receipt.signed.json \
     --release-delegation /ABSOLUTE/PATH/release-delegation.signed.json \
     --release-root /ABSOLUTE/PATH/release-root.pub \
     --image-file /ABSOLUTE/PATH/controller-image.qcow2 \
     --base-image-file /ABSOLUTE/PATH/base-image.qcow2 \
     --kernel-file /ABSOLUTE/PATH/kernel \
     --out /ABSOLUTE/PATH/reviewed-seed-plan.json
   ```

   Keep the exact output and SHA-256. Use the output's `create_identity` value
   for the reservation and the controller-A `BootstrapCreateKey` tag. If the
   reviewed plan sets `seed_a_create_identity`, preflight carries that value;
   otherwise it derives one from the reviewed plan, manifest, anchor, and image
   receipt. Do not substitute another value after preflight. The first-seed
   signing, observation, and fresh completion commands bind to this file and
   digest. Renewed inventory or admission requires a new preflight.
7. Generate user-data from the same signed controller-A manifest:

   ```sh
   python3 deploy/oci-region/preview.py seed-user-data \
     --plan /ABSOLUTE/PATH/manual-region-plan.json \
     --manifest /ABSOLUTE/PATH/controller-a.manifest.json \
     --owner-ssh-public-key /ABSOLUTE/PATH/owner-ed25519.pub \
     --out /ABSOLUTE/PATH/controller-a-user-data.yaml
   ```

   `--owner-ssh-public-key` is optional and accepts one Ed25519 public key.
   The helper writes the user-data file with mode `0600`; it includes the signed
   manifest envelope, not private controller keys or Vault secret contents.
   Before controller A starts, the boot command installs that exact manifest
   at
   `/etc/terrascale-orchestrator/controller-seed-manifest.json` as a regular
   root-owned `0644` file. The installed controller units are ordered after
   cloud-init's network stage, online networking, and time synchronization.
   Do not add a blocking installer start to cloud-init `bootcmd`, which runs
   before `network-online.target`.
8. Before creating controller A, sign and publish its exact seed reservation.
   Use the create identity from the reviewed seed plan without changing it:

   ```text
   ts-bootstrap sign-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json \
     --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reviewed-plan /ABSOLUTE/PATH/reviewed-seed-plan.json \
     --reviewed-plan-sha256 REVIEWED_SEED_PLAN_SHA256 \
     --create-identity EXACT_PREFLIGHT_CREATE_IDENTITY \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-reservation.json

   ts-bootstrap publish-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json \
     --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json \
     --oci-config /ABSOLUTE/PATH/oci-config --oci-profile DEFAULT
   ```

   Do not launch controller A until the exact signed reservation is published.
9. Start only controller A using one OCI CLI launch-input JSON file. The file
   is input to `oci compute instance launch --from-json`, not a raw request
   body copied from an SDK example. Check the installed command input with
   `oci compute instance launch --generate-full-command-json-input`. Put the
   default VNIC's `subnetId`, `privateIp`, `nsgIds`, and `assignPublicIp` at
   the top level; `--subnet-id` is required, and nested SDK `createVnicDetails`
   values are not a substitute for these CLI fields. Keep every value bound
   to the reviewed seed profile and current signed inventory:

   ```json
   {
     "availabilityDomain": "<REVIEWED_AVAILABILITY_DOMAIN>",
     "faultDomain": "<REVIEWED_FAULT_DOMAIN>",
     "compartmentId": "<REVIEWED_COMPARTMENT_OCID>",
     "displayName": "controller-a",
     "shape": "VM.Standard.A1.Flex",
     "shapeConfig": {"ocpus": 1, "memoryInGBs": 6},
     "sourceDetails": {
       "sourceType": "image",
       "imageId": "<SIGNED_IMAGE_OCID>",
       "bootVolumeSizeInGBs": 50,
       "bootVolumeVpusPerGB": 10
     },
     "subnetId": "<REVIEWED_SUBNET_OCID>",
     "privateIp": "<RESERVED_CONTROLLER_A_PRIVATE_IP>",
     "nsgIds": ["<SIGNED_NSG_1_OCID>", "<SIGNED_NSG_2_OCID>"],
     "assignPublicIp": false,
     "userDataFile": "/ABSOLUTE/PATH/controller-a-user-data.yaml",
     "metadata": {
       "terrascale-bootstrap": "{\"schemaVersion\":1,\"slot\":\"controller-a\"}"
     },
     "freeformTags": {
       "BootstrapCreateKey": "<EXACT_PREFLIGHT_CREATE_IDENTITY>"
     }
   }
   ```

   Use the shape and boot-volume values from the signed profile if they differ
   from this validated A1 example. The `terrascale-bootstrap` metadata value
   is the exact v1 descriptor for the first slot in the signed anchor; it is
   an untrusted slot locator, not an authority or a replacement for signed
   manifest and OCI identity checks. `userDataFile` supplies cloud-init data;
   it does not populate this metadata key. Do not synthesize
   `terrascale_hostboot_v1` for this controller-only seed; managed-host
   descriptors must come from the signed placement path.

   If the seed metadata key is missing after launch, do not submit a partial
   metadata map as though OCI will merge it. `UpdateInstance` replaces the
   metadata map: start from an authenticated current instance readback, retain
   the exact existing `user_data`, and use the current ETag with `If-Match`.
   OCI does not allow changing `user_data` after launch. Re-read the metadata
   after an update and rerun the observer; do not sign completion on the
   update response alone.

   Leave `launchOptions` absent unless the reviewed profile explicitly
   requires an override. This launch uses OCI's default firmware and boot
   volume options. Submit the file with the configured profile and region:

   ```sh
   oci compute instance launch \
     --config-file /ABSOLUTE/PATH/oci-config \
     --profile DEFAULT \
     --region <REVIEWED_REGION> \
     --from-json file:///ABSOLUTE/PATH/controller-a-launch-cli.json
   ```

   Record the exact OCI instance OCID returned by the CLI. OCI accepting the
   launch request is not proof that the signed network profile was applied.
10. Re-read controller A, its primary VNIC, and boot-volume sizing with
    `ts-bootstrap observe-external-seed`, then compare them with the reviewed
    plan before signing anything. Require the exact instance in `RUNNING`,
    the exact `BootstrapCreateKey`, signed image and shape, primary VNIC on
    the reviewed subnet and reserved private IP, both signed NSGs, and no
    public IP. Require the attached boot volume to report the signed image
    and exact requested size and VPU setting. Any missing or different field
    must make observation fail. Do not sign or publish completion, refresh
    inventory, or hand off controller A after a failed observation. A launch
    with VNIC settings only under nested `createVnicDetails` previously
    produced the wrong private IP and no NSGs, and the observer rejected that
    instance.

    After observation succeeds, sign the resulting completion bundle offline
    with `ts-bootstrap sign-external-seed-completion`, then publish it with
    `ts-bootstrap publish-external-seed-completion`. Follow steps 4 and 5 in
    [Initial founder authority](founder-genesis-cli.md#first-external-seed-transaction)
    for the exact flags. Do not hand off controller A until completion
    publication succeeds or its exact uncertain outcome is reconciled.
    Before any later inventory or admission refresh, use a new plan copy with
    `resource_ids.instances.controller-a` set to A's exact OCID and
    `seed_a_create_identity` set to the preserved preflight value. The helper
    rejects post-launch inventory if A's exact OCID and `BootstrapCreateKey`
    are not recorded. Preserve the original preflight-bound plan and evidence.
11. Completion publication records the observed seed reservation; it does not
    prove that the controller's signed bootstrap gate admitted A. Before
    handoff, require the controller to complete its current signed anchor,
    slot, image, credential, and founder-floor checks. A failed or pending gate
    holds the handoff even when OCI readback and completion publication passed.
    Then explicitly hand controller A's identity, authority, and inventory to
    the orchestrator owner. The admitted founder launches only the signed
    same-cell B/C peers. Preserve the signed plan and exact IDs so retries and
    reconciliation use the same intent. Do not create replacement seed
    instances to resolve an uncertain handoff or publication result.
12. After the cell is running, the read-only NATS topology/availability helper
    can report controller and JetStream metadata:

    ```sh
    go build -trimpath -o /tmp/natsdiag tests/firecracker/natsdiag.go
    /tmp/natsdiag \
      --controller-config /etc/terrascale-orchestrator/controller.json \
      --phase steady
    ```

    This is a topology and availability diagnostic. It does not establish
    durable recovery, verify the OCI launch, or prove live deployment or
    production readiness. Use the reviewed deployment evidence procedure for
    those claims.

The detailed founder-object formats and seed transaction are documented in
[Initial founder authority](founder-genesis-cli.md). Use that page together
with the frozen CLI help and reviewed plan for the source revision being
operated; do not copy a command from an older OpenTofu-based seed procedure.

## Stop conditions and limits

Stop before a write if the current live readback, signed plan, image, cell,
compartment, network, shape, or cost admission disagree. Stop if the signed
plan or admission expires. For an uncertain result, reconcile using the exact
preserved transaction and evidence; do not create a second A or change the
intent to make a retry pass. Record mismatches and route them to the owner of
the resource or signed plan.

This procedure covers one cell's manual first-controller boundary for the
three fixed mappings above, subject to the host-enrollment limitation. It does
not establish cross-region replication, continuous management during controller
loss, database serving, a live SFO/FRA deployment, or production readiness.
Those require their own current source and runtime evidence.

The post-handoff owner for ARM workload hosts and TerraBase also owns their
disposable-preview removal. For the current GRU cost cutoff and exact workload
teardown procedure, see [Explicit disposable workload teardown](disposable-workload-teardown.md).
