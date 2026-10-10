# Initial founder authority

For the complete one-region operator procedure, including manual OCI
foundation creation and the controller-A launch, see the
[manual regional bootstrap runbook](region-bootstrap.md). This page records
the signed founder objects and seed transaction used by that runbook.

The seed slot is `controller-a`, the only operator-started controller. The
material and first-seed commands accept GRU / `sa-saopaulo-1`, SFO /
`us-sanjose-1`, and FRA / `eu-frankfurt-1`; each cell needs its own reviewed
plan and signed genesis. After A's signed admission and identity/authority
handoff, `ts-orchestrator` uses the selected founder plan to launch
`controller-b` and `controller-c` in the same cell. Do not create either peer
manually. The host-enrollment public bundle renderer accepts matching reviewed
material for all three mapped cells. See the [regional bootstrap
runbook](region-bootstrap.md) and [managed host image instructions](production-role-config.md#managed-host-image)
for the per-cell material inputs; rendering alone does not prove live
enrollment or regional deployment.

Prepare the signed genesis anchor and one current root-signed manifest for each
of its three sorted controller slots. The manifest for the seed must contain its
exact founder and ledger signer secret references. The peer manifests must pin
their image, launch profiles, route and client addresses, and controller TLS
secret references. The plan's two peer rows must match those manifests and the
anchor. Each secret reference names an exact Vault OCID, version, digest, size
limit, and output file. Controller Vault read policy and secret readback require
separate review; a TerraBase member's secret grant does not grant controller
access.

`generate-controller-material` writes a public inventory plus `<out>.peer.pem`
and `<out>.ledger.pem`. Use those PEM files as the peer receipt and ledger
delegation public-key inputs before signing the anchor and manifests. Its
private material remains in the owner-only directory named by `--directory`;
the public inventory and PEM paths never contain private key bytes.

After signing the anchor with the ledger delegation, sign the distinct peer
receipt delegation for exactly `controller-b` and `controller-c`:

```text
ts-orch bootstrap sign-peer-receipt-delegation \
  --identity identity.json --anchor anchor.json --root-key root.pub \
  --signing-key root.key --peer-public-key controller-material.json.peer.pem \
  --out peer-receipt-delegation.signed.json --valid-for 24h
```

Include that exact signed delegation in all three manifest candidates before
signing the manifests.

Write a canonical `bootstrap.FounderPlan` JSON candidate from the reviewed
three-slot inventory. Its `anchorSha256`, `seedManifestSha256`, and peer
`manifestSha256` fields hash the complete signed envelope bytes. Set a UTC
`launchDeadline` inside the signed plan and anchor validity. Then sign it with
the offline root key:

```text
ts-orch bootstrap sign-founder-plan \
  --candidate founder-plan.candidate.json --identity identity.json \
  --anchor anchor.json --manifest controller-a.manifest.json \
  --manifest controller-b.manifest.json --manifest controller-c.manifest.json \
  --root-key root.pub --signing-key root.key \
  --out founder-plan.signed.json --valid-for 24h
```

Write a canonical `bootstrapstart.FounderSelection` JSON candidate with
`schemaVersion: 1`, `generation: 1`, the baked deployment identity, the complete
signed plan and anchor envelope digests, and three sorted slot and manifest
envelope digest pins. Sign that exact candidate:

```text
ts-orch bootstrap sign-initial-founder-selection \
  --candidate founder-selection.candidate.json --identity identity.json \
  --anchor anchor.json --plan founder-plan.signed.json \
  --manifest controller-a.manifest.json \
  --manifest controller-b.manifest.json --manifest controller-c.manifest.json \
  --root-key root.pub --signing-key root.key \
  --out founder-selection.signed.json --valid-for 24h
```

The CLI checks the complete signed plan, anchor, and manifests before writing
either signed output. It never prints the private key or secret contents. Keep
the root key and OCI API credentials in their existing owner-controlled stores.

Once the reviewed foundation and storage buckets exist, publish the five
immutable signed objects and the generation-one selector:

```text
ts-orch bootstrap publish-initial-founder-selection \
  --selection founder-selection.signed.json --identity identity.json \
  --anchor anchor.json --plan founder-plan.signed.json \
  --manifest controller-a.manifest.json \
  --manifest controller-b.manifest.json --manifest controller-c.manifest.json \
  --root-key root.pub --oci-config oci-config --oci-profile DEFAULT
```

The publisher derives its namespace, buckets, keys, and KMS keys only from the
verified anchor. It creates every object with `If-None-Match: *` and reads its
exact bytes back. Retrying the same signed bytes is safe after an uncertain
response; a conflicting existing object or selector fails without replacement.
The later `sign-founder-selection` and `publish-founder-selection` commands
publish subsequent explicit-v1 founder selections during initial formation.
Accepted controllers restart from their root-owned accepted identity; these
commands do not authorize restart or in-place identity re-key.

## First external seed transaction

This is the current manual controller-A seed flow. It supersedes the earlier
proposal to use a `ts-infra` OpenTofu seed apply; current `ts-infra` main has no
regional seed apply. Follow the [regional bootstrap runbook](region-bootstrap.md)
for the operator-owned foundation, live inventory, cost admission, readback,
material provisioning, and launch order. Do not use the historical OpenTofu
plan hash or Terraform `create_identity` input.

The reviewed seed preflight is a schema-two record bound to the signed anchor,
controller-A manifest and image receipt, launch profile, current inventory and
cost admission, and one `BootstrapCreateKey` value. It fixes a private launch
with 1 OCPU, 6 GiB memory, a 50 GB boot volume, and 10 VPUs/GB. Keep the exact
preflight JSON and its SHA-256 with the reservation and completion bundles.
Use the `seed-preflight` command and exact artifact inputs shown in the
[regional bootstrap runbook](region-bootstrap.md). It verifies the current
seed manifest and image receipt, plan, live inventory, budget admission, and
controller-A profile, then writes a hash-bound reviewed plan. It is read-only
and does not create an OCI instance. Keep that output and its SHA-256 with the
reservation and completion bundles.

1. Sign a reservation offline with the owner-only raw
   `<material-directory>/founder-ledger.key` produced by
   `generate-controller-material`. The public `.ledger.pem` is only for the
   anchor's ledger delegation. Use the exact `create_identity` value emitted
   by `seed-preflight` as `--create-identity` and as the controller-A
   `BootstrapCreateKey` freeform tag. The helper uses the value set in the
   reviewed plan or derives one from the plan and signed inputs; do not choose a
   different value after preflight.

   ```text
   ts-orch bootstrap sign-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reviewed-plan reviewed-seed-plan.json \
     --reviewed-plan-sha256 REVIEWED_SEED_PLAN_SHA256 \
     --create-identity EXACT_BOOTSTRAP_CREATE_KEY \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-reservation.json
   ```

2. Publish the exact signed reservation before creating controller A. Use the
   same bytes if the response is uncertain; a different intent or occupied
   slot is a conflict.

   ```text
   ts-orch bootstrap publish-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json \
     --oci-config oci-config --oci-profile DEFAULT
   ```

3. Generate user-data from the exact signed controller-A manifest with the
   `seed-user-data` helper command documented in the [regional bootstrap
   runbook](region-bootstrap.md), then manually create only controller A using
   the reviewed seed preflight. Record the exact OCI instance OCID. Do not
   launch B or C manually; after explicit identity and authority handoff, the
   admitted founder launches the two same-cell peers.

4. Read the exact instance and primary VNIC from OCI, including the seed
   profile and boot-volume size/performance, then sign the root receipt and
   delegated result offline. The OCI observation must be no more than 15
   minutes old for a new first write.

   ```text
   ts-orch bootstrap observe-external-seed \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json \
     --reviewed-plan reviewed-seed-plan.json \
     --reviewed-plan-sha256 REVIEWED_SEED_PLAN_SHA256 \
     --instance-ocid EXACT_MANUAL_INSTANCE_OCID \
     --oci-config oci-config --oci-profile DEFAULT --out seed-observation.json

   ts-orch bootstrap sign-external-seed-completion \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json --observation seed-observation.json \
     --signing-key root.key \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-completion.json
   ```

5. Publish completion for the exact controller A created under the original
   reviewed admission while the signed founder plan's `launchDeadline` remains
   in the future. The 15-minute admission proves A was created during its
   approved window; the current founder plan authorizes observation and a new
   completion for that exact instance until the deadline. Before a new
   completion write, the publisher reads the exact instance and VNIC again and
   checks the reviewed sizing. Replacing controller A requires fresh inventory
   and a newly reviewed admission. The publisher stores the manifest, root
   receipt, delegated result, and completed HEAD in order. Preserve exact bytes
   for an uncertain response.

   ```text
   ts-orch bootstrap publish-external-seed-completion \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json --completion seed-completion.json \
     --reviewed-plan reviewed-seed-plan.json \
     --reviewed-plan-sha256 REVIEWED_SEED_PLAN_SHA256 \
     --oci-config oci-config --oci-profile DEFAULT
   ```

The founder plan's launch deadline is a hard first-admission boundary. If it
passes before the completed HEAD is stored, stop and prepare a newly reviewed
transaction; an expired plan cannot authorize a new seed write. If the exact
completed HEAD was stored before the deadline but its response was uncertain,
retry the same bundle. The reconciliation path verifies the stored proofs and
timestamps without observing OCI or writing another object.

If completion publication has an uncertain outcome, retry the exact completion
bundle first. When only the receipt was stored and the result was not, obtain a
fresh OCI observation and sign a new completion with
`--reuse-receipt-from seed-completion.json` and a new output path. This reuses
the exact root receipt while signing a fresh result. Never create a second seed
instance to resolve a publication failure.
