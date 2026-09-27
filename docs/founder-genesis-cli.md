# Initial founder authority

The reviewed GRU seed slot is `controller-a`, the only externally launched
controller. After its admission, `ts-orchestrator` uses the selected founder
plan to launch `controller-b` and `controller-c`. Do not create either peer
manually.

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
ts-bootstrap sign-peer-receipt-delegation \
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
ts-bootstrap sign-founder-plan \
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
ts-bootstrap sign-initial-founder-selection \
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
ts-bootstrap publish-initial-founder-selection \
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
remain the separate schema-two continuity path after all three installs.

## First external seed transaction

Use the protected `ts-infra` seed resource only for `controller-a`. Before
signing its reservation, review the exact OpenTofu plan, save the SHA-256 of
the reviewed plan file, and fix one `create_identity` value. That value must be
the `BootstrapCreateKey` freeform tag read back from the resulting OCI instance.
Keep the signed reservation and completion bundles: they contain the exact
immutable bytes needed to reconcile an uncertain Object Storage response.

1. Sign the reservation offline, using the owner-only raw
   `<material-directory>/founder-ledger.key` produced by
   `generate-controller-material`. The public `.ledger.pem` file is used only
   when signing the anchor's ledger delegation.

   ```text
   ts-bootstrap sign-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reviewed-plan-sha256 REVIEWED_OPENTOFU_PLAN_SHA256 \
     --create-identity EXACT_BOOTSTRAP_CREATE_KEY \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-reservation.json
   ```

2. Publish that exact reservation before any Terraform seed creation. Repeat
   the same command and bundle after an uncertain response; a different intent
   or occupied slot is a conflict.

   ```text
   ts-bootstrap publish-external-seed-reservation \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json \
     --oci-config oci-config --oci-profile DEFAULT
   ```

3. Apply only the reviewed protected plan for `controller-a`. Check that its
   `create_identity` and plan digest still equal the signed reservation. Record
   the exact instance OCID returned by Terraform. Do not create `controller-b`
   or `controller-c`; the admitted orchestrator provisions those peers.

4. Read the exact instance and primary VNIC from OCI, then sign the root seed
   receipt and delegated result offline. The observation checks the create
   key, image, compartment, shape, availability and fault domains, subnet,
   network security groups, planned private IP, running state, and ETag. The
   signed observation must still be within its 15-minute first-write window.

   ```text
   ts-bootstrap observe-external-seed \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json --instance-ocid EXACT_TERRAFORM_INSTANCE_OCID \
     --oci-config oci-config --oci-profile DEFAULT --out seed-observation.json

   ts-bootstrap sign-external-seed-completion \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json --observation seed-observation.json \
     --signing-key root.key \
     --ledger-signing-key MATERIAL_DIRECTORY/founder-ledger.key \
     --out seed-completion.json
   ```

5. Publish the completion while the founder plan and signed proofs are current.
   The publisher reads the exact instance and VNIC again before the first
   write. It stores the manifest, root receipt, delegated result, and completed
   HEAD in that order. Retrying exact committed bytes succeeds; changed proof
   bytes, OCI identity, ETag, or private IP fail closed.

   ```text
   ts-bootstrap publish-external-seed-completion \
     --identity identity.json --anchor anchor.json \
     --founder-plan founder-plan.signed.json --root-key root.pub \
     --manifest controller-a.manifest.json --manifest controller-b.manifest.json \
     --manifest controller-c.manifest.json \
     --reservation seed-reservation.json --completion seed-completion.json \
     --oci-config oci-config --oci-profile DEFAULT
   ```

The founder plan's launch deadline is a hard admission boundary. If it passes
before the completed HEAD is durably stored, stop and prepare a newly reviewed
bootstrap transaction; an expired plan cannot authorize a new seed write.
If the exact completed HEAD was stored before the deadline but its response was
uncertain, retry the same bundle while the signed anchor, plan, and manifests
remain current. The post-deadline path reads and verifies the stored proofs and
their timestamps; it does not observe OCI or write another object.
If a completion write has an uncertain outcome, retry the exact completion
bundle first. The publisher checks the immutable proof keys and may reconcile
an already stored result after its observation is older than 15 minutes. If
only the root receipt was stored and the result was not, take a fresh
`observe-external-seed` readback, then run `sign-external-seed-completion` with
`--reuse-receipt-from seed-completion.json` and a new output path. This keeps
the exact root receipt while signing a fresh result. The result and completed
HEAD cannot outlive that receipt; complete initial seed admission before its
original expiry. A conflicting stored result requires the original bundle;
never create another seed instance to resolve a publication failure.
