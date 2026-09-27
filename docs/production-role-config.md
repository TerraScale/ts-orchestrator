# Production role configuration

The reviewed controller material input is a public description of one deployment, not a source of instance IDs, Vault OCIDs, or private keys. `generate-controller-material` creates a private local source and a public `Record`. The first controller is the only operator-started instance; after its identity and authority are handed off, `ts-orchestrator` launches the signed peers in that same cell. For the full regional setup and seed sequence, use the [manual regional bootstrap runbook](region-bootstrap.md).

`ts-infra` currently manages shared Email Delivery only: four email resource
identities. Its `main` revision `e347f13a313ebb2b9d0a0b631ba0aed56af65126`
removed the former regional Terraform definitions and workflow. The preceding
state-only handoff removed 24 OCI resource addresses and one local propagation
marker from Terraform state without creating, changing, or destroying OCI
resources. That records ownership bookkeeping, not regional health or a live
controller. The operator prepares regional networking, IAM, and bootstrap
inputs and starts controller A; `ts-orchestrator` forms B/C and manages ARM
workload hosts after the explicit handoff. See the
[regional bootstrap runbook](region-bootstrap.md) for the current boundary.

## Controller inputs

The material generator maps canonical lower-case `gru`, `sfo`, and `fra` cells
to `sa-saopaulo-1`, `us-sanjose-1`, and `eu-frankfurt-1`, respectively. The
checked-in regional plan is the GRU example and needs a separately reviewed,
fully populated copy for either other mapped cell.

For each slot, prepare a reviewed unsigned manifest candidate with the exact image, launch profiles, storage domain, and Vault secret references. The candidate's secret references must match the `Record` file names, purposes, slots, byte lengths, and SHA-256 digests. Prepare three reviewed public JSON files: `oci-region-intent.json`, `oci-region.json`, and `placement.json`. Keep the operator command signer grant in a separate canonical JSON file containing one `TrustedSignerConfig`; its `public_key` is the Ed25519 operator command key, not the NATS operator issuer key.

Run `ts-bootstrap render-controller-config` with `--candidate` and `--candidate-sha256`, `--material-record` and `--material-record-sha256`, `--operator-grant` and `--operator-grant-sha256`, each of the three sidecar paths and SHA-256 pins, and a new `--out` path. The renderer checks the reviewed deployment/slot addresses and material references, then writes canonical `app.Config` JSON. Its output digest is printed for review.

Run `ts-bootstrap sign-manifest` with the same candidate, the rendered `--controller-config` and `--controller-config-sha256`, the three sidecar paths and hashes, the current anchor and release proofs, and the offline root signing key. Signing verifies the config and sidecars again and rejects an envelope larger than the OCI metadata transport bound of 30 KiB.

The offline image contains the baked public anchor, identity, roots, the controller config installer unit, and the orchestrator binary. It contains no controller credentials or per-slot config. For the manually bootstrapped first slot only, place its exact signed manifest envelope at `/etc/terrascale-orchestrator/controller-seed-manifest.json` as a root-owned `0644` regular file before starting the controller installer. Peers receive that envelope in `terrascale-controller-manifest-v1` OCI instance metadata from the managed founder launch. The descriptor supplies a slot hint only.

The installer verifies the current root, release image, signed slot, IMDS instance ID, and OCI instance/VNIC readback. It installs `controller-manifest.json` and the three sidecars before `controller.json`, checking exact bytes and ownership on retries. The bootstrap Gate independently binds the loaded canonical config to the signed ledger manifest before material or authority effects. Restarts use the accepted historical manifest; managed sidecar parsing checks the same file bytes it consumes against that manifest.

## Operator inputs

`operator.creds`, `operator-tls-cert.pem`, and `operator-tls-key.pem` are owner-only offline material. They must not be placed in controller Vault secrets or controller images. `ca.pem` and `ticket.pub` are public source files copied alongside them. A separate reviewed Ed25519 command signing key must match the operator grant. Generate the material source as root under a root-owned private path outside the checkout when it will be installed for the operator. The source loader checks that every private file and the directory belong to the current UID; rendering and installation must therefore run as the same root user.

Run `ts-bootstrap render-operator-config` with the reviewed public Record and SHA-256, the complete owner-only material directory, the canonical operator grant and SHA-256, the separate signing key and SHA-256, and a new owner-only `--out` path. Then run `ts-bootstrap install-operator-material` with the same Record/material source, the rendered operator config and its SHA-256, and the signing key and its SHA-256. Installation reconciles exact bytes into root-owned `0600` files under `/var/lib/terrascale-operator` (`0700`), publishing `operator.json` last. The CLI uses `operator ... --config /var/lib/terrascale-operator/operator.json`.

When the operator reaches a controller through an OCI Bastion local port forward, add `--nats-forward CONTROLLER_PRIVATE_IP:4222=127.0.0.1:LOCAL_PORT` to the `operator` command. Repeat the flag only for other explicitly forwarded controllers. Keep the installed operator config's original controller URLs: the client verifies the controller certificate against each private IP while its TCP connection uses the selected loopback port. In forwarding mode it connects and reconnects only through listed forwards and ignores advertised NATS servers. The loopback forward is transient and is not written to `operator.json`.

No production operator config can be rendered or installed until the reviewed
Record, Vault references, sidecars, operator grant, signing key, and release
proofs exist. Do not substitute example OCIDs or keys.

## Managed host image

Generate a public enrollment bundle from the reviewed material record and the
matching owner-only material directory created from that cell's reviewed
`generate-controller-material` configuration. For example, with SFO-specific
material:

```sh
material_record=/ABSOLUTE/PATH/sfo/controller-material-record.json
material_record_sha256=REVIEWED_RECORD_SHA256
sudo /ABSOLUTE/PATH/ts-bootstrap render-host-enrollment-public \
  --material-record "$material_record" \
  --material-record-sha256 "$material_record_sha256" \
  --material-directory /ABSOLUTE/PATH/sfo/controller-material \
  --out /ABSOLUTE/PATH/sfo/host-enrollment-public.json
```

Set the record digest to the separately reviewed SHA-256 of that record. Run the
renderer as root, use an absolute output path outside the owner-only material
directory, ensure its parent exists, and choose a new output path. The command
creates a new public JSON file and will not overwrite an existing path. The
record and live material directory must match; the renderer checks the live
files and verifies that `ca.pem` matches its recorded digest. It requires at
least 24 hours of material validity. The record supplies the cell, environment,
and ordered controller A/B/C endpoints. The matching owner-only source supplies
`ca.pem`; use this same record and source for the bundle's image.

Pass the generated file through `--host-enrollment-public` and its exact
SHA-256 through `--host-enrollment-public-sha256` to
`deploy/image/build-offline.sh`. The build must use the matching `--environment`
and `--bootstrap-identity`: its validator checks the bundle digest, mapped
cell/region against the bootstrap identity, and environment against the release
environment before installing it at
`/etc/terrascale-orchestrator/host-enrollment-public.json`. The bundle is public
JSON pinned by digest, not an independently signed envelope. The host signs its
enrollment requests, and verifies controller responses with the response
public key in the bundle.

The host setup service creates `/etc/terrascale-orchestrator/host.json` after
live enrollment. The setup service and renewal timer are enabled only when the
bundle is present; the renderer and image validation do not demonstrate a live
OCI enrollment.

The image and bundle use workload UID/GID `2000:2000` (`terrascale-workload`), install root `/var/lib/terrascale-orchestrator-host/install`, state root `/var/lib/terrascale-orchestrator-host/state`, and managed runtime root `/srv/ts-managed`. The builder rejects conflicting base-image UID/GID assignments and creates `/srv/ts-managed` as root:2000 `0750`. The host runtime verifies each member's separate persistent volume mount before launching TerraBase.

An authorized operator can run `terrascale-orchestrator operator host-enrollment-revoke --config /var/lib/terrascale-operator/operator.json --instance-id INSTANCE_OCID` to disable a managed host's durable enrollment grant. This prevents future credential issuance and renewal. TLS and NATS credentials already issued to that host remain valid until their own expiry, up to 48 hours after issuance. Immediate retirement of an active D11 member session remains open; revoking enrollment alone does not close that session.
