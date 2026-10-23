# Live image-consumer audit — 2026-10-23 01:52 UTC

DECISION: remove the unused automated qualified-QCOW2 producer. No serving infrastructure, image assets, catalog objects, runtime signatures or verification gates are deleted.

## Live scope and evidence

The read-only OCI inventory covered all seven accessible compartments, including tenancy root, in sa-saopaulo-1 (GRU), us-sanjose-1 (SJC), and eu-frankfurt-1 (FRA). Four nonterminated instances were found: the three regional founders and rt1-gru-test. Each source image was resolved with compute image metadata. All four are Oracle platform Canonical Ubuntu 24.04 images, not imported/custom QCOW2 images; the test image is Minimal. Founder image metadata reports null compartment and base-image-id.

| Region | Founder source image | Platform name |
|---|---|---|
| GRU | ocid1.image.oc1.sa-saopaulo-1.aaaaaaaaqqxqqfkhlzjcneto533jgu7ey6nzlzlpt5kuh6cqtbldhy2bu2hq | Canonical-Ubuntu-24.04-aarch64-2026.09.18-0 |
| SJC | ocid1.image.oc1.us-sanjose-1.aaaaaaaawpuh2omgoyqorcgzyrozpjgi55rker4nblvxrtanzwtc6jchgoba | Canonical-Ubuntu-24.04-aarch64-2026.09.18-0 |
| FRA | ocid1.image.oc1.eu-frankfurt-1.aaaaaaaa4yruuzv353vx4cf3tcsimt5xqvls6reilpxccqhxbyfk6rzn57qq | Canonical-Ubuntu-24.04-aarch64-2026.09.18-0 |

Read-only SSH inspection found all three founders serving through ts-orch.service and /usr/local/bin/terrascale-orchestrator single-host. Among matching orchestrator units only ts-orch.service was installed. No legacy image/catalog/activation files were found within depth three of /var/lib/ts-orch. This bounded filesystem observation supports the active process and cloud metadata; absence alone is not the dependency proof.

## Reachable live paths

R1 PR [#109](https://github.com/TerraScale/ts-orchestrator/pull/109) merged at 2026-10-22T20:39:14Z. internal/regionhost/instance.go selects Canonical Ubuntu 24.04 and deploys via internal/regionhost/cloudinit.go using the checksum-verified CI release executable. Region add/node join do not consume qualified QCOW2 releases or their final-byte production proofs.

internal/releasepush/handler.go targets the running executable, verifies new binary bytes, swaps them atomically and retains .prev for rollback. This single-host self-update path does not import or admit custom images. The active internal/ociregion/catalog/catalog.go is region geography, not an image inventory.

The older managed-capacity, image promotion and attempt tooling still references image receipts and final-byte evidence. Those are shared verification consumers, not serving entry points in the inspected single-host estate. Keep verify-image-production and its signed candidate-binding tests. Move the shared evidence-fetch transport out of scripts/ci and update direct offline promotion/attempt callers rather than breaking them.

The conclusion is bounded to the accessible authorized three-region OCI estate and current serving paths, not a claim that custom-image tooling can never be activated. Any future custom-image activation still requires the unchanged signed final-byte admission gate.

No credential values, production data, instance changes, new capacity, permissions or signing material were inspected or modified.
