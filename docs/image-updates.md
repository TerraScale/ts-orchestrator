# Image and OS updates in place

A new image must not cost a re-found or a host relaunch. Servers keep their
instance OCID, VNIC, private IP and data; only what runs on them changes
(TS-570).

## Problem

Every managed host had to run exactly the fleet's pinned image
(`image_id` in the signed OCI region config). The fleet compared each host's
launch image, boot volume and boot descriptor with that pin, and placement
did too. Changing the pin made every host launched from the previous image
foreign: the fleet withheld it, placement held its seat, and its retained
volume could not be attached again. In practice a new image meant
re-founding the cell and relaunching the database hosts.

## Model

1. **Allow-list.** The [cell spec](cell-spec.md) holds `host_images`: the
   images, besides the pinned one, that managed hosts may run. Each entry is
   an image's signed release receipt and the root's delegation that signs it,
   so every entry proves by itself that a root qualified that exact image
   for the cell's region and environment. The list lives in the replicated
   `TS_SERVICE_SET` KV record with the rest of the spec, and is snapshotted
   with it.
2. **Per instance.** Every image check now asks two questions of the host
   itself: does its boot volume, launch intent and boot descriptor name the
   same image, and is that image the pin or on the allow-list. A host
   launched from an allowed earlier image stays a fleet member: it is
   observed, keeps its placement seat, can attach its retained volume and can
   be torn down.
3. **Launch** stays on the pinned image, which still needs a currently valid
   receipt and the OCI image readback.
4. **Routine OS updates** apply signed package sets on the running host and
   reboot it, coordinated with self-healing (TS-568). The boot volume and
   image OCID do not change.
5. **Major image changes** move a running host to a new image with the OCI
   in-place boot volume replacement, which keeps the instance OCID, VNIC and
   IP. A root-signed successor plan names the slots and images; the
   orchestrator replaces one slot at a time and keeps quorum. TerraBase data
   must be on managed volumes first (TS-567), because it is on the boot disk
   today.

## Slices

| Slice | Delivers | Status |
| --- | --- | --- |
| 1 | `host_images` allow-list in the cell spec; fleet, provider, terminal and placement checks per instance; `ts-orch service allow-image` and `revoke-image` | this change |
| 2 | Launch image chosen from the allow-list, so new hosts boot the newer image without a new signed controller config | planned |
| 3 | Signed package sets and reboot for routine OS updates (with TS-568) | planned |
| 4 | Root-signed successor plan and OCI boot volume replacement, one slot at a time with quorum (after TS-567) | planned |

## Trust

- A receipt qualifies an image only under a root's image delegation that
  names the image OCID, for the cell's environment and logical region (`gru`
  boots `GRU` images). That says the pipeline built and qualified the image,
  not that this cell should run it, so a root must sign every amendment that
  adds or changes an image (`root_required` lists it). Revoking one is
  ordinary: the release leaf may sign it.
- The leader admits an added or changed image only while its receipt and
  delegation are currently valid under the current roots. An accepted image
  stays allowed after its receipt expires, so a host is never evicted by a
  clock.
- Controllers re-verify every receipt when they load the spec, with every
  root the [root chain](root-rotation.md) ever named. Rotating away the root
  that qualified an image therefore keeps the image allowed; re-sign the
  spec under the new root as usual.
- Revoking an image makes its hosts foreign again: the fleet withholds them,
  placement holds their seats, enrollment and volume attachment refuse them,
  and the public load balancer drops them as backends. Nothing is relaunched
  or deleted while lost-member replacement stays off, as it is today.
  Teardown still works: it trusts the journaled launch and boot binding, not
  the current allow-list. Revoke an image only after its hosts moved off it.
  Allowing it again needs a root and a currently valid receipt, so after the
  receipt expires a revocation lasts until the image is re-qualified.
- A controller binary below level 4, or a controller that restarts while the
  stored spec does not verify, has no allow-list: hosts of earlier images
  are withheld until it adopts the spec again.

## Limits of slice 1

- New hosts still boot only the pinned image; slice 2 moves the launch pin.
- The allow-list checks the image OCID, environment and region. The shape
  architecture is checked at launch only, which an existing host passed.
- A host on a revoked image is withheld, not reported as drifted.
- If the pin moves while a launch is between `EnsureHost` and placement's
  next stage, the retry conflicts with the journaled launch and holds;
  slice 2 reuses an allowed launch intent's image.
- Boot volume replacement changes the instance's boot image; the per-instance
  checks bind the launch intent's image, so slice 4 adds a durable record of
  the replacement.
