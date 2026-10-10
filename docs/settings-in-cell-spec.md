# Settings in the cell spec

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

Design note for TS-569. Changing a running cell's settings must never need a
re-found, and a controller binary must restart cleanly after a self-update or
a rollback. Today neither holds:

TS-796 supersedes the role-config compatibility policy below: unknown fields
are always rejected, and removed settings must be deleted from signed configs
before rollout. The remaining optional cell-spec settings are follow-up scope
under the zero-configuration rule.

- Every setting lives in the signed controller config (`controller.json`).
  Changing one means signing a new config, which only a re-found installs.
- Restart admission compared the manifest's config digest with a digest of
  the config **re-encoded** by the running binary. A binary that adds a
  member without `omitzero`, defaults one, or renames one no longer matches
  its own signed config and refuses to start.
- Configs and KV and wire records decode strictly. Binary N-1 refuses
  anything binary N wrote with a new member, so a rollback, or a cell in the
  middle of a self-update, stops.

## Target

- The signed controller config holds the controller's identity: cell, slot,
  broker addresses and routes, material paths and sidecars. These change only
  with a re-found.
- Every mutable setting is a section of the [cell spec](cell-spec.md), which
  `ts-orch apply` changes on running controllers. A section that widens
  authority needs a root's signature; the rest need the release leaf's.
- The config digest covers the signed bytes, and role-config readers reject
  fields they do not understand at every version.

## Slice 1: restarts and rollbacks survive new members

**Raw digest.** `app.Config` keeps the exact bytes it was loaded from.
Restart admission (full, local and the admission child, which now receives
those bytes on stdin) and the managed config check digest the bytes, not a
re-encoding. Guest installation and every restart re-check the config with
`ValidateInstalledControllerConfig`: the signed digest, a strict decode
and the role's rules. Only signing (`bootstrap render-controller-config` and
`sign-manifest`) still requires this binary's canonical encoding.

**Version-1 configs.** `app.ConfigVersion` is fixed at 1; the renderers and
`host-setup` stamp it as `version`. Loading requires explicit version 1 and
decodes strictly. A version label cannot allow removed switches or unknown
settings to be silently discarded. Rollback must use a signed config whose
fields the target binary understands.
`TestConfigVersionCoversEveryMember` fails when `app.Config`'s members differ
from `internal/app/testdata/config-members.txt`, which names the version it
records: review the changed contract, then rewrite the file.

**Tolerant records.** `protocol.DecodeTolerant` is `DecodeStrict` without the
unknown-member check: duplicate names, invalid UTF-8, the size limit and the
record's own validation still apply. Rollout records (`TS_ROLLOUTS`: the cell
slot, rollouts, the desired release and its generations) use it, so an older
controller reads a newer one's records in the middle of a self-update. Their
schema version names breaking changes, and readers still refuse an unknown
one. A rollout's policy is bound by its digest, so an older controller still
refuses a rollout whose policy it cannot fully read.

Signed payloads stay strict, delivery intents included: a controller must
not act on a signed request whose members it cannot read. A newer member is
omitted while it is unset, so strict decoding already reads it then; setting
it is a new schema version. Signed envelopes stay strict too: every member is
signed scope.

Rules for every config and record member from now on:

1. Remove obsolete settings from code and signed configs; do not preserve
   compatibility shims for them.
2. A new member is `omitzero` or `omitempty`, with a safe zero value: an
   older writer omits it, an older binary that rewrites a record drops it,
   and a digest of a re-encoding stays the same while it is unset.
3. A member an older reader must not skip (one under a digest or signature,
   or one that narrows authority) is a new schema version. A config has no
   such version: a narrowing setting belongs in the cell spec, whose binary
   level an older binary cannot skip.
4. Config changes retain version 1 and update the reviewed member snapshot.

## Next slices: one cell spec section per setting

Each section is optional. While a spec has no section, the signed config's
value is the setting (generation 0), as for services today. The first spec
with the section replaces it. A section raises `cellspec.BinaryLevel`, so a
controller that cannot read it keeps its current spec, and the leader never
amends over a stored record it cannot read. Each section takes effect on
every controller when it adopts the spec, without a restart.

| Setting | Section | Gate | Takes effect |
| --- | --- | --- | --- |
| `controller.trusted_signers` | `signers` (level 8) | Root for any change. The leader refuses a spec that would stop trusting the key that applies it. | Done in slices 6a and 6b: every check reads one live signer set, which the controller swaps as it adopts the spec; a redelivered release is authorized again. Releasers must be signers of the effective spec. |
| `controller.oci_reconcile.desired` | `oci_desired` (level 7) | Root to add or change an `enforce` entry, to turn on prune or shorten its delay, and to drop an entry while prune is on; leaf otherwise. The signed list is generation 0. | Done in slice 5: the leader publishes the list in force into `TS_OCI_DESIRED` at every reconcile pass. |
| `controller.kv_snapshot` interval and pause | `kv_snapshot` (level 5) | Leaf for the interval (5 to 3600 s); root to pause. | Done in slice 3: the uploader reads the schedule at least every 5 s. The location stays in the signed config: a rebuilt cell restores from it before any KV bucket exists. |
| Managed host image receipt and delegation | `host_images` (done in TS-570, see [image updates](image-updates.md)) | Root to add or change an image: a receipt qualifies an image without choosing it for a cell. Leaf to revoke. | The fleet and placement read the adopted spec at each check. |
| `controller.artifact_store_max_bytes` | `artifact_store` (level 10) | Leaf. Startup reserves 3 GiB beside artifacts for control state and host metric history. Cell-spec validation requires 3.5 GiB headroom, or 4 GiB with `machines_api`. | Done in TS-576: the leader applies it within a minute, raising it only while its disk has room; a restart never shrinks a larger quota in force. |
| TerraBase peers (`TERRABASE_PEERS`) | the existing `terrabase` service entry | Root, as today. | Done in slice 2: static member enrollment and host grant checks read the effective profile, not the signed config's. |

These stay in the signed config, because they are read before KV exists or
bind the running process: identity, broker addresses and routes, material
paths, the sidecars (with placement's member role), `offline_restart_admission`,
`membership`, `lease_seconds` and `renew_seconds`,
the observability listener and the `kv_snapshot` location. Other mutable
settings (`autoscale` intervals and node pools, `oci_reconcile` intervals and
NLB, `global`, `region_planner`) get
sections the same way after this ticket. Storage capacity and placement volume
backups instead use [fixed policy in code](storage.md#fixed-storage-policy).

The last slice renders new controller configs with only these: the
`oci-region attempt` services phase applies TerraBase's profile (root-signed)
and ts-auth as generation 1, so a cell spec `terrabase` entry needs only the
signed member CA. The renderer's `--terrabase-profile` and
`--ts-auth-profile`/`--ts-auth-service` still work but are deprecated.
Existing cells keep their signed settings as generation 0 until a spec
replaces them, so no cell needs a re-found.
