# Cell spec

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

A cell spec is a running cell's signed desired state. Operators change it on
running controllers with `ts-orch get`, `diff` and `apply`; nothing is
rebuilt and no controller config is edited. Package
[`internal/cellspec`](../internal/cellspec) holds the model and its
signatures. The controller side is
[`internal/app/cell_spec_registry.go`](../internal/app/cell_spec_registry.go).

## Model

A **cell spec** is the complete desired state of one cell at one generation.
It is bound to the cell's deployment ID, cell and environment. Generation 0
is the signed controller config. Every later generation is a signed spec that
replaces the previous one as a whole.

| Field | Meaning |
| --- | --- |
| `generation` | Exactly one more than the generation it amends. |
| `requires_binary` | The lowest spec level a controller binary must understand to adopt this amendment (see [binary levels](#binary-levels)). |
| `services` | The cell's generic services, sorted by role. |
| `host_grants` | Static hosts that may enroll, such as controller VMs, sorted by node (see [host grants](#host-grants)). |
| `host_images` | Qualified images managed hosts may run besides the fleet's pinned image, sorted by image ID (see [host images](#host-images)). |
| `oci_desired` | Optional desired OCI resources with the shape of `controller.oci_reconcile.desired` (see [OCI reconcile](oci-reconcile.md)). It replaces the signed list from the leader's next reconcile pass, and must pass the signed region config (NSGs it admits). The signed list is generation 0: `diff` and the root rule compare against it. A root signs a new or changed `enforce` entry, turning on `prune`, a shorter prune delay, and an entry dropped while `prune` is on; `report` entries and other changes are ordinary. It needs `controller.oci_reconcile` and binary level 7. |
| `signers` | Optional trusted signers, sorted by actor, with the shape of `controller.trusted_signers`. They replace the signed config's on every controller as it adopts the spec: every operator request, release and capability check reads them, and a redelivered release is authorized again. Any change needs a root, and the signed list is generation 0. The leader refuses a spec that would stop trusting the key that applies it: add the new signer first, then remove the old one with the new key. Needs binary level 8. |
| `launch_image` | Optional: the host image new managed hosts boot instead of the pinned image (see [host images](#host-images)). |
| `artifact_store` | Optional `{max_bytes}` quota of the delivery artifact store (`TS_ARTIFACTS`), replacing the signed `controller.artifact_store_max_bytes`. Every controller refuses a quota above its embedded NATS `store_max_bytes` less 3.5 GiB for the other streams and the host metric archive that reserve their size (less 4 GiB with `machines_api`, whose two buckets reserve 512 MiB): once reservations pass `store_max_bytes`, embedded NATS refuses every stream update, even a shrink (TS-662); the leader applies it within a minute, and raises it only while its NATS store disk has room for the store to fill. A restart never shrinks a larger quota in force. The signed quota, or the 2 GiB default, is generation 0. Ordinary: the leaf may sign it. Needs binary level 10. See [artifact store collection](storage.md#artifact-store-collection). |
| `release_fence` | Optional `{load_balancer_id, backend_sets: [{name, port, min_serving, role}], drain_grace_seconds, settle_seconds, canary}`: the leader's [automatic service releases](continuous-delivery.md#automatic-service-releases-ts-610) restart one node at a time, each node's in-rotation backends taken out of the named sets first (drain, then offline after the grace, 15 s by default) and returned once it serves, then a settle (10 s by default) before the next node. The same sets fence orchestrator rollouts and [node operations](node-operations.md). A backend is taken out only while at least `min_serving` backends of other nodes serve healthy in its set (0 means 2; setting it needs binary level 13). A set with a `role` belongs to the [edge reconciler](node-operations.md#the-edge-reconciler), which keeps it equal to the role's replicas, in rotation only while they serve (level 14). A node's backend is its host grant's `private_ip` at the set's port. Sets sorted by name, at most 8. Without it a service release restarts every replica at once. It may not name the backend set `oci_reconcile.public_lb` owns. `canary` `{credentials: {vault, name}, project, database, auth_url, api_url, dashboard_login_url}` gates each release on its first node (level 15, see [the canary](continuous-delivery.md#canary-before-every-node-ts-623)); `credentials` is the Vault secret `<cell>-<n>-canary-credentials`. Adding or changing it needs a root; removing it does not. Needs binary level 12, and the controllers need `use load-balancers` in the network compartment. |
| `atlas` | Optional [Atlas publisher](atlas.md): the authority leader publishes this topology to ts-atlas every 10 s, signed with the Vault key `publish_key`. Adding or changing it needs a root; removing it stops publishing. Needs binary level 11. |
| `dashboard` | Optional `{token: {vault, name}}`: every controller serves the operator dashboard on its NetBird address at port 9463 behind the bearer token in that Vault secret (`<cell>-<n>-orch-dashboard-token`, the cell's own region). See [observability](observability.md#on-the-netbird-address-cell-spec). Adding or changing it needs a root. Needs binary level 18. |
| `netbird` | Optional `{pin, enrollment}`: pinned `0.80.x` client archive and ELF hashes plus public, same-cell OCI Vault enrollment references. The leader installs missing agents and rolls version changes one node at a time through the TS-632 fence, with mesh health checks and local rollback. Adding the section or changing enrollment needs a root; a pin-only bump is ordinary. Needs binary level 20. See [managed NetBird](netbird-managed.md). |

A **service** is one role:

- `profile` is the role's delivery profile: `resources`, `args`, `env` and
  `secrets` ([Vault secrets](#vault-secrets)).
  It has the same shape as `controller.workloads.<role>` and the `--profile`
  of a release, for example
  [`deploy/oci-region/ts-auth-gru-1-profile.json`](../deploy/oci-region/ts-auth-gru-1-profile.json).
- `spec` is optional. It holds the role's reconciled stateless `ServiceSpec`,
  for example
  [`deploy/oci-region/ts-auth-gru-1-service.json`](../deploy/oci-region/ts-auth-gru-1-service.json).
  With a spec, the workload reconciler owns the role. Without one, releases
  place the role. A signed spec is the decision to reconcile the role, so it
  applies even when the signed controller config does not enable autoscaling
  (gru-1 has none). The reconcile interval, host telemetry and node pools
  still come from the signed config, and a spec with a scaling policy needs
  host telemetry there.
- `releasers` are actors that may release the role and register its hosts in
  the spec's environment, in addition to the signed grants. Each must already
  be one of the cell's trusted signers (the spec's `signers`, else the signed
  config's): a releaser names who releases a role, never adds a key. The
  actor's repository grant and `can_register_hosts` still apply.

Generation 0 holds the signed config's `controller.workloads`, plus
`controller.autoscale.services` when autoscaling is enabled. The spec may not
hold the managed placement member role: it belongs to placement and keeps its
signed controller config profile. A `terrabase` entry replaces TerraBase's
signed profile. It needs the signed TerraBase member CA (a signed TerraBase
profile implies it), so an identity-only controller config gets TerraBase's
profile as its first cell spec. It is never reconciled, and passes the same rules (`TERRABASE_PEERS`, ports,
host-owned settings) as the signed one. Only a root may write it (see
[Trust](#trust)), and while it exists it, not the signed config, is
TerraBase's profile: change or revoke a peer with a root-signed amendment.
Static member enrollment and host grant checks use its `TERRABASE_PEERS` as
soon as a controller adopts the spec: an added member enrolls, and a dropped
one can no longer enroll or renew. Members run the new profile with the next
`operator terrabase-release --profile` of that profile.

Changes take effect as follows:

- A service spec change takes effect at once: the reconciler converges the
  role.
- A profile change takes effect with the role's next release. A release binds
  its profile's config digest, so pass the new profile to the release.
- Removing a role needs the role to have no replicas. Drain it first: update
  its spec to `"replicas": {"min": 0, "max": 0}` (ts-auth allows exactly that),
  or release it with zero replicas. The controller refuses to remove a role
  while any host still runs it.

### Host grants

A spec's `host_grants` let static hosts enroll, such as controller VMs.
Each grant is `{node, private_ip, roles, environment, controller}`. The host agent on such
a host enrolls through the regular enrollment endpoint with a static
descriptor naming `node`. The controller accepts it only from `private_ip`,
and only when OCI shows the running instance named `node` holding that
address. The registration has the grant's roles and environment, and one
replica's `resources` per role as capacity. The signed enrollment response
lists the roles, and `host-setup` writes them to `host.json`.

A grant may name only roles the cell delivers (a signed or spec profile),
never placement's member role. It lists `terrabase` exactly when the
effective `TERRABASE_PEERS` lists a member named after its node, or else one
at the grant's `private_ip`, at that address: the host then runs that
TerraBase member, under the member's name, beside its other roles, with both
roles' capacity, and `host-setup` gives it the TerraBase root (TS-578). This
is how a controller VM colocates a member. Such a host enrolls through the
grant's checks (granted address, running instance of that name), not a
database host's descriptor checks, since a controller VM has no descriptor.
A member without a grant still enrolls through the TerraBase profile.
`controller` (optional, binary level 17) names the controller slot, such as
`controller-a`, whose VM the host is, once the node no longer carries the
slot's NATS server name. Without it the slot's VM is the node of that name
(`gru-1-ctl-1` for controller-a in GRU, `ts-sjc-1` in SJC). Rollouts, their
drain and node operations find a controller's node this way. TS-609 renames
gru-1's nodes to `ts-gru-N`: their NATS server names, certificate CNs and
TerraBase member names stay `gru-1-ctl-N`, internal peer IDs that are not
node names.
Changing a granted member's roles registers the host's next generation: its
host agent's session ends and its workloads restart once the old session
expires, so drain its load balancer backends first. A role that a grant
names cannot be removed until that grant is revoked. A new or changed grant
gives a host credentials, so a root must sign it; revoking one is ordinary.

Controllers run ts-auth this way. A controller VM carries no host
descriptor, so its `host-setup` names itself after its launch slot
(`controller-b` is `gru-1-ctl-2`, or `ts-sjc-2` in sjc-1). Grant each
controller its own address:

```sh
ts-orch service grant-host --config "$OPERATOR" --node gru-1-ctl-1 \
  --private-ip 10.251.0.11 --roles ts-auth --environment canary --out "$WORK/grant-ctl-1.json"
```

### Host images

A spec's `host_images` is the managed fleet's image allow-list. Each entry
is `{image_id, receipt, delegation}`: the image's signed release image
receipt and the root's image delegation that signs it, as exact canonical
envelopes. At most four. A host launched from an allowed image stays a
fleet member after the fleet's pinned image changes: the fleet observes it,
placement keeps its seat and it can attach its retained volume. See
[image updates](image-updates.md).

`launch_image` names one of the host images; new managed TerraBase hosts
boot it instead of the pinned image (node pool hosts keep their template
image). A root must choose it, and only while its receipt is current. The
fleet verifies the receipt under the current roots and reads the image back
from OCI before every provider launch from it, as it does for the pin, and a launch already
journaled keeps its own image on retry. Clearing it (new hosts boot the pin
again, `revoke-image --launch`) is ordinary, and revoking the launch image
clears it. A spec with a launch image requires binary level 9.

- A receipt qualifies only the image it names, for the cell's environment
  and logical region (`gru` boots `GRU` images), under a root delegation.
- A root must sign an amendment that adds or changes an image or sets the
  launch image (see [Trust](#trust)); revoking one is ordinary.
- The leader admits an added or changed image only while its receipt and
  delegation are currently valid. An accepted image stays allowed after they
  expire, and through a rotation of the root that delegated it.
- Revoking an image makes its hosts foreign again: they are withheld and
  their seats hold, but their teardown still works. Revoke it only after its
  hosts moved off it.
- A spec with host images requires binary level 4.

```sh
ts-orch service allow-image --config "$OPERATOR" --image-id ocid1.image.oc1.sa-saopaulo-1.... \
  --receipt image-receipt.json --delegation image-delegation.json --launch --out "$WORK/allow-image.json"
ts-orch release sign-spec --candidate "$WORK/allow-image.json" --root \
  --root-key root.pub.pem --signing-key root.key.pem --out "$WORK/allow-image.signed.json"
```

## Vault secrets

A profile's `secrets` maps environment keys to OCI Vault secrets:

```json
"secrets": {
  "TS_AUTH_MASTER_KEY": {"vault": "ocid1.vault.oc1.sa-saopaulo-1....", "name": "gru-1-ts-auth-master-key"}
}
```

- The host agent reads the current version of each secret with its instance
  principal every time it starts a replica, and adds it to the replica's
  environment. The value goes only to the process: never to KV, desired
  state, reports, logs or disk. A Vault read that fails fails the launch,
  which the host retries on its next poll.
- The release's config digest covers the names, not the values. Rotating a
  secret is a restart (for example the next release), not a new signature;
  changing a name or Vault is a profile change.
- Only a root may add or change a ref: it [widens authority](#trust), so the
  root picks every secret and Vault a role reads. Dropping refs is ordinary.
- The Vault must be in the cell's own OCI region (`sa-saopaulo-1` for `gru`).
- A secret must be named `<cell>-<n>-<role>-<key>` (`gru-1-ts-auth-master-key`
  for role `ts-auth`), so a profile reaches only its own role's secrets even
  where the host may read more. While a role names secrets, no other role may
  extend its name (`foo` and `foo-bar`), since their secret names would
  overlap. A role named like the cell's own secret families (`api`,
  `cloudflare`, `netbird`, `trust`, `ts-dashboard`, or one that extends or
  prefixes them, such as `ts`) takes none, and neither does `terrabase`. A key
  may not also be set in `env`. At most 64 secrets, 96 KiB together.
- A key ending in `_FILE` names a secret file instead (TS-651): the host
  writes the secret to a 0600 file of the workload user in
  `<managed runtime root>/roles/<role>/<key in lower case>` and sets the
  key to that path, so the value never enters an environment. It reads
  the secret again at each start and hourly while the replica runs. A
  `terrabase` profile takes only secret files, and needs every host and
  controller on a binary from TS-651 first: an older one refuses it.
- A spec whose profiles name secrets requires binary level 2
  ([binary levels](#binary-levels)); `service add|update` sets it.
- Every native workload on a host runs as the one workload user, so a replica
  can read the environment of another role's replica on the same host. Give a
  role with secrets hosts of its own, or co-locate only roles trusted alike.
- The host's instance principal needs `read secret-bundles` on each secret
  ([host access](secrets.md#host-access)). The controllers have it for their
  compartment.

## Trust

Cell specs use the release trust chain: the offline root key and the
release leaf, kept in OCI Vault (`gru-1-trust-*`, see [secrets](secrets.md)).

1. The root signs a **cell spec delegation** for the leaf. It names exactly
   one deployment ID, cell and environment and lasts at most 31 days.
2. The leaf signs **ordinary amendments**. The signature lasts at most 24
   hours: an unapplied spec expires.
3. The root signs an amendment that **widens authority** itself, without a
   delegation (`release sign-spec --root`), also for at most 24 hours.
4. Production controllers verify specs with the cell's current roots (the
   image's baked roots until a [root rotation](root-rotation.md)) and
   deployment identity. A lab controller (`nats.lab: true`) uses
   `controller.spec_trust` instead. Signed production configs refuse that
   setting.

An amendment widens authority when, relative to the spec it amends, it:

- adds a releaser to a service, since releasers may release the role and
  register its hosts;
- adds or changes a [Vault secret ref](#vault-secrets) of a service, since
  the host reads that secret for the role with an identity that may read
  more;
- adds or changes a host grant, since the host receives credentials;
- adds or changes a [host image](#host-images), since an image receipt says
  the image was qualified, not that this cell should run it, or sets a new
  launch image, which every new host boots;
- changes TerraBase's effective profile in any way: resources, arguments or
  any setting, including adding or dropping the `terrabase` entry. The
  profile binds membership, listeners and member certificates, and settings
  such as `TERRABASE_AUTH_ISSUER` or `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`
  decide which tokens and credentials TerraBase trusts;
- in `oci_desired`, adds or changes an `enforce` entry, turns on `prune`,
  shortens the prune delay, or drops an entry while `prune` is on, since
  each changes the cell's OCI resources;
- changes the trusted `signers` in any way, since they decide who may send
  operator requests and releases at all.

Everything else is ordinary: adding, changing and removing other services,
removing releasers, host grants and host images, and clearing the launch
image. A leaf amendment keeps what a root
signed earlier; changing it back is a widening change too. `ts-orch diff`
lists the widening changes under `root_required`.

The authority leader admits a spec only when all of these hold:

- The signatures are currently valid for exactly this cell's identity, and
  every encoding is canonical.
- Its `requires_binary` is at most the leader's binary level.
- Every profile and service spec passes the signed config's rules.
- Its generation is exactly one more than the stored spec's. This refuses a
  replayed or older spec, and a spec planned from a stale view, for example by
  a second operator.
- A root signed it when it widens authority.
- No removed role still has replicas.

A spec equal to the stored one is a no-op, so re-applying is safe. The leader
stores the accepted bytes in the replicated JetStream KV record
`TS_SERVICE_SET/current` and journals a `cell_spec_applied` decision. Every
controller re-verifies that record before it uses it: signatures without
expiry, the binary level, the cell's rules, and a generation that only moves
forward. Who signed which change is the leader's admission check; only
controllers can write the record. The signatures verify with the current
roots, so removing a genesis root from the image or rotating it away revokes
its specs. A running controller keeps its previously verified spec when a
new record fails these checks and logs the rejection. Startup fails closed
if the stored record cannot be verified or adopted; it never discards the
stored signer restrictions and falls back to generation 0. Replace a rejected
record through a healthy authority leader with the next signed generation
before restarting a controller. Remove retired policy members through that
same signed replacement path before deploying a binary that refuses them.

Operator requests are signed by the operator's command key and travel on the
existing host registration subject. Every issued operator credential can
publish to it, so no credential is re-issued. Only the authority leader
answers.

## Apply to another region

With global control on (`controller.global`, see
[multi-region](multi-region.md#global-state)), an operator in the global home
region applies a spec for any interregion peer with the same command:
`ts-orch apply -f SIGNED` reads the cell the spec's signature names and, when
it is not the operator config's cell, relays it instead of applying it
locally (TS-562):

1. The operator signs a `cell.spec.relay` request for the target cell around
   the signed spec (valid as long as a spec, 24 hours) and sends it, inside a
   `cell.spec.publish` request bound to the global authority epoch, to the
   home region. The controller holding the global lease answers; the regional
   leader leaves the kind to it. Outside the home region there is no global
   lease and the command fails at once.
2. The global leader checks what it can without the target's trust: the
   operator is a trusted signer here and signed the relay request too, the
   target is an interregion peer, the spec names that cell, and its generation
   is not older than the one already waiting. It stores the relay request as
   the target's `cellspec` record in `TS_GLOBAL_CONTROL`
   (`ts.global.v1.cellspec.<cell>`) and replies `{"status":"relayed","cell",
   "generation"}`.
3. The target's mirror receives the record within seconds. Its authority
   leader watches the record and rechecks it every 10 s, so a new leader picks
   it up too. It applies the spec only if the relay request's signer is a
   trusted signer of the target's own signed config, and the spec then passes
   exactly the checks above. Followers adopt it from `TS_SERVICE_SET` as usual.

The relay never widens authority: the target needs both its own trusted
operator and its own roots, as for a local apply, and the home region holds
neither. A refused record is logged once on the target's leader and stays
until the next relay replaces it. A record is refused for good once its spec
or relay request expires (24 hours), for example after a longer partition:
sign it again. A spec refused because a removed role still has replicas
applies by itself once the role is scaled to zero. The target reports
nothing back yet; check it with `ts-orch get` against that region.

## Binary levels

Each ts-orch binary understands cell specs up to its `cellspec.BinaryLevel`
(21 today; level 2 adds profile `secrets`, level 3 is reserved, level 4 `host_images`, levels 5 and 6 reserved, level 7 `oci_desired`, level 8 `signers`, level 9 `launch_image`, level 10 `artifact_store`, level 11 `atlas`, level 12 `release_fence`, level 13 a fenced set's `min_serving`, level 14 its `role`, level 15 the fence's `canary`, level 16 `machines_api`, see [Machines API](machines-api.md#production-the-cell-spec-section), level 17 a host grant's `controller`, level 18 `dashboard`, level 19 a signer's `can_install_material`, level 20 `netbird`, level 21 `machines_api.platform_organization_id`). Adding or changing `machines_api`, `dashboard` or NetBird enrollment needs a root. A change that adds a section
raises the level, and every amendment that uses the section sets
`requires_binary` to it. A controller
whose binary understands less refuses such an amendment by name and keeps its
current spec: it is the expected state while the new binary rolls out. As
leader, it also refuses to amend over a stored record it cannot read, so an
older binary never drops a newer section. An unknown section in an amendment
that claims this binary's level is invalid.

Update every controller's binary before applying an amendment that needs a
newer level. If the binary is rolled back below the stored record's level,
the cell refuses every amendment except one the root signs for the
generation that follows the stored one; it replaces the record.

## Commands

| Command | Where | Effect |
| --- | --- | --- |
| `ts-orch get --config OPERATOR_JSON` | operator host | Prints the current spec. `service list` is the same. |
| `ts-orch diff --config F -f FILE` | operator host | Plans an unsigned candidate or a signed spec on the leader, without changing anything. Prints `{"deployment_id","cell","environment","from_generation","to_generation","requires_binary","added","updated","removed","host_grants","host_images","oci_desired","signers","launch_image","artifact_store","atlas","root_required","status"}`. `launch_image` is the new launch image, or `pinned` when new hosts return to the pin. `status` is `planned`, `unchanged`, or `stale` when the generation does not follow the current one. A spec that breaks the cell's rules is refused with the rule. |
| `ts-orch apply --config F -f SIGNED` | operator host | Submits the signed spec. Prints `{"status":"applied"\|"unchanged","generation","requires_binary","roles"}`. A spec for another region is [relayed](#apply-to-another-region) through the global home and prints `{"status":"relayed","cell","generation"}`. `service apply --file` is the same. |
| `ts-orch service add --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Plans the next generation with R added and prints the leader's plan. With `--out`, writes the unsigned candidate. An identical existing service plans nothing (`"status":"unchanged"`). A different existing service is refused: use `update`. |
| `ts-orch service update --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Same as `add` for an existing role; keeps its releasers unless `--releasers` is given. |
| `ts-orch service remove --config F --role R [--out F]` | operator host | Plans the next generation without R. |
| `ts-orch service grant-host --config F --node N --private-ip IP --roles A,B --environment E [--controller SLOT] [--out F]` | operator host | Plans the next generation with N's host grant set; the plan lists N under `host_grants` and `root_required`. A grant at another node's address replaces that node's grant (a rename); `--controller` names the controller slot whose VM N is. |
| `ts-orch service revoke-host --config F --node N [--out F]` | operator host | Plans the next generation without N's host grant. The host's next enrollment or renewal is refused; credentials already issued stay valid until they expire, at most 48 hours. |
| `ts-orch service allow-image --config F --image-id ID --receipt F --delegation F [--launch] [--out F]` | operator host | Plans the next generation with the image allowed and, with `--launch`, as the launch image; the plan lists it under `host_images` (and `launch_image`) and `root_required`. The leader checks that the receipt qualifies the image now. |
| `ts-orch service revoke-image --config F --image-id ID [--launch] [--out F]` | operator host | Plans the next generation without the image. Hosts still running it become foreign to the fleet; if it was the launch image, new hosts boot the pin again. With `--launch`, only new hosts stop booting it and it stays allowed. |
| `ts-orch release sign-spec-delegation --subject-public-key LEAF_PUB --root-key ROOT_PUB --signing-key ROOT_KEY --deployment-id ID --cell CELL --environment ENV --issued-at T --expires-at T --out F` | offline, root key | Signs the root's delegation to the leaf. Prints `{"delegation","sha256","expires_at"}`. |
| `ts-orch release sign-spec --candidate F --delegation F --root-key ROOT_PUB --signing-key LEAF_KEY [--valid-for 1h] --out F` | offline, leaf key | Signs an ordinary amendment and verifies the result as a controller would. Prints `{"generation","requires_binary","signer","sha256","deployment_id","cell","environment"}`. |
| `ts-orch release sign-spec --candidate F --root --root-key ROOT_PUB --signing-key ROOT_KEY [--valid-for 1h] --out F` | offline, root key | Signs any amendment as the root, for one that widens authority. |

Candidates and signed files are created new; the commands never overwrite a
file. Signing commands need no controller connection. `--nats-forward` works as
with `ts-orch operator`.

`ts-orch oci-region attempt` uses the same path. Its `services` phase (after
`operator`) applies TerraBase's profile (`terrabase_profile`), then ts-auth
(`ts_auth_profile` and `ts_auth_service`), then
`services: [{"role", "profile", "spec"}]` from the attempt config. It signs a
7-day cell spec delegation with the attempt's trust keys. Then, for each
service, it runs `service add`, `release sign-spec` and `service apply`; it
signs as the root when the plan's `root_required` is not empty (TerraBase's
profile, ts-auth's Vault secrets), otherwise as the leaf. Last, it runs
`service grant-host` for every controller node, signed by the root and
applied: roles `ts-auth` and, where the TerraBase profile lists the node or
its address, `terrabase`; environment `canary`; `--controller` its slot.
Each run plans from the cell's current spec, so a rerun changes nothing. A
new region therefore starts with any set of services, ts-auth included, and
later changes use the same commands.

When the config names TerraBase or ts-auth neither in its own settings nor
in `services`, the phase derives the profile from the attempt's bound plan
and writes it to `services/<role>.profile.json` (ts-auth's spec to
`services/ts-auth.service.json`), then applies it as a configured one:

- **TerraBase:** `TERRABASE_REGION` the cell (`sjc-1`), peer port 9443,
  client port 9465, `TERRABASE_PEERS` the plan's database hosts, or in a
  colocated cell its controller nodes (`ts-sjc-1=10.252.0.11:9443,...`), and
  the first of them as `TERRABASE_CATALOG_PRIMARY`. A cell other than the
  home cell (GRU) trusts the home ts-auth, which already serves:
  `TERRABASE_AUTH_ISSUER` `https://gru.auth.terrascale.tech/terrascale` and
  `TERRABASE_AUTH_AUDIENCE` its own API and GRU's
  (`https://sjc.api.terrascale.tech,https://gru.api.terrascale.tech`). The
  home cell's issuer is its own ts-auth, which cannot be ready before
  TerraBase is, while TerraBase is not ready before it fetched the issuer's
  keys; its derived profile carries `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`
  instead, and a root-signed `service update` adds the issuer and audience
  once ts-auth serves.
- **ts-auth:** the cell's `<cell>.auth` origin and `<cell>.api` URL and
  audience, the TerraBase members' client endpoints (primary first, with
  failover) and the attempt material's `terrabase-member-ca.pem`, the
  region's OCI Email Delivery SMTP host, and its secrets as
  `<cell>-ts-auth-*` refs in the plan's `resource_ids.vault`; 3 replicas,
  one per failure domain. The ts-auth contract reviews only GRU's endpoints
  today, so another cell's leader refuses the derived profile until it
  accepts that cell.

## Add a service to a running region

**Prepared runbook. Every step that changes the cell needs human
confirmation.** It changes only the cell spec: one replicated KV record. No
controller is restarted or rebuilt.

Prerequisites:

1. The operator config (`/var/lib/terrascale-operator/operator.json`) reaches
   the cell over NetBird, or over a Bastion `--nats-forward`.
2. The operator's trusted signer grant lists the role, its environment and
   its repository, or step 2 names the operator with `--releasers` (then the
   root signs in step 3). Hosts for the role are registered (`ts-orch
   operator host-register`) with that role and environment after the spec is
   applied.
3. Local copies of the root public and private keys and the release leaf
   public and private keys exist as owner-only PEM files. They come from
   `gru-1-trust-root-*` and `gru-1-trust-release-leaf-*` in the Vault.
4. The role's reviewed profile, and spec if it is reconciled. For ts-auth these
   are the committed gru-1 files.

```sh
OPERATOR=/var/lib/terrascale-operator/operator.json
WORK=$(mktemp -d)
ts-orch get --config "$OPERATOR"
# Note deployment_id, cell and environment; check the generation.
```

1. Issue the leaf's cell spec delegation (once per 31 days; reuse it until it
   expires):

   ```sh
   NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   END=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
   ts-orch release sign-spec-delegation \
     --subject-public-key leaf.pub.pem --root-key root.pub.pem --signing-key root.key.pem \
     --deployment-id "$DEPLOYMENT_ID" --cell gru --environment canary \
     --issued-at "$NOW" --expires-at "$END" --out "$WORK/spec-delegation.json"
   ```

2. Plan the change and review the printed plan. It must show only the
   intended role under `added`, and `to_generation` one above the current
   generation. `root_required` lists `service ts-auth releaser mariogk` and
   `service ts-auth Vault secrets`:

   ```sh
   ts-orch service add --config "$OPERATOR" --role ts-auth \
     --profile deploy/oci-region/ts-auth-gru-1-profile.json \
     --spec deploy/oci-region/ts-auth-gru-1-service.json \
     --releasers mariogk \
     --out "$WORK/ts-auth.candidate.json"
   ```

3. Sign the candidate. With an empty `root_required`, the leaf signs it:

   ```sh
   ts-orch release sign-spec --candidate "$WORK/ts-auth.candidate.json" \
     --delegation "$WORK/spec-delegation.json" --root-key root.pub.pem \
     --signing-key leaf.key.pem --out "$WORK/ts-auth.signed.json"
   ```

   Otherwise the root signs it:

   ```sh
   ts-orch release sign-spec --candidate "$WORK/ts-auth.candidate.json" --root \
     --root-key root.pub.pem --signing-key root.key.pem --out "$WORK/ts-auth.signed.json"
   ```

4. Review the signed file, then apply it. The reply should be
   `"status":"applied"` with the new generation; `ts-orch get` then shows the
   role:

   ```sh
   ts-orch diff --config "$OPERATOR" -f "$WORK/ts-auth.signed.json"
   ts-orch apply --config "$OPERATOR" -f "$WORK/ts-auth.signed.json"
   ```

5. Release the role. For ts-auth, run `ts-orch operator ts-auth-release ...
   --profile deploy/oci-region/ts-auth-gru-1-profile.json`; see
   [ts-auth deployment](ts-auth-deployment.md).

Stop conditions:

- **Another generation was applied after your plan.** Apply refuses with
  `does not follow the current generation`. Re-plan from step 2.
- **The signed spec expired.** It is older than its validity, by default 1 h.
  Re-sign it in step 3.
- **A profile or service spec breaks the cell's rules.** Diff and apply name
  the rule. Fix the file and re-plan.
- **The leaf signed a widening change.** Apply refuses with `a root must sign
  it`. Sign it with the root in step 3.
- **A controller needs a newer binary.** Apply refuses with `requires binary
  level N`. Update the controllers' binary first.

Rollback: plan the previous content as a new generation, sign it and apply it
with `service update` or `service remove`. A spec is never rolled back by
re-applying an older signed file.
