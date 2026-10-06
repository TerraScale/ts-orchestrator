# Cell spec

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
| `host_grants` | Static hosts outside TerraBase membership that may enroll, sorted by node (see [host grants](#host-grants)). |
| `budget` | Optional `{monthly_cap_cents, currency}` cap on node pool launches (see [autoscaling](autoscaling.md#budget)). Every node pool needs `host_monthly_cents` first. Only lowering the cap is ordinary; any other budget change needs a root. |
| `host_images` | Qualified images managed hosts may run besides the fleet's pinned image, sorted by image ID (see [host images](#host-images)). |
| `kv_snapshot` | Optional `{interval_seconds, paused}` schedule of the [configuration bucket snapshots](storage.md). `interval_seconds` (5 to 3600, 0 keeps the signed config's) applies within 5 seconds. Only a root may pause the uploads; resuming and the interval are ordinary. The signed controller config keeps the location, which a rebuilt cell restores from before any KV bucket exists, and must set one. Needs binary level 5. |

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
  be a trusted signer of the signed controller config: a spec can name who
  releases a role, never add a key. The actor's repository grant and
  `can_register_hosts` still apply.

Generation 0 holds the signed config's `controller.workloads`, plus
`controller.autoscale.services` when autoscaling is enabled. The spec may not
hold the managed placement member role: it belongs to placement and keeps its
signed controller config profile. A `terrabase` entry replaces TerraBase's
signed profile. It needs a signed TerraBase profile in the controller config,
is never reconciled, and passes the same rules (`TERRABASE_PEERS`, ports,
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

A spec's `host_grants` let static hosts outside TerraBase membership enroll.
Each grant is `{node, private_ip, roles, environment}`. The host agent on such
a host enrolls through the regular enrollment endpoint with a static
descriptor naming `node`. The controller accepts it only from `private_ip`,
and only when OCI shows the running instance named `node` holding that
address. The registration has the grant's roles and environment, and one
replica's `resources` per role as capacity. The signed enrollment response
lists the roles, and `host-setup` writes them to `host.json`.

A grant may name only roles the cell delivers (a signed or spec profile). It
may not name `terrabase` or placement's member role, and it may not name a
node listed in the effective `TERRABASE_PEERS`: TerraBase members enroll
through the TerraBase profile. A role that a grant names cannot be removed until that grant is
revoked. A new or changed grant gives a host credentials, so a root must
sign it; revoking one is ordinary.

Controllers run ts-auth this way. A controller VM carries no host
descriptor, so its `host-setup` names itself after its launch slot
(`controller-b` is `gru-1-ctl-2`). Grant each controller its own address:

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
placement keeps its seat and it can attach its retained volume. New hosts
still boot only the pinned image. See [image updates](image-updates.md).

- A receipt qualifies only the image it names, for the cell's environment
  and logical region (`gru` boots `GRU` images), under a root delegation.
- A root must sign an amendment that adds or changes an image (see
  [Trust](#trust)); revoking one is ordinary.
- The leader admits an added or changed image only while its receipt and
  delegation are currently valid. An accepted image stays allowed after they
  expire, and through a rotation of the root that delegated it.
- Revoking an image makes its hosts foreign again: they are withheld and
  their seats hold, but their teardown still works. Revoke it only after its
  hosts moved off it.
- A spec with host images requires binary level 4.

```sh
ts-orch service allow-image --config "$OPERATOR" --image-id ocid1.image.oc1.sa-saopaulo-1.... \
  --receipt image-receipt.json --delegation image-delegation.json --out "$WORK/allow-image.json"
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
  the image was qualified, not that this cell should run it;
- changes TerraBase's effective profile in any way: resources, arguments or
  any setting, including adding or dropping the `terrabase` entry. The
  profile binds membership, listeners and member certificates, and settings
  such as `TERRABASE_AUTH_ISSUER` or `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`
  decide which tokens and credentials TerraBase trusts;
- pauses the `kv_snapshot` uploads, since a rebuilt cell restores only what
  was uploaded.

Everything else is ordinary: adding, changing and removing other services,
removing releasers, host grants and host images. A leaf amendment keeps what a root
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
its specs. A record that fails these checks is logged and ignored. The controller
keeps the spec it has, and the next applied generation replaces the bad
record. A controller that restarts while the record is bad has only
generation 0, the signed config. `ts-orch get` then shows generation 0: plan
the full intended spec from it as generation 1.

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
(5 today; level 2 adds profile `secrets`, level 3 the `budget`, level 4 `host_images`, level 5 the `kv_snapshot` schedule). A change that adds a section
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

A record that a binary before cell specs stored (a signed service set) is
not read: controllers keep generation 0, and the next applied spec replaces
the record. Re-apply its services as a new cell spec.

## Commands

| Command | Where | Effect |
| --- | --- | --- |
| `ts-orch get --config OPERATOR_JSON` | operator host | Prints the current spec. `service list` is the same. |
| `ts-orch diff --config F -f FILE` | operator host | Plans an unsigned candidate or a signed spec on the leader, without changing anything. Prints `{"deployment_id","cell","environment","from_generation","to_generation","requires_binary","added","updated","removed","host_grants","budget","host_images","kv_snapshot","root_required","status"}`. `status` is `planned`, `unchanged`, or `stale` when the generation does not follow the current one. A spec that breaks the cell's rules is refused with the rule. |
| `ts-orch apply --config F -f SIGNED` | operator host | Submits the signed spec. Prints `{"status":"applied"\|"unchanged","generation","requires_binary","roles"}`. A spec for another region is [relayed](#apply-to-another-region) through the global home and prints `{"status":"relayed","cell","generation"}`. `service apply --file` is the same. |
| `ts-orch service add --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Plans the next generation with R added and prints the leader's plan. With `--out`, writes the unsigned candidate. An identical existing service plans nothing (`"status":"unchanged"`). A different existing service is refused: use `update`. |
| `ts-orch service update --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Same as `add` for an existing role; keeps its releasers unless `--releasers` is given. |
| `ts-orch service remove --config F --role R [--out F]` | operator host | Plans the next generation without R. |
| `ts-orch service grant-host --config F --node N --private-ip IP --roles A,B --environment E [--out F]` | operator host | Plans the next generation with N's host grant set; the plan lists N under `host_grants` and `root_required`. |
| `ts-orch service revoke-host --config F --node N [--out F]` | operator host | Plans the next generation without N's host grant. The host's next enrollment or renewal is refused; credentials already issued stay valid until they expire, at most 48 hours. |
| `ts-orch service allow-image --config F --image-id ID --receipt F --delegation F [--out F]` | operator host | Plans the next generation with the image allowed; the plan lists it under `host_images` and `root_required`. The leader checks that the receipt qualifies the image now. |
| `ts-orch service revoke-image --config F --image-id ID [--out F]` | operator host | Plans the next generation without the image. Hosts still running it become foreign to the fleet. |
| `ts-orch release sign-spec-delegation --subject-public-key LEAF_PUB --root-key ROOT_PUB --signing-key ROOT_KEY --deployment-id ID --cell CELL --environment ENV --issued-at T --expires-at T --out F` | offline, root key | Signs the root's delegation to the leaf. Prints `{"delegation","sha256","expires_at"}`. |
| `ts-orch release sign-spec --candidate F --delegation F --root-key ROOT_PUB --signing-key LEAF_KEY [--valid-for 1h] --out F` | offline, leaf key | Signs an ordinary amendment and verifies the result as a controller would. Prints `{"generation","requires_binary","signer","sha256","deployment_id","cell","environment"}`. |
| `ts-orch release sign-spec --candidate F --root --root-key ROOT_PUB --signing-key ROOT_KEY [--valid-for 1h] --out F` | offline, root key | Signs any amendment as the root, for one that widens authority. |

Candidates and signed files are created new; the commands never overwrite a
file. Signing commands need no controller connection. `--nats-forward` works as
with `ts-orch operator`.

`ts-orch oci-region attempt` uses the same path. Its `services` phase (after
`operator`) reads `services: [{"role", "profile", "spec"}]` from the attempt
config. It signs a 7-day cell spec delegation with the attempt's trust keys.
Then, for each service, it runs `service add`, `release sign-spec` and
`service apply`; it signs as the root when the plan's `root_required` is not
empty (ts-auth's Vault secrets), otherwise as the leaf. Each run plans from the cell's current spec, so a rerun
changes nothing. A new region therefore starts with any set of services,
ts-auth included, and later changes use the same commands.

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
