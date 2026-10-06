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

A **service** is one role:

- `profile` is the role's delivery profile: `resources`, `args` and `env`.
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
It takes effect with the next `operator terrabase-release --profile` of
that profile. Static member enrollment still reads the signed config's
peers.

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
node listed in `TERRABASE_PEERS`: TerraBase members enroll through the signed
profile. A role that a grant names cannot be removed until that grant is
revoked. A new or changed grant gives a host credentials, so a root must
sign it; revoking one is ordinary.

Controllers run ts-auth this way. A controller VM carries no host
descriptor, so its `host-setup` names itself after its launch slot
(`controller-b` is `gru-1-ctl-2`). Grant each controller its own address:

```sh
ts-orch service grant-host --config "$OPERATOR" --node gru-1-ctl-1 \
  --private-ip 10.251.0.11 --roles ts-auth --environment canary --out "$WORK/grant-ctl-1.json"
```

## Trust

Cell specs use the release trust chain: the offline root key and the
release leaf, kept in OCI Vault (`gru-1-trust-*`, see [secrets](secrets.md)).

1. The root signs a **cell spec delegation** for the leaf. It names exactly
   one deployment ID, cell and environment and lasts at most 31 days.
2. The leaf signs **ordinary amendments**. The signature lasts at most 24
   hours: an unapplied spec expires.
3. The root signs an amendment that **widens authority** itself, without a
   delegation (`release sign-spec --root`), also for at most 24 hours.
4. Production controllers verify specs with the image's baked trust roots and
   deployment identity. A lab controller (`nats.lab: true`) uses
   `controller.spec_trust` instead. Signed production configs refuse that
   setting.

An amendment widens authority when, relative to the spec it amends, it:

- adds a releaser to a service, since releasers may release the role and
  register its hosts;
- adds or changes a host grant, since the host receives credentials;
- changes TerraBase's effective profile in any way: resources, arguments or
  any setting, including adding or dropping the `terrabase` entry. The
  profile binds membership, listeners and member certificates, and settings
  such as `TERRABASE_AUTH_ISSUER` or `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`
  decide which tokens and credentials TerraBase trusts.

Everything else is ordinary: adding, changing and removing other services,
and removing releasers and host grants. A leaf amendment keeps what a root
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
controllers can write the record. Removing a root from the image revokes its
specs. A record that fails these checks is logged and ignored. The controller
keeps the spec it has, and the next applied generation replaces the bad
record. A controller that restarts while the record is bad has only
generation 0, the signed config. `ts-orch get` then shows generation 0: plan
the full intended spec from it as generation 1.

Operator requests are signed by the operator's command key and travel on the
existing host registration subject. Every issued operator credential can
publish to it, so no credential is re-issued. Only the authority leader
answers.

## Binary levels

Each ts-orch binary understands cell specs up to its `cellspec.BinaryLevel`
(1 today). A change that adds a section raises the level, and every
amendment that uses the section sets `requires_binary` to it. A controller
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
| `ts-orch diff --config F -f FILE` | operator host | Plans an unsigned candidate or a signed spec on the leader, without changing anything. Prints `{"deployment_id","cell","environment","from_generation","to_generation","requires_binary","added","updated","removed","host_grants","root_required","status"}`. `status` is `planned`, `unchanged`, or `stale` when the generation does not follow the current one. A spec that breaks the cell's rules is refused with the rule. |
| `ts-orch apply --config F -f SIGNED` | operator host | Submits the signed spec. Prints `{"status":"applied"\|"unchanged","generation","requires_binary","roles"}`. `service apply --file` is the same. |
| `ts-orch service add --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Plans the next generation with R added and prints the leader's plan. With `--out`, writes the unsigned candidate. An identical existing service plans nothing (`"status":"unchanged"`). A different existing service is refused: use `update`. |
| `ts-orch service update --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Same as `add` for an existing role; keeps its releasers unless `--releasers` is given. |
| `ts-orch service remove --config F --role R [--out F]` | operator host | Plans the next generation without R. |
| `ts-orch service grant-host --config F --node N --private-ip IP --roles A,B --environment E [--out F]` | operator host | Plans the next generation with N's host grant set; the plan lists N under `host_grants` and `root_required`. |
| `ts-orch service revoke-host --config F --node N [--out F]` | operator host | Plans the next generation without N's host grant. The host's next enrollment or renewal is refused; credentials already issued stay valid until they expire, at most 48 hours. |
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
`service apply`. Each run plans from the cell's current spec, so a rerun
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
   generation. `root_required` lists `service ts-auth releaser mariogk`:

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
