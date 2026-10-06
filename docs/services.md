# Services of a running cell

A cell's generic services can be added, updated and removed on running
controllers. Nothing is rebuilt and no controller config is edited. Package
[`internal/serviceset`](../internal/serviceset) holds the model and its
signatures. The controller side is
[`internal/app/service_registry.go`](../internal/app/service_registry.go).

## Model

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

A **service set** is the complete, role-sorted list of a cell's services at
one generation. It is bound to the cell's deployment ID, cell and
environment. Generation 0 is the signed controller config: its
`controller.workloads`, plus `controller.autoscale.services` when autoscaling
is enabled. Every later generation is a signed set that replaces the whole
list.

The set may not hold the managed placement member role. It belongs to
placement and keeps its signed controller config profile. `terrabase` keeps
its signed profile too, but a set may hold a `terrabase` entry that adds
environment settings to it, for example `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`
or `TERRABASE_AUTH_ISSUER` and `TERRABASE_AUTH_AUDIENCE`. That entry must keep
the signed resources, arguments and every signed setting (peers, ports,
region), so membership and member certificates stay as signed; it takes effect
with the next `operator terrabase-release --profile` of the extended profile.
Controllers check every set with the rules the signed config uses, including
the ts-auth contract.

Changes take effect as follows:

- A spec change takes effect at once: the reconciler converges the role.
- A profile change takes effect with the role's next release. A release binds
  its profile's config digest, so pass the new profile to the release.
- Removing a role needs the role to have no replicas. Drain it first: update
  its spec to `"replicas": {"min": 0, "max": 0}` (ts-auth allows exactly that),
  or release it with zero replicas. The controller refuses to remove a role
  while any host still runs it.

A service's `releasers` (`service add|update --releasers ops,ci`) are actors
that may release the role and register its hosts in the set's environment, in
addition to the signed grants. Each must already be a trusted signer of the
signed controller config: a set can name who releases a role, never add a key.
The actor's repository grant and `can_register_hosts` still apply. `service
update` keeps the current releasers unless `--releasers` is given. Without
`releasers`, the operator's trusted signer grant in the signed controller
config must list the role, its environment and its repository.

### Host grants

A set's `host_grants` let static hosts outside TerraBase membership enroll.
Each grant is `{node, private_ip, roles, environment}`. The host agent on such
a host enrolls through the regular enrollment endpoint with a static
descriptor naming `node`. The controller accepts it only from `private_ip`,
and only when OCI shows the running instance named `node` holding that
address. The registration has the grant's roles and environment, and one
replica's `resources` per role as capacity. The signed enrollment response
lists the roles, and `host-setup` writes them to `host.json`.

A grant may name only roles the cell delivers (a signed or set profile). It
may not name `terrabase` or placement's member role, and it may not name a
node listed in `TERRABASE_PEERS`: TerraBase members enroll through the signed
profile. A role that a grant names cannot be removed until that grant is
revoked.

Controllers run ts-auth this way. A controller VM carries no host
descriptor, so its `host-setup` names itself after its launch slot
(`controller-b` is `gru-1-ctl-2`). Grant each controller its own address:

```sh
ts-orch service grant-host --config "$OPERATOR" --node gru-1-ctl-1 \
  --private-ip 10.251.0.11 --roles ts-auth --environment canary --out "$WORK/grant-ctl-1.json"
```

## Trust

Service sets use the release trust chain: the offline root key and the
release leaf, kept in OCI Vault (`gru-1-trust-*`, see [secrets](secrets.md)).

1. The root signs a **service set delegation** for the leaf. It names exactly
   one deployment ID, cell and environment and lasts at most 31 days.
2. The leaf signs each set. The signature lasts at most 24 hours: an unapplied
   set expires.
3. Production controllers verify sets with the image's baked trust roots and
   deployment identity. A lab controller (`nats.lab: true`) uses
   `controller.service_trust` instead. Signed production configs refuse that
   setting.

The authority leader admits a set only when all of these hold:

- The delegation and the leaf signature are currently valid for exactly this
  cell's identity, and both encodings are canonical.
- Every profile and spec passes the signed config's rules.
- Its generation is exactly one more than the stored set's. This refuses a
  replayed or older set, and a set planned from a stale view, for example by a
  second operator.
- No removed role still has replicas.

A set equal to the stored one is a no-op, so re-applying is safe. The leader
stores the accepted bytes in the replicated JetStream KV record
`TS_SERVICE_SET/current`. Every controller re-verifies that record before it
uses it: signatures without expiry, the cell's rules, and a generation that
only moves forward. Removing a root from the image revokes its sets. A record
that fails these checks is logged and ignored. The controller keeps the set it
has, and the next applied generation replaces the bad record. A controller
that restarts while the record is bad has only generation 0, the signed
config. `service list` then shows generation 0: plan the full intended set
from it as generation 1.

Operator requests are signed by the operator's command key and travel on the
existing host registration subject. Every issued operator credential can
publish to it, so no credential is re-issued. Only the authority leader
answers.

## Commands

| Command | Where | Effect |
| --- | --- | --- |
| `ts-orch service list --config OPERATOR_JSON` | operator host | Prints the current set, generation and identity. |
| `ts-orch service add --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Plans the next generation with R added and prints `added`. With `--out`, writes the unsigned candidate. An identical existing service plans nothing (`"status":"unchanged"`). A different existing service is refused: use `update`. |
| `ts-orch service update --config F --role R --profile F [--spec F] [--releasers A,B] [--out F]` | operator host | Same as `add` for an existing role; keeps its releasers unless `--releasers` is given. |
| `ts-orch service remove --config F --role R [--out F]` | operator host | Plans the next generation without R. |
| `ts-orch service grant-host --config F --node N --private-ip IP --roles A,B --environment E [--out F]` | operator host | Plans the next generation with N's host grant set; the plan lists N under `host_grants`. |
| `ts-orch service revoke-host --config F --node N [--out F]` | operator host | Plans the next generation without N's host grant. The host's next enrollment or renewal is refused; credentials already issued stay valid until they expire, at most 48 hours. |
| `ts-orch release sign-service-delegation --subject-public-key LEAF_PUB --root-key ROOT_PUB --signing-key ROOT_KEY --deployment-id ID --cell CELL --environment ENV --issued-at T --expires-at T --out F` | offline, root key | Signs the root's delegation to the leaf. Prints `{"delegation","sha256","expires_at"}`. |
| `ts-orch release sign-service-set --candidate F --delegation F --root-key ROOT_PUB --signing-key LEAF_KEY [--valid-for 1h] --out F` | offline, leaf key | Signs a candidate and verifies the result as a controller would. Prints `{"generation","sha256","deployment_id","cell","environment"}`. |
| `ts-orch service apply --config F --file SIGNED` | operator host | Submits the signed set. Prints `{"status":"applied"\|"unchanged","generation","roles"}`. |

Plans print `{"deployment_id","cell","environment","from_generation",
"to_generation","added","updated","removed","status","candidate"}`.
Candidates and signed files are created new; the commands never overwrite a
file. Signing commands need no controller connection. `--nats-forward` works as
with `ts-orch operator`.

`ts-orch oci-region attempt` uses the same path. Its `services` phase (after
`operator`) reads `services: [{"role", "profile", "spec"}]` from the attempt
config. It signs a 7-day service set delegation with the attempt's trust keys.
Then, for each service, it runs `service add`, `release sign-service-set` and
`service apply`. Each run plans from the cell's current set, so a rerun
changes nothing. A new region therefore starts with any set of services,
ts-auth included, and later changes use the same commands.

## Add a service to a running region

**Prepared runbook. Every step that changes the cell needs human
confirmation.** It changes only the cell's service set: one replicated KV
record. No controller is restarted or rebuilt.

Prerequisites:

1. The operator config (`/var/lib/terrascale-operator/operator.json`) reaches
   the cell over NetBird, or over a Bastion `--nats-forward`.
2. The operator's trusted signer grant lists the role, its environment and
   its repository, or step 2 names the operator with `--releasers`. Hosts for
   the role are registered (`ts-orch operator host-register`) with that role
   and environment after the set is applied.
3. Local copies of the root public and private keys and the release leaf
   public and private keys exist as owner-only PEM files. They come from
   `gru-1-trust-root-*` and `gru-1-trust-release-leaf-*` in the Vault.
4. The role's reviewed profile, and spec if it is reconciled. For ts-auth these
   are the committed gru-1 files.

```sh
OPERATOR=/var/lib/terrascale-operator/operator.json
WORK=$(mktemp -d)
ts-orch service list --config "$OPERATOR"
# Note deployment_id, cell and environment; check the generation.
```

1. Issue the leaf's service set delegation (once per 31 days; reuse it
   until it expires):

   ```sh
   NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   END=$(date -u -d '+30 days' +%Y-%m-%dT%H:%M:%SZ)
   ts-orch release sign-service-delegation \
     --subject-public-key leaf.pub.pem --root-key root.pub.pem --signing-key root.key.pem \
     --deployment-id "$DEPLOYMENT_ID" --cell gru --environment canary \
     --issued-at "$NOW" --expires-at "$END" --out "$WORK/service-delegation.json"
   ```

2. Plan the change and review the printed plan. It must show only the
   intended role under `added`, and `to_generation` one above the current
   generation:

   ```sh
   ts-orch service add --config "$OPERATOR" --role ts-auth \
     --profile deploy/oci-region/ts-auth-gru-1-profile.json \
     --spec deploy/oci-region/ts-auth-gru-1-service.json \
     --releasers mariogk \
     --out "$WORK/ts-auth.candidate.json"
   ```

3. Sign the candidate with the leaf:

   ```sh
   ts-orch release sign-service-set --candidate "$WORK/ts-auth.candidate.json" \
     --delegation "$WORK/service-delegation.json" --root-key root.pub.pem \
     --signing-key leaf.key.pem --out "$WORK/ts-auth.signed.json"
   ```

4. Apply it. The reply should be `"status":"applied"` with the new generation;
   `ts-orch service list` then shows the role:

   ```sh
   ts-orch service apply --config "$OPERATOR" --file "$WORK/ts-auth.signed.json"
   ```

5. Release the role. For ts-auth, run `ts-orch operator ts-auth-release ...
   --profile deploy/oci-region/ts-auth-gru-1-profile.json`; see
   [ts-auth deployment](ts-auth-deployment.md).

Stop conditions:

- **Another generation was applied after your plan.** Apply refuses with
  `does not follow the current generation`. Re-plan from step 2.
- **The signed set expired.** It is older than its validity, by default 1 h.
  Re-sign it in step 3.
- **A profile or spec breaks the cell's rules.** Apply names the rule. Fix
  the file and re-plan.

Rollback: plan the previous content as a new generation, sign it and apply it
with `service update` or `service remove`. A set is never rolled back by
re-applying an older signed file.
