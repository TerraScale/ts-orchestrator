# Secrets in OCI Vault

TerraScale production secrets belong in the Vault of their serving region:
`gru` (`sa-saopaulo-1`) or `sfo` (`us-sanjose-1`). The
[TS-745 inventory](secrets-inventory.md) distinguishes verified Vault records
from consumers and plaintext copies that still need migration. Production
OpenBao reads are retired; homelab ts-router/ts-reviewer stay on OpenBao.

| Vault | Value |
| --- | --- |
| Vault | `ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq` (compartment `gru-1-control`, plan `resource_ids.vault`) |
| Master key | `ocid1.key.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr57gu27ray2ukib2irijktpd6eqa6ou5zeqstsmasvqcr7hmfu2ia` (plan `resource_ids.key`) |

No value is ever printed: commands output secret names and OCIDs, errors name
the secret, and receipts and evidence carry names, OCIDs and checksums only.

## Names

A secret is named `<scope>-<service>-<key>`, lowercase words joined by
hyphens. New secrets use the region, `gru` or `sfo`, as their scope. Existing signed
`gru-1` / `sfo-1` names remain valid. The service is the consumer
(`ts-auth`, `netbird`, `cloudflare`, `trust`); the key says what it holds.
Code derives a name from an environment-style key `SERVICE_KEY` by lowering
it and turning `_` into `-`: `NETBIRD_RELAY_AUTH_SECRET` of `gru-1` is
`gru-1-netbird-relay-auth-secret` (`vaultsecret.Name`). OCI secret names allow
no `/`. Bootstrap material keeps the generated names its tooling assigns.

## Compartments decide who reads

A secret may live in another compartment than the Vault. Its compartment
decides who can read it:

| Compartment | Readers | Holds |
| --- | --- | --- |
| `gru-1-control` | Every gru-1 controller (`read secret-bundles` in the compartment); the hosts by exact grant | ts-auth, NetBird setup key and controller admin PAT, `gru-1-api-origin`, bootstrap material |
| `ts-ops` | The ts-ops instance, by exact grant | NetBird manager configuration |
| `TerraScale` | Operators only (`Administrators`) | Trust keys, NetBird owner and automation, Cloudflare |

Never put an operator-only secret in `gru-1-control`: every controller can
read that compartment.

| Secret | Compartment | Consumer |
| --- | --- | --- |
| `gru-1-ts-auth-*` | `gru-1-control` | ts-auth replicas, through the secret refs of its profile; see [ts-auth deployment](ts-auth-deployment.md) |
| `gru-1-netbird-setup-key`, `gru-1-netbird-admin-pat` | `gru-1-control` | Server enrollment and controller reconciliation; see [NetBird](../deploy/netbird/README.md#secrets-and-tokens) |
| `gru-1-netbird-datastore-encryption-key`, `gru-1-netbird-relay-auth-secret`, `gru-1-netbird-session-cookie-encryption-key` | `ts-ops` | `/run/terrascale-netbird/config.yaml` on ts-ops, fetched before each server start |
| `gru-1-netbird-owner-email`, `gru-1-netbird-owner-password` | `TerraScale` | NetBird dashboard owner login |
| `gru-1-netbird-automation-user-id`, `-pat`, `-pat-id`, `-pat-expires` | `TerraScale` | `ts-orch netbird --pat-file` and operator API calls |
| `gru-1-netbird-ssh-automation-email`, `-password` | `TerraScale` | `ts-orch netbird ssh`: browserless NetBird SSH login |
| `gru-1-cloudflare-dns-edit-token` | `TerraScale` | `CF_API_TOKEN` of `ts-orch oci-region public-api` and `dns` |
| `gru-1-cloudflare-aop-ca-key`, `gru-1-cloudflare-aop-client-key` | `TerraScale` | Zone AOP certificate keys, once created ([public API](region-bootstrap.md)) |
| `gru-1-trust-root-private-key`, `-public-key`; `gru-1-trust-release-leaf-private-key`, `-public-key` | `TerraScale` | Durable copy of the gru-1 trust root and release leaf; TS-470 signs from its local `0600` files |

## Host access

A host reads only the secrets it needs, with its instance principal, through
a dynamic group and one exact statement per secret. ts-ops:

```text
dynamic group ts-ops:  ALL {instance.id = '<ts-ops instance OCID>'}
policy ts-ops-netbird-manager-secrets (compartment ts-ops), one per secret:
  Allow dynamic-group ts-ops to read secret-bundles in compartment id <ts-ops> where target.secret.id = '<secret OCID>'
```

`read secret-bundles` covers `GetSecretBundleByName`. To give a host one more
secret, add one statement; never grant a whole compartment that holds other
secrets. The cell's own grants live in the [foundation](region-bootstrap.md).

## Store a secret

`ts-orch vault put` stores a file, a pipe or `/dev/stdin` once, with the
operator's `~/.oci/config`:

```sh
ts-orch vault put --vault-id "$VAULT" --key-id "$VAULT_KEY" \
  --compartment-id "$COMPARTMENT" --name gru-1-trust-root-public-key \
  --file gru-1-root.public.pem
```

It never replaces an existing secret. It always reads the current version
back and fails unless it equals the input, so a rerun proves the stored
copy. It prints `{"secret", "id", "created"}`.

The rotating owner adds a version with an optimistic concurrency check. Supply
bytes on stdin, never in arguments or a disk staging file:

```sh
ts-orch vault version --vault-id "$VAULT" --name "$NAME" \
  --secret-id "$SECRET" --expect-current "$VERSION" --file /dev/stdin
```

A regional privileged publisher may use `--instance-principal` instead of the
operator profile. Grant writes only to its owned secret OCIDs. The command
checks the named target, ACTIVE state and expected CURRENT version, then uses
OCI `If-Match` while publishing a new CURRENT version. Reread CURRENT on an
uncertain result; never blindly retry a signing-ring mutation. `put` remains
create-once and never rotates a value. Historical versions remain retained.

## TS-703 signing publisher

Each region has an API-key-only IAM user and group named
`gru-ts-auth-signing` or `sfo-ts-auth-signing`. The regional ring secret is
`gru-ts-auth-signing-key-ring` or `sfo-ts-auth-signing-key-ring`. The API private
key is retained in the same regional Vault as `gru-ts-auth-oci-signing-key` or
`sfo-ts-auth-oci-signing-key`; no private key belongs in a profile or env file.
The [inventory](secrets-inventory.md) records the secret OCIDs and live checks.

Each group's policy grants `read secret-bundles` only on its ring OCID and
`use secrets` on the same OCID, constrained to `SECRET_READ` and `SECRET_UPDATE`.
The API identity has no secret creation/deletion or KMS grants. Live conditional
publication of the unchanged placeholder and denial of master-key reads were
verified in both regions. The host/controller dynamic groups have a separate
bundle-read grant for their region's API private-key secret.

The regional [GRU profile](../deploy/oci-region/ts-auth-gru-1-profile.json) and
[SFO profile](../deploy/oci-region/ts-auth-sfo-1-profile.json) carry the six
non-secret `TS_AUTH_SIGNING_KEY_*` / `TS_AUTH_OCI_*` settings and the
`TS_AUTH_OCI_PRIVATE_KEY` Vault reference. The host resolves that reference into
the process environment in memory at start. ts-auth owns ring bootstrap,
conditional version publication and refresh; its UID-2000 IMDS block remains.
These profiles are prepared for signed in-place application, not applied by
this provision step. No auth binary, signing ring or auth identity data has
been changed. TS-703 must verify the applied profiles before deploying #56.
For an attempt's `services` phase, set `ts_auth_profile` and `ts_auth_service`
to the reviewed regional files. The plan-derived bootstrap profile has no
provisioned publisher IAM identity and cannot start the TS-703 release.

TS-754's auth cutover follows verified Vault delivery. Fence every old auth
writer in both regions before the owning TS-754 data operation. Its storage
contract and matching SDK release must be ready first. If TerraBase replaces
the auth storage project, update `TS_AUTH_TERRASCALE_PROJECT_ID` and its narrowed
`TS_AUTH_TERRASCALE_API_KEY` together in each regional Vault before starting the
new writer. The host derives `TS_AUTH_DATABASE` from that project ID; there is
no `TS_AUTH_PROJECT_ID` setting. Preserve master-key bytes, derivation and
sealed material; coordinate signing-ring changes separately with TS-703.

## Read a secret

Go services can import
`git.terrascale.tech/TerraScale/ts-orchestrator/pkg/vaultsecret`. `Read` returns
OCIDs, CURRENT version numbers, and values accessible only through `Value()`;
formatting and JSON show metadata only. `Watch` reads at startup, polls CURRENT,
and invokes the consumer only when an OCID/version changes. The consumer must
validate the complete snapshot and atomically replace its in-memory state.
Reads have a 30-second deadline; a startup failure refuses initialization.
Later read/apply failures retain the last successfully applied snapshot and
retry on the next interval. No secret content is included in SDK errors.
An older CURRENT version of the same secret is refused after a newer version
was applied: OCI can briefly serve stale reads after publication. To roll back,
publish the previous content as a new version instead of moving an old stage.

A service in another language can use its OCI SDK equivalent or the single
binary's file delivery path:

```sh
ts-orch vault deliver --cell gru --service ts-auth \
  --refs /etc/terrascale-orchestrator/vault/ts-auth.json \
  --dir /run/ts-auth-vault --refresh 1m
```

The reference file maps environment-style keys to `{ "vault": "<Vault OCID>",
"name": "gru-ts-auth-<purpose>" }`. The existing numbered names also work.
Files are named by lowercasing keys. The directory must already exist, be
owned by the delivery process, have mode 0700, and reside on tmpfs with swap
disabled. Consumers use the same UID, or use the host agent's workload-owned
`_FILE` deliveries described below. Under systemd, `Type=notify` waits for the
first complete delivery (`READY=1`); `RuntimeDirectoryMode=0700` creates the
private directory. `--once` verifies/delivers one snapshot and exits.

For existing signed controller paths, `--file-names` accepts reference keys
such as `controller-a.creds` as exact filenames. The service/region restriction
still applies; directory separators and hidden filenames are refused.

The writer replaces each 0600 file atomically. Services must reopen files to
observe versions; an already-open descriptor or a startup-only loader keeps
its old bytes. Coupled signing-key material belongs in one ring secret so one
atomic replacement publishes the entire ring. Every ref is limited to the
configured service and region; IAM must independently grant only its secret
OCIDs. Outputs contain directory paths, secret OCIDs and version numbers.

## Render a host file

`ts-orch vault render` runs on a host as root. It replaces each `{{KEY}}` of a
template with the JSON-quoted current secret `<scope>-<key>`, read with the
instance principal, and writes the file atomically with mode `0600` in a private tmpfs directory
with swap disabled:

```sh
ts-orch vault render --vault-id "$VAULT" --scope gru-1 \
  --template /opt/ts-ops/netbird/templates/config.yaml.tmpl --out /run/terrascale-netbird/config.yaml
```

It prints the file and the secret names it read, and refuses to run as any
other user. Every Vault read or write in `ts-orch`, ts-auth's included,
refuses to run while an OCI SDK debug, endpoint or TLS override variable is
set.

## Give a workload a secret

A workload profile names its secrets in `secrets`; its host agent reads them
with the instance principal each time it starts a replica. Signed config and
desired state hold only the names, so rotating a secret (above) needs a
restart, not a new signature. A key ending in `_FILE` is delivered as a
0600 file of the workload user under
`/run/terrascale-orchestrator-host/roles/<role>` instead of an environment value.
The host reads it again each minute, so a rotation reaches the file without a
restart; a process that reads the file only at start (TerraBase's backup
keys) still needs one. See [services](cell-spec.md#vault-secrets).

## Retired OpenBao entries

The [migration record](evidence/ts-534-oci-vault-secrets-20261005.md) lists
what moved and how each consumer was verified. These OpenBao entries did not
move and stay unchanged:

- `secret/homelab/infra/netbird/servers-gru`: the stale GRU enrollment key,
  replaced by `gru-1-netbird-setup-key`. TS-470 left it unread.
- `secret/homelab/infra/oci/operator-api`: the operator's own OCI API key,
  which cannot sit behind OCI authentication. Nothing here reads it.
- `secret/homelab/external/ts-forgejo-oci/static/{backup-local,backup-s3,harbor,object-storage}`:
  Forgejo host configuration from the HomeLab ts-ops runbook, not used by
  this repository.
