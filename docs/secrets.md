# Secrets in OCI Vault

Every TerraScale secret lives in the gru-1 OCI Vault. OpenBao is retired for
TerraScale (decision of 2026-10-05): nothing in this repository reads it, and
its old entries are kept, not deleted.

| Vault | Value |
| --- | --- |
| Vault | `ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq` (compartment `gru-1-control`, plan `resource_ids.vault`) |
| Master key | `ocid1.key.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr57gu27ray2ukib2irijktpd6eqa6ou5zeqstsmasvqcr7hmfu2ia` (plan `resource_ids.key`) |

No value is ever printed: commands output secret names and OCIDs, errors name
the secret, and receipts and evidence carry names, OCIDs and checksums only.

## Names

A secret is named `<scope>-<service>-<key>`, lowercase words joined by
hyphens. The scope is the Vault's cell, `gru-1`; the service is the consumer
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
| `gru-1-ts-auth-*` | `gru-1-control` | ts-auth env file; see [ts-auth deployment](ts-auth-deployment.md) |
| `gru-1-netbird-setup-key`, `gru-1-netbird-admin-pat` | `gru-1-control` | Server enrollment and controller reconciliation; see [NetBird](../deploy/netbird/README.md#secrets-and-tokens) |
| `gru-1-netbird-datastore-encryption-key`, `gru-1-netbird-relay-auth-secret`, `gru-1-netbird-session-cookie-encryption-key` | `ts-ops` | `/etc/netbird/config.yaml` on ts-ops, rendered by `install.sh` |
| `gru-1-netbird-owner-email`, `gru-1-netbird-owner-password` | `TerraScale` | NetBird dashboard owner login |
| `gru-1-netbird-automation-user-id`, `-pat`, `-pat-id`, `-pat-expires` | `TerraScale` | `ts-orch netbird --pat-file` and operator API calls |
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

To rotate, add a version without putting the value on a command line, then
rerun `put` with the new value to prove it:

```sh
umask 077
base64 -w0 new-value > new-value.b64
jq -n --rawfile c new-value.b64 '{secretContentContent: $c}' > new-value.json
oci vault secret update-base64 --secret-id "$SECRET" --from-json file://new-value.json
shred -u new-value new-value.b64 new-value.json
```

## Read a secret

Operators read a secret into an owner-only file or an environment variable,
never onto the terminal:

```sh
vault_secret() {
  oci secrets secret-bundle get-secret-bundle-by-name --vault-id "$VAULT" --secret-name "$1" \
    --query 'data."secret-bundle-content".content' --raw-output | base64 -d
}
(umask 077; vault_secret gru-1-netbird-automation-pat > "$PAT")
export CF_API_TOKEN="$(vault_secret gru-1-cloudflare-dns-edit-token)"
```

## Render a host file

`ts-orch vault render` runs on a host as root. It replaces each `{{KEY}}` of a
template with the JSON-quoted current secret `<scope>-<key>`, read with the
instance principal, and writes the file atomically with mode `0600`:

```sh
ts-orch vault render --vault-id "$VAULT" --scope gru-1 \
  --template /opt/ts-ops/netbird/templates/config.yaml.tmpl --out /etc/netbird/config.yaml
```

It prints the file and the secret names it read, and refuses to run as any
other user. Every Vault read or write in `ts-orch`, ts-auth's included,
refuses to run while an OCI SDK debug, endpoint or TLS override variable is
set.

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
