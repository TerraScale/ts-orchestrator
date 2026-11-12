# Service secrets come from the Vault the spec names

A service spec's `secrets` refs all name one Vault (`SwarmSpec` enforces one
cell and one Vault per spec). Every host resolves them with its instance
principal from that Vault, whatever region the host is in:

- The cell is the one whose OCI region holds that Vault (the gru-1 Vault in
  `sa-saopaulo-1` means cell `gru`). Names are checked against that cell:
  `<cell>-<n>-<service>-<purpose>`, or a `sharedSecrets` entry the service may read.
- The GHCR pull token is separate: every host reads the shared one from
  gru-vault (`vaultsecret.ReadGHCRPullToken`, #119).

IAM: policy `ts-orch-hosts-vault` lets dynamic group `ts-orch-hosts` (every
host) read secret bundles in the gru-1 Vault, so sjc and fra hosts need no
Vault of their own. Per-region Vaults can come later.

Every service apply resolves all references through the existing Vault client
before creating or updating a service, including metadata completion. A missing
or unreadable secret fails the apply with its name and leaves the running service
unchanged. Values are discarded after the preflight; tasks still fetch their own
file deliveries at startup. This checks availability at apply time and cannot
prevent a later Vault outage or secret removal.

## TerraBase file storage

Prepare one R2 identity for all regions before applying the TerraBase service:

1. Create one R2 API token with object read, write and delete access only to
   `terrascale-gru-files`, `terrascale-sjc-files` and `terrascale-fra-files`.
2. Store its access key ID in the service spec's OCI Vault as
   `gru-1-terrabase-files-access-key-id`, and its secret access key as
   `gru-1-terrabase-files-secret-key`. Do not put either value in the service spec.
3. Roll TerraBase from a host with the reviewed service file using
   `ts-orch service apply -f deploy/m1/services/terrabase.json`.

The spec delivers these as `TERRABASE_FILES_S3_ACCESS_KEY_ID_FILE` and
`TERRABASE_FILES_S3_SECRET_ACCESS_KEY_FILE` identically in every region. It sets
`TERRABASE_FILES_S3_ENDPOINT` to
`https://6cd3f3639e928077593d9b470765efeb.r2.cloudflarestorage.com`.
Signing uses region `auto`; TerraBase derives the bucket name from its serving
region, so no bucket setting is needed.

Without file-storage credentials, TerraBase answers 503 on file transfers and
everything else keeps working. The apply preflight refuses to roll the new spec
until both Vault secrets, along with every other referenced secret, are readable.
