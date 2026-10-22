# Service secrets and GHCR pull token come from the Vault the spec names

A service spec's `secrets` refs all name one Vault (`SwarmSpec` enforces one
cell and one Vault per spec). Every host resolves them with its instance
principal from that Vault, whatever region the host is in:

- The cell is the one whose OCI region holds that Vault (the gru-1 Vault in
  `sa-saopaulo-1` means cell `gru`). Names are checked against that cell:
  `<cell>-<n>-<service>-<purpose>`, or a `sharedSecrets` entry the service may read.
- A private `ghcr.io` image is pulled with `<cell>-<n>-ghcr-pull-token` from
  the same Vault, in the refs' namespace (`gru-1-ghcr-pull-token`).
- A spec with no secrets reads the pull token from the host's own cell Vault,
  as before.

IAM: policy `ts-orch-hosts-vault` lets dynamic group `ts-orch-hosts` (every
host) read secret bundles in the gru-1 Vault, so sjc and fra hosts need no
Vault of their own. Per-region Vaults can come later.

Not covered: the mesh pre-pull presents only the image, so on a host without a
cell Vault it fails and the task pulls in Prepare instead (slower, not broken).
