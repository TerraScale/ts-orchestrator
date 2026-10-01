# NetBird client and automatic enrollment

The shared GRU image installs NetBird 0.79.0 for every controller and managed
host. `deploy/image/image-inputs.json` pins the upstream ARM64 and AMD64 archive
sizes, SHA-256 checksums and extracted binary checksums. `client.py` verifies the
archive before streaming only its regular root-level `netbird` executable; it
does not extract archive paths or execute the upstream installation script.
`TS_NETBIRD_CLIENT_CACHE` optionally reuses archives by digest, with verification
on each use.

The image enables `netbird.service` and `terrascale-netbird-enroll.service`.
The daemon stores its identity in root-owned `/var/lib/netbird` (0700). Enrollment
runs as root, retries failures without a systemd start-rate limit, and invokes
`terrascale-orchestrator netbird-enroll`. Neither service gates controller or
managed-host startup.

Enrollment keeps servers off NetBird DNS and routes and enables NetBird SSH:
root login, SFTP and local port forwarding, with identity-provider (JWT)
authentication required and remote port forwarding off. An already connected
server whose effective configuration differs is brought down once and up again
with its saved identity. Because the daemon spawns `login` and `su` sessions,
`netbird.service` runs unconfined like `ssh.service`. Sessions run in their own
logind scopes, and `KillMode=process` lets a `systemctl restart netbird` issued
from a session finish. Manager policies decide who may connect; see "Operator
SSH and internal tools" in `docs/region-bootstrap.md`.

The public `/etc/terrascale-orchestrator/netbird.json` identifies the management
HTTPS origin, its private OCI IP, OCI region, and the setup-key secret OCID.
`config.example.json` shows the fields. The production GRU input is
`deploy/image/inputs/netbird-gru.json`; changes must update its SHA-256 in the
image inputs. The IP pins the management hostname in `/etc/hosts`, preserving
the HTTPS hostname and certificate verification when private servers cannot
reach the public address. The enrollment command reads the setup key with the
server's OCI instance principal. Setup keys and API tokens are never image
inputs. The instance's dynamic group must have read access to the referenced
OCI Vault secret.

This enrollment policy applies to controllers and managed hosts. Forgejo's
NetBird routing gateway keeps its separate routing-enabled client configuration;
its service is managed with the NetBird manager deployment.

For an existing server, stage this repository's `deploy/netbird`,
`deploy/systemd`, `deploy/image/image-inputs.json`, and
`deploy/image/inputs/netbird-gru.json`, plus the newly built orchestrator command
and its independently verified digest. Run:

```sh
sudo python3 deploy/netbird/install-client.py \
  --config deploy/image/inputs/netbird-gru.json \
  --enroll-binary /tmp/terrascale-orchestrator-linux-arm64 \
  --enroll-sha256 VERIFIED_ORCHESTRATOR_SHA256
```

The installer downloads and verifies the matching client, installs the new
enrollment command at `/usr/local/lib/terrascale-orchestrator/netbird-enroll`,
and points the enrollment unit there. It leaves the existing orchestrator
executable, configuration, and services in place. It starts NetBird and queues
enrollment asynchronously; check the result with:

```sh
sudo systemctl status netbird terrascale-netbird-enroll
sudo netbird status --json
sudo journalctl -u terrascale-netbird-enroll --no-pager -n 30
sudo netbird debug config | grep -i ssh
```

`--client-binary FILE` accepts a predownloaded client only when its digest and
architecture match the checked-in pin. `--root DIRECTORY` installs and enables
the two services in an offline root without starting them, useful for verifying
an additive rollout before applying it to a live server.

On 2026-10-01 an isolated local NetBird 0.79.0 manager (embedded IdP) verified
this configuration end to end. A systemd server peer ran this
`netbird.service` and the enrollment flags. An `operators` peer completed the
IdP device login, opened a root `netbird ssh` session (in its own logind
scope), and reached a loopback-only HTTP tool through `-L`. A peer outside
`operators` had no route to the server. After a `systemctl restart netbird`
issued from a session, the daemon reconnected with its saved identity and
accepted new sessions.
