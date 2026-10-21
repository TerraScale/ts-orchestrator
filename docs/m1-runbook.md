# Milestone 1 runbook: ts-orch single host on ts-gru-1

One process (`ts-orch single-host`) runs the SwarmKit manager and worker,
the containerd executor, a local control socket and the HTTPS edge (`:80`
ACME HTTP-01 + redirect, `:443`). Services come from
`deploy/m1/services/*.json`.

## Host

| Fact | Value |
|---|---|
| ssh | `ssh ts-gru-1` (`ubuntu@163.176.124.12`, passwordless sudo) |
| Shape | OCI `gru-1-ctl-1`, A1.Flex 4 OCPU / 24 GB, Ubuntu 24.04 aarch64 |
| Runtime | containerd 2.2.1 + runc 1.3.4 (Ubuntu packages) |
| Open ports | 80, 443 from anywhere; 22 from the operator egress IP |
| State | `/var/lib/ts-orch` (Raft, edge certificates, socket) |
| Data | `/var/lib/ts-data/<service>` (bind mounts; TerraBase uses `terrabase`) |
| Edge certificates | `/var/lib/ts-orch/edge-certs` (Let's Encrypt, HTTP-01 on :80) |

The Ubuntu OCI image ends `INPUT` with a REJECT rule; the 80/443 ACCEPT rules
must sit above it or ACME validation fails with "no viable challenge type".
Fixed on ts-gru-1 2026-10-21 and saved with `netfilter-persistent save`:

```sh
ssh ts-gru-1 sudo iptables -S INPUT   # 80 and 443 ACCEPT before the REJECT
```

## Install or upgrade

Every main push publishes a CI release `ci-<sha>-run-<id>` with
`terrascale-orchestrator-linux-arm64`. Install the newest one:

```sh
tag=$(gh release list -R TerraScale/ts-orchestrator -L 1 --json tagName -q '.[0].tagName')
asset=terrascale-orchestrator-linux-arm64
url=https://github.com/TerraScale/ts-orchestrator/releases/download/$tag/$asset
sum=$(gh release view "$tag" -R TerraScale/ts-orchestrator --json assets \
  -q ".assets[] | select(.name==\"$asset\") | .digest" | cut -d: -f2)
deploy/m1/install.sh ts-gru-1 "$url" "$sum"
```

`install.sh` verifies the sha256, installs `/usr/local/bin/terrascale-orchestrator`
(alias `ts-orch`), creates the state and data directories, installs
`ts-orch.service` and restarts it. Re-running it is the upgrade.

Check:

```sh
ssh ts-gru-1 systemctl is-active ts-orch
ssh ts-gru-1 sudo journalctl -u ts-orch -n 50 --no-pager
```

## Services

```sh
scp deploy/m1/services/whoami.json ts-gru-1:/tmp/whoami.json
ssh ts-gru-1 sudo ts-orch service apply -f /tmp/whoami.json
ssh ts-gru-1 sudo ts-orch service ls
ssh ts-gru-1 sudo ts-orch service rm whoami
```

## DNS (Cloudflare, DNS-only)

Records point at the host public IP; the edge obtains certificates itself, so
Cloudflare proxying stays off.

| Name | Type | Content | Record ID | Purpose |
|---|---|---|---|---|
| `m1-test.terrascale.tech` | A | 163.176.124.12 | `fac1872f4903e4ddbb235db8c3c48af1` | W6 whoami proof |

Create a record (the `cf` OAuth login was absent on 2026-10-21; the
`CLOUDFLARE_API_TOKEN` environment token has `dns_records:edit`):

```sh
cf dns records create -z terrascale.tech --body \
  '{"type":"A","name":"<name>.terrascale.tech","content":"163.176.124.12","proxied":false,"ttl":1}'
```

## Proof log

| Date | Binary (CI release) | Check | Result |
|---|---|---|---|
| 2026-10-21 | local arm64 build of W2+W3+W4+W5 branches (smoke, state `/var/lib/ts-orch-smoke`) | `curl https://m1-test.terrascale.tech/` | Let's Encrypt cert issued, edge 502 (task blocked by container-material gate) |
