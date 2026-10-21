# NetBird in milestone 1

ts-orch runs TerraScale's self-hosted NetBird on `ts-gru-1` and enrolls every
TerraScale host as a peer. The operator PC joins with one command whose setup
key is read from OCI Vault on the PC.

## Public ports (OCI network thread opens these on ts-gru-1)

| Port | Proto | Source | Why |
|---|---|---|---|
| 443 | tcp | 0.0.0.0/0 | Edge TLS for `netbird.terrascale.tech`: management gRPC, signal gRPC, relay websocket, REST API, embedded IdP |
| 80 | tcp | 0.0.0.0/0 | ACME HTTP-01 for the edge certificate (already open) |
| 3478 | udp | 0.0.0.0/0 | STUN (NAT discovery), served directly by `netbird-server` |
| 51820 | udp | 0.0.0.0/0 | WireGuard on ts-gru-1's own client, so peers connect directly instead of through the relay |

Nothing else is public. SSH (22/tcp) moves to the NetBird interface `wt0`
once the proof below passes; until then 22 stays open from
179.124.206.245/32.

## Server

- Image: `docker.io/netbirdio/netbird-server:0.81.3@sha256:541ecef7e98a66b17411d44e9d4dcfdb65913415f39b3b944b8e7e748f997f1d`
  (upstream combined server: management, signal, relay, STUN and the embedded
  IdP in one process).
- ts-orch service `netbird-server` (`deploy/m1/services/netbird-server.json`),
  host network, plain HTTP on `127.0.0.1:8095`, STUN on `0.0.0.0:3478/udp`.
- State: `/var/lib/ts-data/netbird` (SQLite store, IdP keys, `config.yaml`).
- `exposedAddress` is `https://netbird.terrascale.tech:443`. ts-orch sets the
  peer range to `10.200.0.0/16` so it never overlaps Tailscale's
  `100.64.0.0/10` on the NixOS hosts.

### What the edge (W5) must do for `netbird.terrascale.tech`

One hostname, one backend `127.0.0.1:8095`. The backend multiplexes by request:

1. gRPC: HTTP/2 requests with `Content-Type: application/grpc*`. The edge must
   forward them as HTTP/2 cleartext (h2c) to the backend, keep trailers, and
   never time out or buffer the stream (management sync and signal streams
   stay open for hours).
2. Websockets: `/relay`, `/ws-proxy/management`, `/ws-proxy/signal` need
   `Upgrade` pass-through with no idle timeout.
3. Everything else (`/api/*`, `/oauth2/*`) is ordinary HTTP/1.1 or HTTP/2.

A `httputil.ReverseProxy` with an `http2.Transport{AllowHTTP: true}` dial to
the backend (h2c) and `FlushInterval: -1` covers all three.

## Secrets (OCI Vault `gru-vault`, names only)

| Secret | Made by | Used by |
|---|---|---|
| `netbird-relay-auth-secret` | generated | server `authSecret` |
| `netbird-store-encryption-key` | generated | server `store.encryptionKey` |
| `netbird-session-cookie-key` | generated | server `auth.sessionCookieEncryptionKey` |
| `netbird-owner-password` | generated | owner `mariogk@terrascale.tech` in the embedded IdP |
| `netbird-admin-pat` | ts-orch, at first start (`/api/setup`) | ts-orch reconcile of groups, policies and setup keys |
| `netbird-hosts-setup-key` | ts-orch (reusable key, group `terrascale-hosts`) | host clients |
| `netbird-operator-setup-key` | ts-orch (reusable key, group `operators`) | operator PC |

Values never leave Vault except into the process that needs them.

## Access policy

- `operators` -> `terrascale-hosts`: all ports.
- `terrascale-hosts` <-> `terrascale-hosts`: all ports.

## Clients

| Host | OS | How it is enrolled |
|---|---|---|
| ts-gru-1 | Ubuntu 24.04 arm64 | ts-orch installs the pinned client and enrolls with `netbird-hosts-setup-key` (instance principal) |
| delta, mariogk-dev, beta | NixOS | Homelab fleet module `services.netbird.clients.terrascale`, setup key file from Vault |
| operator PC | any | the one command below |

## Operator PC

Run on the PC (needs the `oci` CLI logged in to the TerraScale tenancy). The
key goes from Vault through a pipe straight into the client; it is never
printed or put in argv:

```sh
curl -fsSL https://pkgs.netbird.io/install.sh | sh && \
oci secrets secret-bundle get-secret-bundle-by-name --region sa-saopaulo-1 \
  --vault-id ocid1.vault.oc1.sa-saopaulo-1.ffvnrldqaaexa.abtxeljrlqoda2dl7r527hwngvx5k5j7lhfytswubkmx6rtg5f4mjtv4xzlq \
  --secret-name netbird-operator-setup-key \
  --query 'data."secret-bundle-content".content' --raw-output | base64 -d | \
sudo netbird up --management-url https://netbird.terrascale.tech --setup-key-file /dev/stdin
```

## Proof

```sh
ssh ts-gru-1 sudo netbird status --detail   # peers: delta, mariogk-dev, beta connected
ssh delta ssh ubuntu@<ts-gru-1 NetBird IP> hostname
```
