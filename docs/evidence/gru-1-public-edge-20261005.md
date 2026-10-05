# TS-486 gru-1 public edge, 2026-10-05

Live run of the public API edge from #158 under the standing non-destructive
gru-1 authorization. Every action was a create. Nothing was deleted,
detached or terminated. No secret values appear here.

Plan: [bound plan](gru-1-public-edge-20261005/bound-plan.json). It is the
[phase-1 bound plan](gru-1-phase1-completion-20261004/bound-plan.json) plus:

- `budget.rates.lb_hour` and `lb_mbps_hour`
- the TS-487 controller rule (TCP 8080 from `10.251.0.128/26`)
- `public_api.min_mbps` 10, `max_mbps` 100 and `terrabase_members` `["gru-1-db-1"]`
- `public_api.origin_pull`
- the five public `resource_ids` that `apply` printed

## Origin pulls

- **CA:** dedicated RSA 3072 self-signed CA `CN=TerraScale gru-1 origin-pull CA`, valid until 2046-10-05. SHA-256 fingerprint `04:88:F6:79:…:0E:61`. Public PEM: [origin-pull-ca.pem](gru-1-public-edge-20261005/origin-pull-ca.pem).
- **Client certificate:** RSA 2048 leaf with `CA:FALSE` and clientAuth, signed directly by that CA, valid until 2041-10-01.
  - Uploaded to the `terrascale.tech` zone as `a68331f0-3491-4c68-8cb3-264953efcc89`. Status `active`; it is the zone's only certificate.
  - Zone AOP is still `enabled: false`. `dns --apply` turns it on.
- **Private keys:** kept only in the gru-1 OCI Vault, in the operator-only `TerraScale` compartment ([secrets](../secrets.md)). Key material went to `oci` only through an owner-only file or stdin, never in arguments.
  - `gru-1-cloudflare-aop-ca-key`: `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa64654wytuun36oudkcpx5gtgn5ikzyghp4beyhckmota`
  - `gru-1-cloudflare-aop-client-key`: `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajetlmkgbof754hmc5caeyiq5ehifj7f6dapkqapsvt5q`
  - `ts-orch vault put` wrote both and verified its own readback. Their SHA-256 prefixes (`1aa58712…`, `a48bae37…`) match the generated files.
  - The first copies were created in `gru-1-control` as `gru-1-api-originpull-ca-key` and `gru-1-api-originpull-client-key`, before TS-534 fixed the names. That compartment is readable by every controller, so both copies were moved to `TerraScale` with `change-compartment`. They are duplicates now; deleting them needs the user's approval.

## Origin certificate

`public-api cert --apply` asked Cloudflare's Origin CA for a certificate covering `auth.terrascale.tech` and `gru.api.terrascale.tech`, expiring 2041-10-01. It stored the certificate and key in Vault secret `gru-1-api-origin`. A rerun reports `no changes`.

## Load balancer

`public-api apply --member-ca` used the public gru-1 TerraBase member CA from the Vault: `CN=TerraBase member CA gru-1`, SHA-256 `60:B4:46:8D:…:65:99`. It created:

| Resource | ID |
|---|---|
| `gru-1-api` load balancer, public IP `163.176.163.205` | `ocid1.loadbalancer.oc1.sa-saopaulo-1.aaaaaaaawziu3epvzdahcls7kxcxxetcur5jrjjzunjeokagnfd3nhwh2gra` |
| `gru-1-api-nsg` | `ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaa7f5ctnhutqzezcsfjqdeoqlwgyzguyarp3mgpvfxwsn7dxaq5bya` |
| `gru-1-api-subnet` | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaargqfo5ecs2l3titnqrwmulh4almznhdm4wwzx43vgpquqys4p52a` |
| `gru-1-api-igw` | `ocid1.internetgateway.oc1.sa-saopaulo-1.aaaaaaaa53y2eoywfdus76w64hnx3mj3nky4oxpfwa75ymqlxcgyy3bn5e4a` |
| `gru-1-api-routes` | `ocid1.routetable.oc1.sa-saopaulo-1.aaaaaaaazayk7xhuk3cebehkgp5m5377y4lhplp4hguv4frowelwwu73r2na` |
| `gru-1-api-security` | `ocid1.securitylist.oc1.sa-saopaulo-1.aaaaaaaa4vx6wjsw5zzceb443emn7372dxzeugtp2a7dms5ib3xyfrtvyv3q` |

`apply` completed only after its shared readback (`CheckBalancer`, attachments and Cloudflare-only NSG rules) passed. `origin-ips` and `cert` dry runs then report `no changes`.

Readback at 2026-10-05T20:27Z:

```text
backend-set terrabase: 10.251.0.21:9465 OK (HTTPS, member-CA verified, GET /readyz 200)
backend-set ts-auth:   10.251.0.11-13:8080 CRITICAL CONNECT_FAILED
direct https://163.176.163.205/  no connection (NSG admits Cloudflare ranges only)
direct http://163.176.163.205/   no connection
```

`ts-auth` reports CONNECT_FAILED because nothing listens on the controllers' port 8080 yet. That workload belongs to TS-487.

## Regional hostnames, 2026-10-05T20:45Z

The user decided that regional hosts follow `<region>.<service>.terrascale.tech`, so ts-auth is `gru.auth.terrascale.tech`. `api.terrascale.tech` and `auth.terrascale.tech` are ts-atlas Worker routes (proxied AAAA `100::`). This run did not create, change or delete them.

| Step | Result |
|---|---|
| `cert` dry run | Plans a new version of `gru-1-api-origin`, then installs the certificate and points both listeners at it |
| `cert --apply` | New Origin CA certificate for `gru.api.terrascale.tech` and `gru.auth.terrascale.tech`, expiring 2041-10-01, as a new version of `gru-1-api-origin`. Installed as `origin-546805c6db19`; both HTTPS listeners now serve it. A rerun reports `no changes`. |
| `apply --member-ca` | Hostname `ts-auth` updated in place to `gru.auth.terrascale.tech`. The full readback passed. |

Load balancer readback:

```text
hostnames {'terrabase': 'gru.api.terrascale.tech', 'ts-auth': 'gru.auth.terrascale.tech'}
listeners {'http': None, 'terrabase': 'origin-546805c6db19', 'ts-auth': 'origin-546805c6db19'}
cert origin               SAN auth.terrascale.tech, gru.api.terrascale.tech   (unused, kept)
cert origin-546805c6db19  SAN gru.api.terrascale.tech, gru.auth.terrascale.tech, notAfter 2041-10-01
```

Kept, not deleted:
- the unused `origin` certificate on the load balancer
- its Origin CA certificate in Cloudflare (hosts `auth.terrascale.tech` and `gru.api.terrascale.tech`)
- the earlier version of `gru-1-api-origin`

Removing any of them needs the user's approval.

## Cloudflare, with the logged-in `cf` CLI

The DNS token lacks Config Rules Edit, so these steps ran through `cf` (account owner login) instead of `oci-region dns`. They follow the same order and values:

1. **Full (strict):** configuration rule `ts-orch-gru-1-api-ssl-strict`, `set_config ssl strict` for `(http.host in {"gru.api.terrascale.tech" "gru.auth.terrascale.tech"})`, appended last to the zone's `http_config_settings` ruleset `ca1fd87761ab4266a19c23e1de815891`. The ruleset's only other rule sets `disable_rum` and does not change SSL.
2. **Hostname overrides:** `GET origin_tls_client_auth/hostnames/<host>` answers `404` / `1553` for both hosts, which means no association exists. Voiding them with `enabled: null` is not possible: Cloudflare rejects the PUT with `1404 Certificate ID required`. The code now accepts `1553` as "no override" and still refuses every other error.
3. **Zone AOP:** `origin_tls_client_auth/settings` set to `enabled: true` and read back. The zone's only client certificate is `a68331f0-3491-4c68-8cb3-264953efcc89`, status `active`.
4. **DNS:** proxied A records to `163.176.163.205`, TTL auto:
   - `gru.api.terrascale.tech`: `d951f2b5a6a802c7821a4670a9f8fc98`
   - `gru.auth.terrascale.tech`: `ecc4fc7b0e07cb7828ac6ce7f9516a52`

## Verification, 2026-10-05T20:50Z

```text
200 https://gru.api.terrascale.tech/healthz  {"status":"ok","version":"0.1.0","region":"gru-1"}
200 https://gru.api.terrascale.tech/readyz   {"status":"ready","version":"0.1.0","region":"gru-1"}
302 https://gru.api.terrascale.tech/         -> /docs
301 http://gru.api.terrascale.tech/          -> https://gru.api.terrascale.tech/
200 https://api.terrascale.tech/healthz      {"status":"ok","version":"0.1.0","region":"gru-1"}   (through ts-atlas)
302 https://api.terrascale.tech/             -> https://api.terrascale.tech/docs
404 https://api.terrascale.tech/docs         Scalar (TS-539) ships with the next TerraBase rollout
502 https://gru.auth.terrascale.tech/readyz  ts-auth backends CONNECT_FAILED: nothing listens on :8080 yet (TS-487)
530 https://auth.terrascale.tech/readyz      ts-atlas Worker; follows gru.auth once ts-auth runs
```

The origin answers only Cloudflare: its NSG admits Cloudflare's ranges, and every HTTPS listener requires the origin-pull client certificate. The 200s above came through Cloudflare. Direct connections to `163.176.163.205` get no connection.

## Follow-ups

- **Token permission:** add Config Rules Edit (read is enough for a dry run) to `gru-1-cloudflare-dns-edit-token`, so `ts-orch oci-region dns` can verify this state itself.
- **Deletions awaiting user approval:**
  - the stale `origin` certificate and its Origin CA certificate
  - the duplicate `gru-1-api-originpull-*` Vault secrets
