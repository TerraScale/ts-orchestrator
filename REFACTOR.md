# ts-orch: fastest working deployment (milestone 1 = gru)

> Model rule (user, 2026-10-21): Opus 5.5 (`claude-opus-5-5`) for lead and
> long work, Haiku 5.5 (`claude-haiku-5-5`) for bounded work under 10 minutes.
> Never Haiku 4.5. This replaces the older GPT 6.1 Sol rule.
>
> The previous 1,241-line plan is kept unchanged in
> [docs/refactor-full-plan.md](docs/refactor-full-plan.md). Everything in it
> that is not below is **Later**.

## Goal

`ts-orch` (embedded SwarmKit + containerd) runs on one OCI A1 VM in gru and
deploys TerraBase, ts-auth and ts-dashboard from container images pinned by
digest. The services are public on HTTPS, sign-in works, and the dashboard
shows data stored in TerraBase. Nothing else ships in milestone 1.

## Milestone 1: Done =

| # | Check | Expected |
|---|---|---|
| 1 | `curl -fsS https://api.terrascale.tech/readyz` | 200 |
| 2 | `curl -fsS https://auth.terrascale.tech/healthz` | 200 |
| 3 | `curl -fsS https://dash.terrascale.tech/readyz` | 200 |
| 4 | `curl -fsS https://auth.terrascale.tech/terrascale/.well-known/openid-configuration \| jq -r .issuer` | `https://auth.terrascale.tech/terrascale` |
| 5 | `ssh ts-gru-1 sudo ts-orch service ls` | 3 services, each `1/1 running`, image `ghcr.io/terrascale/...@sha256:...` |
| 6 | Browser: open `https://dash.terrascale.tech`, sign in as `mariogk@terrascale.tech` with the email code | Lands on the dashboard; org/projects list loads |
| 7 | `ssh ts-gru-1 sudo systemctl restart ts-orch && sleep 60`, then repeat 1-3 and reload the dashboard | All 200; same data shown (TerraBase volume survived) |
| 8 | `dig +short auth.terrascale.tech dash.terrascale.tech api.terrascale.tech` | The VM's public IP (Cloudflare DNS-only) |

## Architecture (milestone 1)

```
Internet ─443/80─> VM ts-gru-1 (VM.Standard.A1.Flex, Ubuntu 24.04 arm64, public IP)
  ts-orch (systemd, root) = SwarmKit manager+worker in one process (single-node Raft)
    ├─ containerd executor: pulls ghcr.io/terrascale/*@sha256, runc, host network
    ├─ edge: :443 TLS (ACME HTTP-01, certs in /var/lib/ts-orch/edge), host -> 127.0.0.1:port
    │     api.terrascale.tech -> terrabase:8080   auth.terrascale.tech -> ts-auth:8090
    │     dash.terrascale.tech -> ts-dashboard:8085
    └─ services from deploy/m1/services/*.json (`ts-orch service apply -f`)
  terrabase: bind mount /var/lib/ts-data/terrabase -> /data (boot volume, 100 GB)
  ts-auth, ts-dashboard -> TerraBase at http://127.0.0.1:8081 (shared host network)
  secrets: OCI Vault -> ts-orch injection into containers (owned by the OCI Vault thread)
  netbird: ts-orch runs the NetBird server on ts-gru-1 and enrolls clients (N1)
  OCI network: gru-1-vcn/subnet/IGW/security list/NSGs reconciled by ts-orch (N2)
Host already provisioned (ts-gru-1); deploy/m1/install.sh puts the ts-orch release binary + systemd unit on it.
```

No OCI load balancer, custom image, NATS federation, admission service or
3-controller cell in milestone 1.

## What works today (read on `refactor/oci-regional-always-on`, now consolidated into main `225a0aa9e`, 2026-10-21)

| Component | Status | Evidence | Gap for M1 |
|---|---|---|---|
| Build | FIXED (W1) | consolidation thread repaired `internal/rootsecret` on main `225a0aa9e` | none |
| SwarmKit manager | PARTIAL | `internal/swarmruntime/node.go:127-142` single-node Raft exists; only reachable via `managed-runtime-start` (`internal/app/managed_runtime.go:22`), which needs OCI, Vault, admission | W2 |
| containerd executor | PARTIAL | `internal/swarmruntime/executor.go:67`, `controller.go:121-194`: digest pull, runc, env, read-only rootfs, host network. Real-containerd test only with `-containerd-socket` | W4 (mounts, readiness path); secrets W11 |
| Declare a service | MISSING | `ServiceIntent` (`swarmruntime/service.go:37`) has no CLI/API caller; TerraBase refused (`service.go:62`); ts-auth port hardcoded (`app/platform_service.go:55`) | W3 |
| `deploy` command | OLD PATH | `operator deploy` -> `placement.PlanWorkload` -> native host supervision (`app/delivery_planner.go:223`) | Not used in M1; delete Later |
| OCI provisioning | PARTIAL | `oci-region foundation` (private subnet only, no IGW), `oci-region attempt up` (3 controllers, `bootstrap/founder_plan.go:207`) | N2 adopts the existing gru network; W7 installs on the host |
| Host image / boot | WORKS, heavy | `image.yml` qcow2 with containerd + NetBird + units; needs `image promote` | Not needed: stock Ubuntu + containerd already on ts-gru-1 |
| Public HTTPS | PARTIAL | Cloudflare -> OCI LB -> fixed backends (`ociregion/publicapi/public.go:137-143`) | W5 built-in edge |
| Secrets | PARTIAL | Vault-only delivery (`vaultsecret/delivery.go:22`, `swarmruntime/container_material.go`) | W11 (OCI Vault thread) |
| NetBird | Required by image | `internal/image/guest.go:40`, `internal/netbird/**` | N1 (ts-orch-managed server + clients) |
| Dashboard (ts-orch) | PARTIAL | served by `ts-orch run`; mixes SwarmKit and old rollout data | Not needed for M1 |
| ts-orch release binary | WORKS | `ci.yml` publishes linux arm64/amd64 to release `ci-<sha>-run-<id>` | Used by W7 |
| TerraBase / ts-auth images | NOT USABLE | `terrascale/Dockerfile` linux-x64 only; pushed only to private `registry.fly.io` | W8 |
| Off-Fly runtime | MISSING | ts-auth/TerraBase/dashboard hardcode `*.ts-terrabase.internal`; off Fly only `127.0.0.1:8081` in Development | W9, W10 |
| ts-dashboard image | NOT USABLE | amd64 only, `registry.fly.io` | W10 |
| Fly apps | GONE | `flyctl apps list` empty; `auth.` CNAME dangles; data volumes destroyed 2026-10-13 | M1 starts with fresh data |

## Decisions

- DECISION: one VM, not a 3-controller cell. Reason: fastest path; single-node Raft already exists.
- DECISION: own edge TLS in ts-orch (`golang.org/x/crypto/acme/autocert` + `httputil.ReverseProxy`), Cloudflare DNS-only. Reason: no LB, no Origin CA, no Vault; about 150 lines.
- DECISION: images on public GHCR (`ghcr.io/terrascale/<name>`), multi-arch, built by `GITHUB_TOKEN`. Reason: all repos are public; no pull credential on the VM.
- Secrets: OCI Vault for all OCI-hosted TerraScale services (user, 2026-10-21). The OCI Vault thread owns Vault infra and ts-orch secret injection (W11); no other item touches secret-injection code.
- DECISION: fresh data. Reason: Fly volumes are gone; snapshot restore is Later.
- DECISION: `single-host` is a separate command, not a flag on the cluster path. Reason: repo zero-config rule (no on/off switches).

## Work items

Owned paths are exclusive: no two items edit the same file. ts-orch items
W2-W7, N1, N2 branch from the consolidated main SHA. W8-W12 can start now.
Hours are for one Opus 5.5 worker. Threads (2026-10-21): W2, W3, W4, W5, W6+W7, N1, N2 on mariogk-dev; W9 on beta; W8+W10 images thread; W11 OCI Vault thread; W12 after W6-W11.

**Ask-once list for the parent** (user decisions before the marked item can finish):
- PAID: none. The gru host exists and is Always Free (whole A1 free quota).
- CRED: W11 (into OCI Vault) Cloudflare Email Sending token + account ID for ts-auth email sign-in (create with `cf`, user-approved); Stripe secret + webhook keys for ts-dashboard (test-mode keys are fine).

### W1 Build green on consolidated main — DONE by the consolidation thread

### W2 Single-host SwarmKit node (ts-orchestrator)
- Owns: `internal/swarmruntime/single.go` (new), `internal/app/single_host.go` (new)
- Input: `swarmruntime.StartNode` founder path; executor from `runtime_worker_start.go`.
- Do: `ts-orch single-host --state /var/lib/ts-orch` starts manager (Active) + worker + containerd executor in one process, plus a local control socket. No OCI, Vault, NetBird, NATS, admission.
- Done = on mariogk-dev with containerd running, the process starts, `ts-orch service ls` over the socket returns an empty list, restart keeps Raft state.
- ~5 h. Deps: W1.

### W3 Service spec and `ts-orch service apply|ls|rm` (ts-orchestrator)
- Owns: `internal/swarmruntime/service.go`, `internal/app/platform_service.go`, `internal/app/service_cli.go` (new), `deploy/m1/services/*.json` (new)
- Spec JSON: `name, image (must be @sha256), env{}, secrets[] (names only; resolved by W11), mounts[{source,target}], port, readyPath, replicas(=1)`. Remove the TerraBase refusal and ts-auth-only port rule.
- Done = `ts-orch service apply -f deploy/m1/services/whoami.json` on mariogk-dev runs a public test image to `1/1`; `ls` shows digest; `rm` stops it.
- ~5 h. Deps: W1; integrates with W2 (socket) and W4 (spec fields).

### W4 Executor: mounts, readiness path (ts-orchestrator)
- Owns: `internal/swarmruntime/spec.go`, `controller.go`, `readiness.go`
- Do: bind mounts (source must be under `/var/lib/ts-data/`), readiness HTTP path per service (default `/readyz`), container user stays non-root but data dir is chowned to it.
- Done = real-containerd integration test (CI job with containerd) writes to a mount, restarts, reads it back; a `/healthz`-only image becomes ready.
- ~4 h. Deps: W1.

### W5 Built-in HTTPS edge (ts-orchestrator)
- Owns: `internal/edge/**` (new)
- Do: `:80` (ACME HTTP-01 + redirect) and `:443` with autocert, host -> `127.0.0.1:<port>` map taken from service specs (`hostnames` field), cert cache in the state dir, websocket/SSE pass-through.
- Done = integration test with a Pebble ACME server issues a cert and proxies to a test backend.
- ~4 h. Deps: none (pure package); wired by W6.

### W6 Wiring + M1 runbook (ts-orchestrator) — integrator
- Owns: `internal/cli/cli.go`, `internal/app/app.go`, `docs/m1-runbook.md` (new)
- Do: register `single-host` and `service` commands, start the edge inside `single-host`.
- Done = one binary from CI release runs W2+W3+W4+W5 together on mariogk-dev with the three M1 specs pointed at test images.
- ~2 h. Deps: W2-W5.

### W7 Install ts-orch on the gru host (ts-orchestrator, new files only)
- Host (ready, 2026-10-21): `ssh ts-gru-1` = `gru-1-ctl-1`, A1.Flex 4 OCPU / 24 GB, Ubuntu 24.04 aarch64, public IP 163.176.124.12, compartment `gru-1-control`, containerd 2.2.1 + runc 1.3.4 running, 80/443 open to the world, 22 from 179.124.206.245/32. Facts: delta `.cos/briefs/orch-20261021/oci-gru-host.md`.
- Owns: `deploy/m1/install.sh`, `deploy/m1/ts-orch.service` (new)
- Do: `install.sh <release-url> <sha256>` over ssh: fetch the ts-orch arm64 binary, verify sha256, install to `/usr/local/bin/terrascale-orchestrator`, create `/var/lib/ts-orch` and `/var/lib/ts-data/terrabase`, enable `ts-orch.service` (`ts-orch single-host`). Idempotent; re-run = upgrade.
- Done = `ssh ts-gru-1 systemctl is-active ts-orch` = active with a W6 build. Script can merge before W6.
- ~1.5 h. Deps: W6 for the live run. No paid capacity.

### W8 TerraBase + ts-auth multi-arch images on GHCR (terrascale)
- Owns: `Dockerfile`, `.github/workflows/images-ghcr.yml` (new)
- Do: build `terrabase` and `ts-auth` targets for linux/amd64 + linux/arm64 (`TARGETARCH` -> `linux-x64`/`linux-arm64` RID), push to public `ghcr.io/terrascale/terrabase` and `ghcr.io/terrascale/ts-auth` on main; print digests in the job summary. ts-dotnet is public now: clone it without the deploy key.
- Done = `docker manifest inspect ghcr.io/terrascale/ts-auth@sha256:...` lists arm64, anonymous pull works.
- ~3 h. Deps: none.

### W9 TerraBase + ts-auth run off Fly in Production (terrascale)
- Owns: `src/TerraScale.Authentication/App.cs` and its settings file, TerraBase Fly-detection/listener files under `src/TerraBase/Hosting/`
- Do: setting `TS_AUTH_TERRABASE_URL` (used when set, any environment); TerraBase without `FLY_*` runs Production with internal 8081 on loopback and issuer from `TERRABASE_TOKEN_ISSUER` (default `https://auth.terrascale.tech/terrascale`). No Fly DNS peer discovery when `FLY_APP_NAME` is unset.
- Done = CI integration test starts both binaries without `FLY_*` in Production and ts-auth `/healthz` = 200 against TerraBase on 127.0.0.1:8081.
- ~4 h. Deps: none. Not a Fly-mode toggle: it is a URL setting.

### W10 ts-dashboard off Fly + multi-arch GHCR image (ts-dashboard)
- Owns: `Dockerfile`, `.github/workflows/images-ghcr.yml` (new), the TerraBase/ts-auth address config file(s)
- Do: `TS_DASHBOARD_TERRABASE_URL` setting, listen URL from `ASPNETCORE_URLS` (M1 uses `http://127.0.0.1:8085`), amd64 + arm64 image to public `ghcr.io/terrascale/ts-dashboard`.
- Done = image digest published with arm64; CI test boots it in Production with the URL setting.
- ~4 h. Deps: none.

### W11 Secrets via OCI Vault — owned by 'OCI Vault thread' — CRED
- Owns: OCI Vault infra for gru, `internal/rootsecret/**`, `internal/vaultsecret/**`, `internal/swarmruntime/container_material.go`, `internal/app/container_material.go`, and any other secret-injection path in ts-orch
- Do: create the gru vault + keys; store `TERRABASE_PEER_SECRET`, `TERRABASE_MASTER_KEY`, `TS_AUTH_MASTER_KEY`, `TS_AUTH_AUDIT_SIGNING_KEY`, `TS_AUTH_DASHBOARD_CLIENT_SECRET`, `TS_DASHBOARD_SESSION_ENCRYPTION_KEY` (generated, never printed) and the user-supplied `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_EMAIL_TOKEN`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`; inject the names listed in a W3 spec's `secrets[]` into the task env at start, from the VM's instance principal.
- Done = on the gru VM each service's container sees every required name (checked by name only, never value).
- Deps: W7 (VM + instance principal), W3 spec field.

### W12 DNS + go-live proof
- Owns: no repo files except appending results to `docs/m1-runbook.md` after W6 merges (hand-off from W6)
- Do: `env -u CLOUDFLARE_API_TOKEN cf` A records `api`, `auth`, `dash` -> VM IP, DNS-only; apply the three M1 specs with the W8/W10 digests; ts-auth redirect URIs for `https://dash.terrascale.tech`.
- Done = every row of "Milestone 1: Done =" passes; outputs pasted into the runbook.
- ~2 h. Deps: W6-W11.

### N1 NetBird server + clients managed by ts-orch (ts-orchestrator)
- Owns: `internal/netbird/**`
- Do: ts-orch runs and recovers the NetBird management/signal/relay server on ts-gru-1 (as a SwarmKit service or managed unit) and enrolls clients: ts-gru-1 itself plus the operator hosts (delta, mariogk-dev, beta). Setup keys come from OCI Vault (W11).
- Done = `ssh ts-gru-1 netbird status` = Connected to the ts-orch-run management; `netbird status` on delta lists ts-gru-1 as a connected peer; restarting ts-orch keeps both.
- ~6 h. Deps: W2 (single-host), W11 (setup-key secret). User decision 2026-10-21.

### N2 ts-orch-owned OCI networking for gru (ts-orchestrator)
- Owns: `internal/ociregion/foundation/**` (VCN, subnet, IGW, route table, security list, NSGs)
- Do: ts-orch adopts and reconciles the existing `gru-1-vcn` 10.251.0.0/24, public `gru-1-host-subnet` 10.251.0.0/25, `gru-1-igw`, `gru-1-host-sl` (22 from 179.124.206.245/32, 80/443 world) and adds the NetBird ports N1 needs; no recreation.
- Done = `ts-orch oci-region foundation --plan <gru> --apply` on mariogk-dev changes nothing on the second run, and the live rules match; ts-gru-1 stays reachable throughout.
- ~5 h. Deps: none to start. User decision 2026-10-21.

### W13 Repo rules allow milestone 1 — DONE, no edit
- `AGENTS.md` (and the `CLAUDE.md` symlink) is human-only ("AI IS NOT ALLOWED TO EDIT THIS FILE").
- DECISION: no change. Reason: the current rules already fit M1: NetBird membership (N1), OCI Vault secrets (W11), zero configuration (`single-host` is a command, not a switch). The 3-controller requirement lives in code, not in the rules.

## Later (not milestone 1)

- 3-controller cells, HA, sjc + fra, regional joining, global fabric, NATS federation.
- OCI LB + Cloudflare Origin CA ingress.
- Admission; OCI custom image pipeline (`image.yml`, `image promote`).
- Adopting ts-gru-1 as a managed controller (image allow-list in `internal/oci/static_host.go`, `terrascale-host-enrollment-v1` metadata).
- Full OCI lifecycle ownership beyond gru networking (`oci-region attempt`, instances, volumes), autoscaling, capacity.
- Delete the old scheduler path (`machines`, `placement`, `rollout`, `rolloutexec`, `workload`, `operator deploy`) once M1 runs only on SwarmKit.
- Customer Wasm functions (Wasmtime vs wazero), mixed arm64/amd64 workloads.
- ts-orch dashboard on SwarmKit data only; cluster CLI parity.
- Signed releases, regional channels, self-update, production qualification gates.
- Integration-only test migration, unit-test deletion, cost studies, evidence ledgers.
- Restore old data from Fly snapshots (if they still exist; retention ends ~2026-12-11).
- TerraBase backup to Tigris/S3.
