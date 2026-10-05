# ts-auth deployment on gru-1

Status: **implemented in source and tested locally with fake OCI Vault,
the real TerraBase release and fake replicas; not run on OCI.** ts-auth (repository
`TerraScale/ts-auth`, C# .NET 10) runs as a native single-file workload of
role `ts-auth` on the gru-1 controllers and is served publicly at
`https://gru.auth.terrascale.tech` through the OCI L7 load balancer `gru-1-api`
(TS-486). Package
[`internal/tsauth`](../internal/tsauth) holds the contract, the Vault secrets,
the TerraBase tenant bootstrap and the `ts-orch ts-auth` command; the host
side is [`internal/host/tsauth.go`](../internal/host/tsauth.go).

| Command | Where | Effect |
| --- | --- | --- |
| `ts-orch ts-auth secrets --plan FILE` | operator host, `~/.oci/config` | Generates `TS_AUTH_MASTER_KEY`, `TS_AUTH_AUDIT_SIGNING_KEY`, `TS_AUTH_OPERATOR_KEY` and `TS_AUTH_DASHBOARD_CLIENT_SECRET` once into the cell's Vault. |
| `ts-orch ouroboros bootstrap --plan FILE --client-url URL --admin-url URL --member NODE --member-ca FILE --dashboard-credential-file FILE [--management-listener client\|admin] [--owner-email EMAIL --ts-auth-instance SLUG --ts-auth-key-file FILE [--ts-auth-url URL]]` | operator host, SSH forward to `gru-1-db-1` | Finds or creates TerraScale's TerraBase organization and the ts-auth and ts-dashboard projects and databases; stores each project ID and, once, a new API key in the Vault. With `--owner-email` (needs `--management-listener admin`), makes that ts-auth user the organization's owner. |
| `ts-orch ouroboros fly-secrets --plan FILE` | operator host, `~/.oci/config` | Hands the dashboard's TerraBase settings to Fly app `ts-dashboard`: stages them with `FLY_API_TOKEN`, otherwise prints the non-secret ones. |
| `ts-orch ts-auth env-file --host-config FILE --vault-id OCID` | each controller, as root | Reads the six secrets with the instance principal and writes `<ts_auth_root>/ts-auth.env`, mode 0600, owned by the workload user. |
| `ts-orch ts-auth metadata-rules` | operator host, no OCI access | Renders the nftables metadata block installed on each controller in step 3. |
| `ts-orch service add --role ts-auth --profile F --spec F --out F`, `release sign-service-set`, `service apply` | operator host | Adds ts-auth to a running cell with a signed service set; see [services](services.md). |
| `ts-orch bootstrap render-controller-config ... --ts-auth-profile F --ts-auth-profile-sha256 H --ts-auth-service F --ts-auth-service-sha256 H --out F` | operator host, before initial controller signing | Includes the reviewed ts-auth profile and service in canonical signed controller configuration. |
| `ts-orch operator ts-auth-release --config FILE --binary F --sha256 F --source-checkout DIR --commit SHA --environment ENV --profile F [--wait 10m]` | operator host | Verifies, admits and rolls out one release; gates on readiness and rolls back a release that fails. |

On cell hosts the installed binary is `terrascale-orchestrator`; it exposes
the same commands. No command prints a secret: they print secret names,
OCIDs, tenant IDs and digests.

## Placement: two stateless replicas on the controllers

ts-auth is **stateless**: users, sessions, keys, claims, webhook deliveries
and audit events live in its TerraBase database, and every replica serves
any request ("regional ts-auth processes share one database", ts-auth
README). Its only process state is a two-second readiness cache. So it runs
as a `stateless` service with **2 replicas**, at most one per failure domain,
on two of `gru-1-ctl-1`, `-2` and `-3`:

- Two replicas survive the loss of one controller or fault domain; the load
  balancer sends traffic only to replicas whose `/readyz` answers.
- The workload reconciler owns the role (`controller.autoscale.services`), so
  it replaces a replica lost with its controller on the third controller.
- The `db` hosts stay dedicated to TerraBase members. Three replicas would
  put one beside every controller process on the 1 OCPU / 6 GB controllers
  without adding a failure domain.

If ts-auth ever keeps state in process (for example a local rate limiter
that must be exact), this decision becomes 1 replica.

## Runtime contract

### Release

ts-auth CI publishes `ts-auth-linux-arm64` and `ts-auth-linux-arm64.sha256`
(TS-488). `tsauth.VerifyRelease` checks them like a TerraBase release: the
asset name (`ts-auth-linux-amd64` or `-arm64`), ELF magic, at most 512 MiB,
and the single `sha256sum` line; that digest is admitted and pinned. The
source claim is `https://git.terrascale.tech/TerraScale/ts-auth`, the commit
and the SHA-256 of `git archive --format=tar <commit>`.

### Signed configuration

Two committed files go into the signed controller config:

- [`deploy/oci-region/ts-auth-gru-1-profile.json`](../deploy/oci-region/ts-auth-gru-1-profile.json)
  is `controller.workloads["ts-auth"]` and the `--profile` of the release.
- [`deploy/oci-region/ts-auth-gru-1-service.json`](../deploy/oci-region/ts-auth-gru-1-service.json)
  is one entry of `controller.autoscale.services` (`enabled: true`). Its
  `environment` (`canary`) must equal the controller hosts' registration.

The profile is readable wherever desired state is, so it holds no secret. The
controller refuses to start, and the release command refuses to run, when it
breaks these rules:

| Key | Rule |
| --- | --- |
| `TS_AUTH_PUBLIC_ORIGIN` | Exactly `https://gru.auth.terrascale.tech`, the regional host (user decision 2026-10-05; `auth.terrascale.tech` stays the ts-atlas proxy). |
| `TS_AUTH_TERRASCALE_API_URL` | Exactly `https://gru.api.terrascale.tech`. |
| `TS_AUTH_DATABASE` | Exactly `auth`, the database `ouroboros bootstrap` creates. The host passes ts-auth `<project-uuid>/auth`, the project from the env file. |
| `TS_AUTH_ACCESS_TOKEN_AUDIENCES` | Exactly `https://gru.api.terrascale.tech`, TerraBase's `auth-audience`: every access token names it, so a dashboard user's token reaches TerraBase's Management API (TS-519). |
| `TS_AUTH_DASHBOARD_REDIRECT_URIS` | Exactly `https://dash.terrascale.tech/login/callback`, the dashboard's callback. |
| `TS_AUTH_DASHBOARD_POST_LOGOUT_REDIRECT_URIS` | Exactly `https://dash.terrascale.tech/login`, the `post_logout_redirect_uri` the dashboard sends; ts-auth compares it exactly. |
| Env file keys, `TS_AUTH_LISTEN`, `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | Must not be set. |
| `TS_AUTH_SMTP_PASSWORD`, `TS_AUTH_STRIPE_SECRET_KEY`, `TS_AUTH_STRIPE_WEBHOOK_SECRET`, `TS_AUTH_SENTRY_DSN`, `TS_AUTH_AUDIT_VERIFY_KEYS`, `TS_AUTH_SERVICE_CLIENTS`, `OTEL_EXPORTER_OTLP_HEADERS` | Must not be set: they are secrets, and the env file does not carry them yet. Non-secret optional settings (SMTP host, OTEL endpoint) may be added. |
| `args` | Must be empty: an argument overrides any setting. |

### Secrets and the env file

| Env file key | Source | Vault secret |
| --- | --- | --- |
| `TS_AUTH_MASTER_KEY` | `ts-auth secrets`: 32 random bytes, base64 | `gru-1-ts-auth-master-key` |
| `TS_AUTH_AUDIT_SIGNING_KEY` | `ts-auth secrets` | `gru-1-ts-auth-audit-signing-key` |
| `TS_AUTH_OPERATOR_KEY` | `ts-auth secrets` | `gru-1-ts-auth-operator-key` |
| `TS_AUTH_DASHBOARD_CLIENT_SECRET` | `ts-auth secrets` | `gru-1-ts-auth-dashboard-client-secret` |
| `TS_AUTH_TERRASCALE_API_KEY` | `ouroboros bootstrap`: TerraBase `POST /admin/api-keys` | `gru-1-ts-auth-terrascale-api-key` |
| `TS_AUTH_TERRASCALE_PROJECT_ID` | `ouroboros bootstrap`: the project the key is narrowed to | `gru-1-ts-auth-terrascale-project-id` |

The project ID is not secret; it travels with the API key because the key
reaches only that project's database. The host joins it to the profile's
database as `TS_AUTH_DATABASE=<project-uuid>/auth`, the selector ts-auth
reads, and does not pass `TS_AUTH_TERRASCALE_PROJECT_ID` itself.

### OpenID Connect

ts-auth (ts-auth#36) serves one issuer, `https://gru.auth.terrascale.tech/terrascale`,
with discovery at `https://gru.auth.terrascale.tech/terrascale/.well-known/openid-configuration`.
At startup it registers the confidential client `ts-dashboard` from
`TS_AUTH_DASHBOARD_CLIENT_SECRET` and the two profile URIs above.
`ouroboros fly-secrets` hands the dashboard the matching `TS_AUTH_ISSUER`,
`TS_AUTH_CLIENT_ID`, `TS_AUTH_REDIRECT_URL` and `TS_AUTH_CLIENT_SECRET`.

- Every secret lives in the gru-1 Vault (phase 1) in the control
  compartment, read from the plan's `resource_ids` (`control_compartment`,
  `vault`, `key`).
- A secret is created only when the Vault holds no active secret of its name,
  with an OCI retry token. A rerun never regenerates, replaces or rotates
  one. A secret of that name in another state (for example pending deletion)
  stops the command for inspection. Rotating `TS_AUTH_MASTER_KEY` would make
  stored secrets unreadable and is not supported.
- The controllers read them with their instance principal through the
  existing controller policy grant `read secret-bundles` in the control
  compartment, which covers `GetSecretBundleByName`.
- `env-file` rejects a ts-auth root equal to, inside, or containing the
  install, state or TerraBase root before reading Vault secrets or changing
  directory permissions. It writes `KEY=VALUE` lines atomically (temporary file, fsync,
  rename). The host agent reads the file at every launch: a regular file, not
  a symlink, mode 0600, owned by the workload user; otherwise it refuses to
  launch. Errors name keys and line numbers, never values. Secrets never enter
  signed config, desired state, reports or logs. A running replica keeps its
  environment until it restarts.

### Host layout and launch

Set `"ts_auth_root": "/srv/ts-managed/ts-auth"` in the controller host's
`host.json` (`host` section). It is validated like `terrabase_root`
(separate from the install, state and TerraBase roots, no replaceable or
symlinked ancestor) and kept across host credential renewal. It lives inside
the managed runtime tree `/srv/ts-managed`, which the host service can write.

| Path | Owner, mode | Content |
| --- | --- | --- |
| `<root>` | supervisor, workload group, 0750 | |
| `<root>/ts-auth.env` | workload user, 0600 | The six secrets |
| `<root>/bundle` | workload user, 0700 | Extracted native libraries |

The replica's environment is the host base environment, the profile, the env
file, then `TS_AUTH_LISTEN=http://0.0.0.0:8080` and
`DOTNET_BUNDLE_EXTRACT_BASE_DIR=<root>/bundle`. It runs as the workload user
in its own cgroup under the host agent.

### Instance metadata firewall

COS chose to block ts-auth's metadata access on 2026-10-05. The
`metadata-rules` command renders a dedicated nftables `inet` table with an
output hook at priority 0, after destination NAT. COS approved metadata access
for root and `terrascale-orchestrator`, the controller service account, so its
OCI autoscaling client retains its instance principal. All other users,
including ts-auth and its descendants, are blocked. Native workloads cannot
assume those host UIDs or modify the firewall. `systemd-timesync` also retains
UDP/123 to the same address, OCI's NTP server; that exception grants no HTTP
metadata access and gives ts-auth no exception.

The rule applies to existing connections as well as new ones. Reloading
atomically replaces only `terrascale_metadata`, leaving NetBird and other
firewall tables intact. A root oneshot unit loads it before the host service:
enabling the unit adds a required dependency, so a missing nft executable,
missing controller/timesync account or rejected ruleset prevents host startup. It
returns inactive after loading, so every host start (including after reboot)
reloads the rules. Stopping the unit leaves the rule installed.
Start ts-auth through that host service; a manually started agent bypasses
the systemd dependency. Do not flush the global nftables ruleset.

### Health, readiness and drain

On launch the host reports the replica `starting`. On every poll it calls
`GET http://127.0.0.1:8080/healthz` (`{"status":"ok"}`, alive) and then
`/readyz` (`{"status":"ready"}`, TerraBase answered) and reports `running`
only when both answer 200; otherwise `starting` with the failing path. A
replica whose process exits is reported `failed` once and relaunched on the
next poll. Stop sends SIGTERM and waits 45 s (ASP.NET Core drains for 30 s)
before the cgroup is killed.

### Load balancer

`gru.auth.terrascale.tech` is a proxied Cloudflare record for the OCI L7 load
balancer `gru-1-api` in the public API subnet (`10.251.0.128/26`), which
TS-486 creates. TLS ends at the load balancer with a Cloudflare Origin CA
certificate; a hostname rule sends `gru.auth.terrascale.tech` to the ts-auth
backend set over plain HTTP. These are the values it consumes,
`tsauth.BackendSet(plan)`:

| Value | gru-1 | Source |
| --- | --- | --- |
| Hostname | `gru.auth.terrascale.tech` | `tsauth.Hostname` |
| Backends | `10.251.0.11`, `10.251.0.12`, `10.251.0.13` | every controller `private_ip` in `plan.json`: a replica may run on any of them |
| Port | `8080` | `tsauth.Port` = `ociregion.TSAuthPort` |
| Health check | HTTP `GET /readyz`, 200, body `{"status":"ready"}` | `tsauth.ReadyPath` |

The controller without a replica, and a replica whose TerraBase is
unreachable, fail the health check and get no traffic. The cell plan admits
the load balancer: `network_security.nsg_rules` (controller NSG) has TCP 8080
from `10.251.0.128/26`, and the plan validator accepts the public API subnet
on the controllers for exactly that port (`TestPublicSubnetReachesControllersOnlyOnTSAuthPort`).
TS-486 adds the public security list egress to `10.251.0.0/25` TCP 8080.
Cloudflare closes a request after 100 s and the load balancer idles out after
120 s, so no ts-auth request may hold a connection longer than 100 s.

### Release gate

`operator ts-auth-release` is `operator terrabase-release` for role
`ts-auth` (see [TerraBase deployment](terrabase-deployment.md#run) for the
steps, interrupt handling and rollback). It waits for 2 replicas that report
the new digest `running`; a `failed` replica fails the gate at once, and a
failed release is rolled back to the digest the replicas ran before. The
reconciler owns the role, so the hosts get release-scoped generations
(`intent << 24`); the command computes the next release from them and gates
on `generation >> 24`.

## TerraBase tenant (ouroboros)

TerraScale runs on its own product (TS-529, "ouroboros"). ts-auth and the
dashboard keep their data in the production TerraBase, the same release end
users reach at `https://gru.api.terrascale.tech`, as ordinary tenants: there
is no private TerraBase instance. `tsauth.Projects` is the table.

| Object | Name | How |
| --- | --- | --- |
| Organization | `terrascale`, owner `ts-orchestrator` until phase B, then the person | Management API on the member's client listener (9465), or from TerraBase TS-519 its loopback admin listener (9464) |
| Project, database | `ts-auth`, `auth` (`TS_AUTH_DATABASE`) | Management API |
| Project, database | `ts-dashboard`, `dashboard` | Management API |
| API keys | one per project, scopes `documents:read`, `documents:write`, narrowed to that project's organization, project and database | `POST /admin/api-keys` on the member's loopback admin listener (9464) |

| Vault secret | Content |
| --- | --- |
| `gru-1-ts-auth-terrascale-project-id` | ts-auth's project ID |
| `gru-1-ts-auth-terrascale-api-key` | ts-auth's key (what `ts-auth env-file` reads) |
| `gru-1-ts-dashboard-terrabase-project-id` | the dashboard's project ID |
| `gru-1-ts-dashboard-terrabase-api-key` | the dashboard's key |

The names are stable: `<cell>-<key lowercased, _ replaced by ->`.

### Phase A: tenants and keys (always)

`ouroboros bootstrap` acts as the fixed service identity `ts-orchestrator`
(header `X-TerraBase-User-Id: ts-orchestrator`, with the member's Management
service credential). The Management API needs that credential
(`TERRABASE_MANAGEMENT_CREDENTIAL_FILE` from TerraBase TS-519 on, before it
`TERRABASE_DASHBOARD_CREDENTIAL_FILE`); without one it answers 401 and the
command stops. Phase B refuses to add a member once another user owns the
organization, so a rerun with a different address changes nothing. The creator of an organization becomes its first owner, so a
new organization is owned by `ts-orchestrator`. The command reaches both
listeners through an SSH forward to `gru-1-db-1`, trusts the cell's member CA
and checks the member certificate names `--member`.

Each object is created only when the acting user has none of that name; two
of one name stop the command. Per project, the command stores the project ID
in the Vault, reads it back and compares it with the tenant's project before
any key is issued. A key is issued only when the Vault holds none for that
project; the stored key must then list its own database's collections, so a
stale Vault entry (for example after a TerraBase reset) stops the command
instead of passing. TerraBase has no key revocation yet: a key issued while
the Vault write then fails stays unused, and the rerun issues one more. Each
TerraBase request times out after 30 s.

Both phases reach the member's loopback listeners through the SSH or NetBird
forward to `gru-1-db-1` (or run on that host), never the public
`gru.api.terrascale.tech`. From TerraBase TS-519 (terrabase PR #24) the
public Management API accepts only ts-auth access tokens, and the Management
service credential works only on the loopback admin listener. Against such a
release pass `--management-listener admin`: every Management request of both
phases then goes to `--admin-url` (the same `/v1/management/...` routes, with
the credential and `X-TerraBase-User-Id`). The default, `client`, serves the
releases before TS-519, which answer Management only on the client listener.
Data-plane requests (the key check) always use the client listener.

It prints one line per project, `{"tenant":{"organization_id","project",
"project_id","database_id","database"},"secrets":[{"key","secret","id",
"created"},...]}`, never a secret value.

The admin listener is loopback-only, so both APIs are reached on one member,
`gru-1-db-1`, through the forward. **Open (TerraBase TS-464):** until
replication exists each member is an independent database, so the tenants and
keys exist only on `gru-1-db-1`, while `gru.api.terrascale.tech` balances over
every member. ts-auth and the dashboard work only once replication carries
the tenants to every member, or while the API's backend set holds
`gru-1-db-1` alone.

### Phase B: ownership (with `--owner-email`)

Phase B needs `--management-listener admin` and a TerraBase release with
TS-535: it adds the person as a member with the admin-listener-only
`PUT /v1/management/organizations/{organization}/members/{user}` and
`{email}`. The credential carries no verified email, so it cannot accept an
invitation (TS-519). Without `--management-listener admin` the command stops
before phase A.

Run it once ts-auth is live and the person has signed in once (for example
on the dashboard). The command resolves the address through ts-auth's
Management API, `GET {ts-auth-url}/v1/{instance}/users?limit=100&starting_after=ID`
(`--ts-auth-url` defaults to `https://gru.auth.terrascale.tech`), with the
instance's `sk_` management key from an owner-only file. This needs the
management users API (the `/v1/{slug}/users` contract, TS-490 and later) to be
served.

- No user has that email: it stops with `ts-auth instance S has no user E
  yet: sign in once with that address (for example on the dashboard), then
  rerun`.
- The user must have a verified email and be neither banned nor anonymous;
  two users of that email are refused.

Then, only for the steps still undone:

1. Add the user as a member, acting as `ts-orchestrator`. TerraBase records
   the address only in the audit event `member.added`.
2. Start the ownership transfer to the user (as `ts-orchestrator`) and
   confirm it acting as the user. Confirming demotes `ts-orchestrator` to
   member.
3. Make `ts-orchestrator` admin again, acting as the new owner.

`ts-orchestrator` is never removed. The command prints
`{"organization_id","owner","admin":"ts-orchestrator","steps":[...]}`; a rerun
prints `"steps":[]`. Phase A reruns still work afterwards: an admin may list
and create projects and databases.

## gru-1 live runbook

**Prepared, not executed. Requires human confirmation before every step that
changes the cell, the Vault or TerraBase.** Blast radius: one controller NSG
rule, the gru-1 Vault (four generated keys, then four from bootstrap), the
production TerraBase on `gru-1-db-1` (one organization, two projects, two
databases and two API keys, and with phase B its ownership), the Fly app
`ts-dashboard` (eight staged secrets) and the three controllers (`host.json`,
one env file each, one ts-auth replica on two of them).

### Prerequisites

1. **Phase 1.** `deploy/oci-region/plan.json` `resource_ids` names the live
   `control_compartment`, `vault` and `key` (TS-470).
2. **TerraBase.** `gru-1-db-1` serves a C# TerraBase release with TS-535 or
   later ([TerraBase deployment](terrabase-deployment.md)) with
   `TERRABASE_CLIENT_PORT=9465`, `TERRABASE_REGION` (required outside
   Development) and a Management service credential:
   `TERRABASE_MANAGEMENT_CREDENTIAL_FILE` names a file of at least 32
   characters that the workload user can read. TS-519 removed
   `TERRABASE_DASHBOARD_CREDENTIAL_FILE`, and TerraBase ignores it, so a
   member with only that variable answers every bootstrap call with 401. **Open:** the committed
   [`terrabase-gru-1-profile.json`](../deploy/oci-region/terrabase-gru-1-profile.json)
   does not set it yet; TS-470 adds it with the TerraBase deployment.
3. **Controller hosts.** Each controller VM's own host agent enrolls itself
   once the cell has a `ts-auth` profile (signed config or service set). At
   boot, and on its 12-hour timer, `host-setup` finds no host descriptor but
   finds the controller's launch slot (`terrascale-bootstrap`). It enrolls as
   that controller's server name (`gru-1-ctl-N`, static descriptor) with the
   public bundle every controller already carries. The controller accepts it
   only from one of the signed controller addresses (its broker host and NATS
   routes) when OCI shows the running instance of that name holding the
   address. The registration has role `ts-auth`, environment from the placement
   config, the instance's fault domain, and the `ts-auth` profile's `resources`
   as capacity (one replica). `host.json` gets `ts_auth_root`
   `/srv/ts-managed/ts-auth` and the agent's observability listener on
   `127.0.0.1:9466`, next to the controller's. The host agent starts right
   after enrollment, so install the metadata firewall in step 3 before the
   first ts-auth release.
4. **Load balancer.** TS-486 is merged and applied: `gru-1-api` with the
   ts-auth backend set and hostname rule, its Origin CA certificate and the
   proxied DNS record for `gru.auth.terrascale.tech`. Step 0 opens the controller
   NSG to it.
5. **Release.** A ts-auth release with `ts-auth-linux-arm64` and its
   `.sha256` (TS-488).
6. **Operator grant.** The operator's signer grant lists role `ts-auth`,
   environment `canary` and repository
   `https://git.terrascale.tech/TerraScale/ts-auth`.
7. **Operator OCI access.** The operator's `~/.oci/config` DEFAULT profile
   may list, create and read secrets (`manage secret-family`) in the control
   compartment, use the Vault key (`use keys`) and, for step 0, manage the
   controller NSG's rules; `ts-orch` sends no other OCI request in steps 1
   and 2.
8. **Instance metadata blocked.** Step 3 installs the nftables rule and its
   boot dependency on every controller before the host is restarted. Each
   host must provide `/usr/sbin/nft` (Ubuntu package `nftables`) and the
   `systemd-timesync` and `terrascale-orchestrator` accounts. nft resolves the
   account names to the actual host UIDs when loading the rule.

### Before initial controller bootstrap

A running cell gets ts-auth with a signed service set: follow
[Add a service to a running region](services.md#add-a-service-to-a-running-region)
with the two committed files below. Never edit an accepted controller's
installed JSON or delete its acceptance marker: the installer is write-once,
and restart admission binds the config digest to the accepted manifest.

A new region can instead start with ts-auth in its initial controller config.
`ts-orch oci-region attempt` does so when its `attempt.json` names both files:

```json
"ts_auth_profile": "/ABSOLUTE/PATH/deploy/oci-region/ts-auth-gru-1-profile.json",
"ts_auth_service": "/ABSOLUTE/PATH/deploy/oci-region/ts-auth-gru-1-service.json"
```

It passes them, with their SHA-256 pins, to `render-controller-config` for
every controller slot, and refuses one without the other. Its `services`
phase adds services through signed service sets instead. Run by hand, the
renderer takes them as follows.

For each controller slot, use the reviewed candidate, material record,
operator grant and three sidecars from
[production role configuration](production-role-config.md). Set the variables
below to their reviewed paths and SHA-256 pins, choose a new
`CONTROLLER_CONFIG` output path, and use the reviewed TerraBase profile with
the dashboard credential setting described above:

```sh
REPO=$PWD
ts-orch bootstrap render-controller-config \
  --candidate "$CANDIDATE" --candidate-sha256 "$CANDIDATE_SHA256" \
  --material-record "$MATERIAL_RECORD" --material-record-sha256 "$MATERIAL_RECORD_SHA256" \
  --operator-grant "$OPERATOR_GRANT" --operator-grant-sha256 "$OPERATOR_GRANT_SHA256" \
  --oci-region-intent "$REGION_INTENT" --oci-region-intent-sha256 "$REGION_INTENT_SHA256" \
  --oci-region-config "$REGION_CONFIG" --oci-region-config-sha256 "$REGION_CONFIG_SHA256" \
  --placement-config "$PLACEMENT_CONFIG" --placement-config-sha256 "$PLACEMENT_CONFIG_SHA256" \
  --terrabase-profile "$TERRABASE_PROFILE" --terrabase-profile-sha256 "$TERRABASE_PROFILE_SHA256" \
  --ts-auth-profile "$REPO/deploy/oci-region/ts-auth-gru-1-profile.json" --ts-auth-profile-sha256 "$TS_AUTH_PROFILE_SHA256" \
  --ts-auth-service "$REPO/deploy/oci-region/ts-auth-gru-1-service.json" --ts-auth-service-sha256 "$TS_AUTH_SERVICE_SHA256" \
  --out "$CONTROLLER_CONFIG"
sha256sum "$CONTROLLER_CONFIG"
```

The renderer emits canonical `app.Config` bytes and validates both workload
profiles and the service. Review the printed digest, then pass the output as
`--controller-config` and that digest as `--controller-config-sha256` to the
initial `ts-orch bootstrap sign-manifest` invocation, with the same candidate
and sidecars. Follow the regional bootstrap runbook to launch the controllers.
Keep these exact bytes intact; a `jq` rewrite would fail canonical validation.

### Steps after bootstrap

```sh
# On the operator host, as the operator user whose ~/.oci/config DEFAULT
# profile may manage secrets in the gru-1 Vault, in a ts-orchestrator checkout
# of the deployed revision.
REPO=$PWD
PLAN=$REPO/deploy/oci-region/plan.json
VAULT=$(jq -er .resource_ids.vault "$PLAN")
NSG=$(jq -er .resource_ids.network_security_group "$PLAN")
CRED=<path that TERRABASE_MANAGEMENT_CREDENTIAL_FILE names on gru-1-db-1>
WORK=$(mktemp -d)
```

0. Open the controller NSG to the load balancer subnet unless phase 1
   already created the rule from `plan.json`:

   ```sh
   oci network nsg rules list --nsg-id "$NSG" --all |
     jq -e '.data[] | select(.source == "10.251.0.128/26" and ."tcp-options"."destination-port-range".min == 8080)' ||
   oci network nsg rules add --nsg-id "$NSG" --security-rules '[{"direction":"INGRESS","protocol":"6",
     "source":"10.251.0.128/26","sourceType":"CIDR_BLOCK","isStateless":false,
     "tcpOptions":{"destinationPortRange":{"min":8080,"max":8080}}}]'
   ```

1. Generate the four keys into the Vault. Expect four lines with
   `"created":true` (a rerun prints `"created":false`):

   ```sh
   terrascale-orchestrator ts-auth secrets --plan "$PLAN"
   ```

2. Bootstrap the TerraBase tenants on `gru-1-db-1`. Keep the forward open in a
   second terminal, copy the dashboard credential into an owner-only file,
   run the bootstrap, then delete the copy. If `gru-1-db-1` runs a TerraBase
   release with TS-519, add `--management-listener admin` (here and in the
   owner step below): only its loopback admin listener accepts the
   credential.
   Agents without a browser run each `netbird ssh ARGS` below as
   `ts-orch netbird ssh --vault-id "$VAULT" --netbird "$NB" -- ARGS` on the
   [operator automation peer](../deploy/netbird/README.md#operator-automation-peer).

   ```sh
   netbird ssh -L 19464:127.0.0.1:9464 -L 19465:127.0.0.1:9465 root@gru-1-db-1.nb.ts.internal   # terminal 2
   (umask 077; netbird ssh root@gru-1-db-1.nb.ts.internal cat "${CRED:?}" > "$WORK/dashboard-credential")
   sudo cat /var/lib/terrascale-operator/terrabase-ca-gru-1/member-ca.pem > "$WORK/member-ca.pem"   # public certificate
   terrascale-orchestrator ouroboros bootstrap --plan "$PLAN" \
     --client-url https://127.0.0.1:19465 --admin-url http://127.0.0.1:19464 --member gru-1-db-1 \
     --member-ca "$WORK/member-ca.pem" \
     --dashboard-credential-file "$WORK/dashboard-credential"
   shred -u "$WORK/dashboard-credential"
   ```

   Expect two lines `{"tenant":{...},"secrets":[...]}`, one for `ts-auth`
   (database `auth`) and one for `ts-dashboard` (database `dashboard`), both
   with organization `terrascale`'s IDs and both secrets `"created":true`. A
   rerun prints `"created":false` and issues no key.

3. On each controller, set the ts-auth root in `host.json` (edited on the
   operator host: the host image has no `jq`), make sure `/srv/ts-managed`
   exists before the host agent restarts (its unit can write there only if it
   exists at start), install the metadata firewall, write the env file and
   restart the agent:

   ```sh
   (
   terrascale-orchestrator ts-auth metadata-rules > "$WORK/ts-auth-metadata.nft" || exit 1
   for n in 1 2 3; do
     h=root@gru-1-ctl-$n.nb.ts.internal
     ssh "$h" cat /etc/terrascale-orchestrator/host.json > "$WORK/host-$n.json" &&
       jq -e '.host.ts_auth_root = "/srv/ts-managed/ts-auth"' "$WORK/host-$n.json" > "$WORK/host-$n.new" &&
       ssh "$h" 'umask 077 && cat > /etc/terrascale-orchestrator/host.json.new && test -s /etc/terrascale-orchestrator/host.json.new &&
         mv /etc/terrascale-orchestrator/host.json.new /etc/terrascale-orchestrator/host.json' < "$WORK/host-$n.new" &&
       ssh "$h" 'test -x /usr/sbin/nft && getent passwd systemd-timesync > /dev/null &&
         getent passwd terrascale-orchestrator > /dev/null &&
         if ! test -d /srv/ts-managed; then install -d -m 0755 /srv/ts-managed; fi' &&
       ssh "$h" 'install -o root -g root -m 0644 /dev/stdin /etc/terrascale-orchestrator/ts-auth-metadata.nft' < "$WORK/ts-auth-metadata.nft" &&
       ssh "$h" 'install -o root -g root -m 0644 /dev/stdin /etc/systemd/system/terrascale-ts-auth-metadata.service' \
         < "$REPO/deploy/systemd/terrascale-ts-auth-metadata.service" &&
       ssh "$h" 'systemctl daemon-reload && systemctl enable terrascale-ts-auth-metadata.service &&
         test -L /etc/systemd/system/terrascale-orchestrator-host.service.requires/terrascale-ts-auth-metadata.service' &&
       ssh "$h" terrascale-orchestrator ts-auth env-file --host-config /etc/terrascale-orchestrator/host.json --vault-id "$VAULT" &&
       ssh "$h" 'systemctl restart terrascale-orchestrator-host.service && /usr/sbin/nft list table inet terrascale_metadata' &&
       ssh "$h" stat -c "'%U %a %n'" /srv/ts-managed/ts-auth/ts-auth.env || { echo "gru-1-ctl-$n failed" >&2; exit 1; }
   done
   shred -u "$WORK"/host-*.json "$WORK"/host-*.new
   )
   ```

   `ssh` to a NetBird name uses NetBird SSH. Expect
   `{"env_file":"/srv/ts-managed/ts-auth/ts-auth.env","keys":[...]}` and
   `terrascale-workload 600 /srv/ts-managed/ts-auth/ts-auth.env` on each.
   The nft output must show the output hook, the timesync-only UDP/123
   exception and `ip daddr 169.254.169.254 meta skuid != { 0, "terrascale-orchestrator" } counter drop`
   (nft may print the controller's numeric UID).
   Enabling the firewall dependency does not start it. The env file is ready
   before restarting the host, which runs the rule transaction as a prerequisite.
   The subshell exits unsuccessfully at the first controller failure; it does
   not prepare any later controller or hide the error with cleanup.
   This check reads the rules; live enforcement and reboot verification
   remain TS-470 deployment checks. If nftables is missing, stop this step
   and have TS-470 provision it before retrying.

4. Confirm the initially signed controller configs already contain the
   `ts-auth` profile and enabled stateless service from the preparation above.
   This step changes no controller configuration. `autoscale.enabled` starts
   the reconciler for every service the signed config lists. The host agent
   must be prepared before releasing an artifact that can run there.

5. Download, verify and release:

   ```sh
   TAG=<ts-auth release tag>; COMMIT=<its full commit>
   cd "$WORK"
   fj -H git.terrascale.tech release asset download -r TerraScale/ts-auth "$TAG" ts-auth-linux-arm64
   fj -H git.terrascale.tech release asset download -r TerraScale/ts-auth "$TAG" ts-auth-linux-arm64.sha256
   sha256sum -c ts-auth-linux-arm64.sha256
   fj repo clone -H https://git.terrascale.tech TerraScale/ts-auth "$WORK/ts-auth"
   F=(--nats-forward 10.251.0.11:4222=127.0.0.1:14222)   # Bastion only
   sudo terrascale-orchestrator operator ts-auth-release \
     --config /var/lib/terrascale-operator/operator.json "${F[@]}" \
     --binary "$WORK/ts-auth-linux-arm64" --sha256 "$WORK/ts-auth-linux-arm64.sha256" \
     --source-checkout "$WORK/ts-auth" --commit "$COMMIT" \
     --environment canary --profile "$REPO/deploy/oci-region/ts-auth-gru-1-profile.json" \
     --wait 10m
   ```

   Expect `{"step":"artifact",...}`, `{"step":"deploy",...}` and
   `{"step":"ready",...,"members":2}`.

6. Verify:

   ```sh
   sudo terrascale-orchestrator operator hosts --config /var/lib/terrascale-operator/operator.json "${F[@]}"
   curl -fsS https://gru.auth.terrascale.tech/readyz
   curl -fsS https://gru.auth.terrascale.tech/terrascale/.well-known/openid-configuration | jq -e '.issuer == "https://gru.auth.terrascale.tech/terrascale"'
   ```

   Expect two `ts-auth` reports `running` with the new digest on two
   different controllers, `{"status":"ready",...}` and `true`.

A later release repeats step 5. A changed secret needs step 3's `env-file`
on every controller and a new release (or replica restart) to load it.

### Ouroboros owner and dashboard handoff

Both follow the numbered steps and are separate confirmations. Reuse the
forward and member CA of step 2.

Owner (phase B), after ts-auth is live (step 6 passed) and `mariogk@terrascale.tech`
has signed in once. `<slug>` is the ts-auth instance the person signed in
to; copy its `sk_` management key into an owner-only file and shred it
afterwards:

```sh
(umask 077; cat > "$WORK/ts-auth-sk")   # paste the sk_ key, then Ctrl-D
(umask 077; netbird ssh root@gru-1-db-1.nb.ts.internal cat "${CRED:?}" > "$WORK/dashboard-credential")
terrascale-orchestrator ouroboros bootstrap --plan "$PLAN" \
  --client-url https://127.0.0.1:19465 --admin-url http://127.0.0.1:19464 --member gru-1-db-1 \
  --member-ca "$WORK/member-ca.pem" \
  --dashboard-credential-file "$WORK/dashboard-credential" --management-listener admin \
  --owner-email mariogk@terrascale.tech --ts-auth-instance <slug> \
  --ts-auth-key-file "$WORK/ts-auth-sk"
shred -u "$WORK/dashboard-credential" "$WORK/ts-auth-sk"
```

Expect the two phase A lines with `"created":false`, then
`{"organization_id":"...","owner":"<user id>","admin":"ts-orchestrator","steps":[...]}`.
A rerun prints `"steps":[]`. If the person has not signed in, it stops with
`ts-auth instance <slug> has no user mariogk@terrascale.tech yet: sign in once
with that address (for example on the dashboard), then rerun`; sign in and
rerun.

Dashboard handoff, Fly app `ts-dashboard`. It sets `TERRABASE_URL`
(`https://gru.api.terrascale.tech`), `TERRABASE_PROJECT_ID` (from the Vault),
`TERRABASE_DATABASE` (`dashboard`) and `TERRABASE_API_KEY` (from the Vault),
and the dashboard's ts-auth client: `TS_AUTH_ISSUER`
(`https://gru.auth.terrascale.tech/terrascale`), `TS_AUTH_CLIENT_ID`
(`ts-dashboard`), `TS_AUTH_REDIRECT_URL`
(`https://dash.terrascale.tech/login/callback`) and `TS_AUTH_CLIENT_SECRET`
(from the Vault, the secret ts-auth registers).

```sh
# Without a token: reads only the project ID, prints the six non-secret
# settings and the Vault secrets that hold the key and the client secret.
terrascale-orchestrator ouroboros fly-secrets --plan "$PLAN"
# Expect {"app":"ts-dashboard","settings":{...},"api_key_secret":"gru-1-ts-dashboard-terrabase-api-key","client_secret_secret":"gru-1-ts-auth-dashboard-client-secret","staged":false}

# With a token (after step 1 created the client secret): reads all three
# secrets and runs
# flyctl secrets import --app ts-dashboard --stage, values on stdin.
FLY_API_TOKEN=<token> terrascale-orchestrator ouroboros fly-secrets --plan "$PLAN"
# Expect the same line with "staged":true
```

No secret is in argv, output or logs. Staged secrets take effect at the
dashboard's next deploy (`fly deploy` or `fly secrets deploy`), which is the
TS-472 cutover.

## Qualification

TerraBase is never faked: the tenant bootstrap runs against the real
TerraBase release binary.

- `internal/tsauth` (T2, suite `ts-auth-terrabase` of
  `scripts/ci/qualify-image.sh`; locally
  `make terrabase-release-process TERRABASE_BINARY=<terrabase-linux-amd64>`):
  `TestBootstrapAgainstTerraBaseRelease` starts a member of the release
  named by `TS_TERRABASE_BINARY` (TS-535 or later) with a cell-CA member
  certificate on its client listener and a Management service credential,
  runs `ouroboros bootstrap` through the admin listener twice (organization `terrascale`, projects `ts-auth` and `ts-dashboard`, four
  secrets; the rerun issues no key) and checks that each project's key
  cannot read the other project's database, and that another tenant's key, a
  wrong credential, the credential on the client listener and a certificate
  for another member are refused. It then runs phase B against a fake
  ts-auth users API: the missing-user message, the member add and ownership
  transfer with `ts-orchestrator` kept as admin, a no-op rerun, and a phase A
  rerun after the transfer. Passed locally against
  `ci-7f743f1abe3180aeca77fe23d0eabefdf8c6a5af-run-13654`
  (`terrabase-linux-amd64`, SHA-256
  `68b8c15719a5f2d59ef6934b0312fab1fc587a696e5621932f56a7d9116da897`).
- `internal/tsauth` (T0): `TestEnsureOwnerAddsTransfersAndKeepsTheBootstrapAdmin`
  (phase B's calls and acting users against a fake admin listener with
  TerraBase's role rules; a rerun only lists members),
  `TestOuroborosTSAuthUserLookup` (paging;
  unverified, banned, duplicate and missing users; HTTP errors without the
  key) and `TestOuroborosFlySecrets` (no-token mode reads no API key; token
  mode stages through a stub `flyctl` with the values on stdin and redacts the
  key from a failure). Also profile rules, env file parse and render (no value
  in any error), probe, release verification, the backend set from the real
  `plan.json`, Vault create-once with a fake OCI Vault (existing, pending
  deletion, duplicate and paged secrets, retry token), `ReadSecrets`, and
  `WriteEnvFile` mode, owner and atomic replace.
  `TestEnvFileRefusesOverlappingHostRootsBeforeMutation` covers equality,
  ancestor and descendant overlaps for the install, state and TerraBase
  roots, both through the command and a direct call; permissions and contents
  stay unchanged and no OCI request is made.
  `TestRenderedMetadataRulesReserveMetadataForRootAndController` checks the rendered
  output rule, its root/controller allowlist, its timesync-only UDP exception,
  and the unit's required boot ordering.
- `internal/host` (T0): `TestTSAuthReplicaGetsEnvFileSecrets`,
  `TestTSAuthEnvFileMustBeWorkloadOwnedAndPrivate`,
  `TestTSAuthRootBelowManagedRuntimeRoot` (the image layout),
  `TestTSAuthRefusedWithoutRoot`, `TestTSAuthRunningOnlyWhenReady`,
  `TestTSAuthRootMustBeSeparate`, `TestTSAuthExitReportedOnceBeforeRelaunch`.
- `internal/ociregion` (T0): `TestPublicSubnetReachesControllersOnlyOnTSAuthPort`.
- `internal/app` (T0): `TestTSAuthGRUConfigIsValid` checks the committed
  profile and spec against signed-config validation;
  `TestTSAuthReleaseGateWithFakeReplicas` runs `operator ts-auth-release`
  against an in-process controller whose reconciler owns ts-auth and two host
  agents in two failure domains, with a stand-in for the unpublished ts-auth
  binary: deploy, upgrade, and a crashing release rolled back.

Not tested: OCI Vault, instance principal reads, the real ts-auth binary
(TS-488 has not published it), and the load balancer.
