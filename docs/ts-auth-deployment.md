# ts-auth deployment on gru-1

**Production today (M1, 2026-10-27).** ts-auth runs only in gru
([`deploy/m1/services/ts-auth.json`](../deploy/m1/services/ts-auth.json),
`regions: ["gru"]`) and is served at exactly one hostname,
`https://auth.terrascale.tech`, by the ts-orch edge (DNS-only A record).
Its issuer is `https://auth.terrascale.tech/terrascale`. The dashboard is served
only at `https://dash.terrascale.tech`. There are no regional
`<cell>.auth.terrascale.tech` or `<cell>.dash.terrascale.tech` hostnames, and
none have DNS records. The `sjc.auth` and `fra.auth` records were deleted on
2026-10-27 because nothing served them. Regional hostnames below belong to the
legacy `ts-orch oci-region` cell model.

The standalone `TerraScale/terrabase`, `TerraScale/ts-auth` and
`TerraScale/ts-libs` repositories have no GitHub copies (API checked
2026-10-28). Current service source lives in the public
[TerraScale monorepo](https://github.com/TerraScale/terrascale). The legacy
standalone producer/image/E2E commands below still require their original
qualified inputs; monorepo outputs cannot silently replace signed source and
artifact contracts. They do not describe the current M1 app release path; see
[delivery pipeline](delivery-pipeline.md). Historical Forgejo evidence and
signed records keep their original identities.

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

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
| `ts-orch ouroboros bootstrap --plan FILE --client-url URL --admin-url URL --member NODE --member-ca FILE --dashboard-credential-file FILE [--management-listener client\|admin] [--owner-email EMAIL --ts-auth-instance SLUG --ts-auth-key-file FILE [--ts-auth-url URL]]` | operator host, SSH forward to `gru-1-db-1` | Finds or creates TerraScale's TerraBase organization and the ts-auth, ts-dashboard and atlas (ts-atlas' store, see [Atlas](atlas.md)) projects and databases; stores each project ID and, once, a new API key in the Vault. With `--owner-email` (needs `--management-listener admin`), makes that ts-auth user the organization's owner. |
| `ts-orch ts-auth metadata-rules` | operator host, no OCI access | Renders the nftables metadata block installed on each controller in step 3. |
| `ts-orch service add --role ts-auth --profile F --spec F --out F`, `release sign-spec`, `apply -f` | operator host | Adds ts-auth to a running cell with a signed cell spec; see [cell spec](cell-spec.md). |
| `ts-orch bootstrap render-controller-config ... --ts-auth-profile F --ts-auth-profile-sha256 H --ts-auth-service F --ts-auth-service-sha256 H --out F` | operator host, before initial controller signing | Includes the reviewed ts-auth profile and service in canonical signed controller configuration. |
| `ts-orch operator ts-auth-release --config FILE --binary F --sha256 F --source-checkout DIR --commit SHA --environment ENV --profile F [--wait 10m]` | operator host | Verifies, admits and rolls out one release; gates on readiness and rolls back a release that fails. |

On cell hosts the installed binary is `terrascale-orchestrator`; it exposes
the same commands. No command prints a secret: they print secret names,
OCIDs, tenant IDs and digests.

## Placement: one stateless replica on every node

ts-auth is **stateless**: users, sessions, keys, claims, webhook deliveries
and audit events live in its TerraBase database, and every replica serves
any request ("regional ts-auth processes share one database", ts-auth
README). Its only process state is a two-second readiness cache. So it runs
as a `stateless` service with **3 replicas**, at most one per failure domain:
one on each of gru-1's three nodes, beside that node's controller and
TerraBase member (TS-578).

- Every replica reaches TerraBase through the members' private endpoints
  (`TS_AUTH_TERRASCALE_API_ENDPOINTS`) and fails over between them.
- Three replicas survive the loss of one node or fault domain with two still
  serving; the load balancer sends traffic only to replicas whose `/readyz`
  answers.
- The workload reconciler owns the role (`controller.autoscale.services`), so
  a lost replica comes back when its node does.

If ts-auth ever keeps state in process (for example a local rate limiter
that must be exact), this decision becomes 1 replica.

## Runtime contract

### Release

ts-auth CI publishes `ts-auth-linux-arm64` and `ts-auth-linux-arm64.sha256`
(TS-488). `tsauth.VerifyRelease` checks them like a TerraBase release: the
asset name (`ts-auth-linux-amd64` or `-arm64`), ELF magic, at most 512 MiB,
and the single `sha256sum` line; that digest is admitted and pinned. The
source claim is `https://github.com/TerraScale/ts-auth`, the commit
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
| `TS_AUTH_PUBLIC_ORIGIN` | Exactly `https://<cell>.auth.terrascale.tech`, the cell's regional host, `https://gru.auth.terrascale.tech` in gru-1 (user decision 2026-10-05; `auth.terrascale.tech` stays the ts-atlas proxy). `<cell>` is the lower-case catalog cell (`gru`, `sjc`, `fra`); a cell outside the catalog, or another cell's URLs, are refused. ts-auth's issuer is `<origin>/terrascale`. |
| `TS_AUTH_TERRASCALE_API_URL` | Exactly `https://<cell>.api.terrascale.tech`, `https://gru.api.terrascale.tech` in gru-1. |
| `TS_AUTH_TERRASCALE_API_ENDPOINTS`, `TS_AUTH_TERRASCALE_API_CA`, `TS_AUTH_TERRASCALE_API_FAILOVER` | Optional, endpoints and CA together: the [private TerraBase path](#private-terrabase-path). Each endpoint is `https://<IP>:<TERRABASE_CLIENT_PORT>` of a member the cell's `terrabase` profile lists in `TERRABASE_PEERS`, at most once, `;`-separated; the CA is 1 to 4 PEM CA certificates. Several endpoints need `TS_AUTH_TERRASCALE_API_FAILOVER=true`. Checked by the controller against the cell's current `terrabase` profile, so a spec that drops a member ts-auth still names is refused. |
| `TS_AUTH_DATABASE` | Exactly `auth`, the database `ouroboros bootstrap` creates. The host passes ts-auth `<project-ulid>/auth`, the project from the Vault. |
| `TS_AUTH_ACCESS_TOKEN_AUDIENCES` | Exactly `https://<cell>.api.terrascale.tech`, the cell TerraBase's `auth-audience`: every access token names it, so a dashboard user's token reaches TerraBase's Management API (TS-519). |
| `TS_AUTH_DASHBOARD_REDIRECT_URIS` | Exactly `https://dash.terrascale.tech/login/callback`, the dashboard's callback. |
| `TS_AUTH_DASHBOARD_POST_LOGOUT_REDIRECT_URIS` | Exactly `https://dash.terrascale.tech/login`, the `post_logout_redirect_uri` the dashboard sends; ts-auth compares it exactly. |
| `TS_AUTH_SMTP_HOST`, `TS_AUTH_SMTP_PORT`, `TS_AUTH_SMTP_FROM_ADDRESS`, `TS_AUTH_SMTP_CHECK_REVOCATION` | The [SMTP relay](#secrets-and-email-delivery): `smtp.email.sa-saopaulo-1.oci.oraclecloud.com`, `587` (STARTTLS), `noreply@terrascale.tech` and `false`. Other non-secret optional settings (OTEL endpoint) may be added. |
| The secret keys below, `TS_AUTH_LISTEN`, `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | Must not be set in `env`. |
| `secrets` | Names the six secret keys below, each `{"vault": OCID, "name": NAME}`, and may add `TS_AUTH_SMTP_USERNAME`, `TS_AUTH_SMTP_PASSWORD` and `TS_AUTH_SERVICE_CLIENTS`. The committed profile names both SMTP credentials. |
| `TS_AUTH_STRIPE_SECRET_KEY`, `TS_AUTH_STRIPE_WEBHOOK_SECRET`, `TS_AUTH_SENTRY_DSN`, `TS_AUTH_AUDIT_VERIFY_KEYS`, `OTEL_EXPORTER_OTLP_HEADERS` | Must not be set: they are secrets, and the profile does not name them yet. |
| `args` | Must be empty: an argument overrides any setting. |

### Secrets and email delivery

OCI Vault must automatically create, deliver and configure master/audit/operator,
OIDC client, database and email-delivery credentials. Vendor-issued credentials
are stored once and discovered automatically. Project selectors travel with the
narrowed database credential; the host must validate the complete scope before
publishing a snapshot. Operators do not generate, upload or copy production keys.

**Current gap (TS-796):** profile refs and existing bootstrap commands still
select/create part of this material. Delivery through a profile is evidence only
for that consumer; it does not prove automatic first-party provisioning.

SMTP requires authenticated STARTTLS, an approved sender and valid certificate
chain/hostname. The current revocation-check exception can accept a revoked
relay certificate and remains a security limitation to resolve, not a switch
recipe. Logging-only delivery belongs in test binaries. IAM must grant only the
approved sender and exact owned secret identities. Credential rotation must
prove new-version delivery before retiring the old version; uncertain mutations
must not be blindly replayed. Maintain fenced one-replica-at-a-time rollout,
verified artifact digests and readiness/native-login checks.

### Private TerraBase path

ts-auth stores through the cell's TerraBase members over the VCN, not
through `https://gru.api.terrascale.tech` (Cloudflare, then the OCI load
balancer) (TS-577). The profile names the members' client listeners and the
cell's member CA:

```json
"TS_AUTH_TERRASCALE_API_ENDPOINTS": "https://10.251.0.21:9465;https://10.251.0.22:9465",
"TS_AUTH_TERRASCALE_API_FAILOVER": "true",
"TS_AUTH_TERRASCALE_API_CA": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
```

- **Failover is a documented security exception.** ts-auth's contract is
  one storage authority without failover; with one endpoint it is pinned and
  fails closed while that member is down. `TS_AUTH_TERRASCALE_API_FAILOVER=true`
  (required for several endpoints) lets it move to the next member, which
  may not have replicated the latest writes yet: within the members'
  replication lag a read can miss them, and a conditional write there can
  succeed against older state (a consumed challenge, a uniqueness claim, a
  refresh-token rotation). gru-1 sets it: before TS-577 ts-auth reached both
  members round-robin through the load balancer (TS-574), so every request
  had that exposure; now only a db-1 outage does. Drop db-2 and the flag to
  fail closed instead.
- **Order.** Every replica sends to the first ready member, in the
  profile's order, so all replicas use one member and read their own writes
  (TS-575). ts-auth probes each member's `/readyz` every 2 s; a member that
  answers 503 (draining, or a catalog follower that has not caught up) or
  does not answer is skipped. A request that cannot connect within 2 s marks
  its member down at once. Requests are never resent. Order the list to choose
  the preferred member.
- **TLS.** ts-auth trusts only `TS_AUTH_TERRASCALE_API_CA` for these
  endpoints, the CA in `controller.terrabase_ca_cert_file`. Member
  certificates carry the member's IP as a SAN, so an IP endpoint verifies by
  name. TerraBase's client listener does not request client certificates;
  ts-auth authenticates with its project API key, as before. A rebuilt cell
  has a new member CA: put it in the profile before releasing ts-auth there.
- **Network.** The `gru-1-databases-nsg` admits TCP 9465 from each controller
  (`10.251.0.11/32`, `.12/32`, `.13/32`; `workload_nsg_rules` in
  [`plan.json`](../deploy/oci-region/plan.json)). The controllers' egress to
  `10.251.0.0/24` is already open.
- **`TS_AUTH_TERRASCALE_API_URL`** stays required and keeps its rules; with
  endpoints set, storage no longer uses it. A ts-auth release before TS-577
  ignores both settings and keeps storing through it.

Change it in place: `ts-orch service update --role ts-auth` with the live
profile (`ts-orch get`) plus the two settings, `release sign-spec --root`
(the profile names Vault secrets), `diff`, `apply`, then `operator
ts-auth-release` with that profile; the gate replaces one replica at a time.
Roll back the same way without the two settings.

### OpenID Connect

ts-auth (ts-auth#36) serves one issuer, `https://auth.terrascale.tech/terrascale`,
with discovery at `https://auth.terrascale.tech/terrascale/.well-known/openid-configuration`.
At startup it registers the dashboard confidential client
`01M4EQ2FRJ8S8B29E8TQVWNW4J` from
`TS_AUTH_DASHBOARD_CLIENT_SECRET` and the two profile URIs above.
ts-orch delivers the dashboard the matching `TS_AUTH_ISSUER`,
`TS_AUTH_CLIENT_ID`, `TS_AUTH_REDIRECT_URL` and `TS_AUTH_CLIENT_SECRET`
from OCI Vault.
This ID matches `OidcIssuer.DashboardClientId` in ts-auth revision
`ac893792853c564b54947b2bcf9b0019d5e9cd9f`. Qualify a release with this
registration before the coordinated greenfield deployment; old auth releases
registering `ts-dashboard` are not compatible.

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
- The host agent reads the profile's secrets with its instance principal at every
  launch of a replica and checks their forms before it starts it. Errors name
  keys and secrets, never values. Values never enter signed config, desired
  state, reports, logs or disk. A running replica keeps its environment until
  it restarts; a rotated secret reaches it at the next restart.

### Host layout and launch

Set `"ts_auth_root": "/srv/ts-managed/ts-auth"` in the controller host's
`host.json` (`host` section). It is validated like `terrabase_root`
(separate from the install, state and TerraBase roots, no replaceable or
symlinked ancestor) and kept across host credential renewal. It lives inside
the managed runtime tree `/srv/ts-managed`, which the host service can write.

| Path | Owner, mode | Content |
| --- | --- | --- |
| `<root>` | supervisor, workload group, 0750 | |
| `<root>/bundle` | workload user, 0700 | Extracted native libraries |

The replica's environment is the host base environment, the profile, the
secrets, then `TS_AUTH_LISTEN=http://0.0.0.0:8080` and
`DOTNET_BUNDLE_EXTRACT_BASE_DIR=<root>/bundle`. It runs as the workload user
in its own cgroup under the host agent.

Each role's cgroup shares the native workloads' CPU cap (below one CPU) at a
lower CPU and I/O weight than the controller and host agent, which also run
at nice -20, so NATS keeps its share. Memory is unlimited unless the host
sets `role_memory_max_bytes` in `host.json` (`host` section, kept across
credential renewal), for example on a 6 GB controller that also runs a
TerraBase member (TS-578):

```json
"role_memory_max_bytes": {"terrabase": 3221225472, "ts-auth": 1073741824}
```

A role's cap becomes its cgroup `memory.max` from its next start; .NET sizes
its heap to it. The agent refuses a cap for a role the host does not run.
Set `"version": 3` in the same file when adding it by hand, so an older
binary skips the member instead of refusing the config.

### Instance metadata firewall

The controller/worker image installs the `metadata-rules` renderer's root-only
IMDS fence and its mandatory systemd unit. The pinned Ubuntu base must contain
the audited native `/usr/sbin/nft` executable and nftables libraries; the builder
rejects missing tools, unexpected packages, symlinks, modes or architectures.
It follows ELF interpreter and transitive library dependencies through the
pinned Noble system directories, checks their native architecture and protected
ownership, and rejects preloads or custom library search paths.
Installed rules and unit are root-owned 0644 files, and the finished image
readback verifies their bytes and the complete inspected nft runtime.

Only host root may access OCI instance metadata at `169.254.169.254`. The
ordinary `terrascale-orchestrator` account, ts-auth and other workloads cannot
obtain its certificates or private key. The `inet` output hook runs at priority
0 after destination NAT, with no established-connection bypass. IPv4-mapped
sockets produce IPv4 packets and hit the same rule. Routed namespace traffic
is blocked before destination NAT and again at forwarding; a `bridge` forward
hook blocks layer-2 forwarding even without `br_netfilter`. The inspected OCI
clients use that IPv4 IMDS endpoint; no separate IPv6 endpoint is configured.
`systemd-timesync` retains only UDP/123 to OCI's NTP service, and
`systemd-resolve` retains only TCP/UDP port 53 to OCI's DNS resolver. Workloads
use the host resolved stub and host clock, not direct forwarded access.

The rule applies to existing connections as well as new ones. Reloading
atomically replaces only the owned `inet` and `bridge` tables named
`terrascale_metadata`, leaving NetBird and other firewall tables intact.
The root oneshot runs before network-pre, containerd, managed host startup,
controller installation/admission (including dropped children), managed
runtime, the ordinary controller and worker host services. Required dependency
links and explicit ordering make a missing executable, missing DNS/time
account or rejected ruleset prevent those startup paths. It returns inactive
after loading, so every dependent start reloads the rules.
Stopping the unit leaves the rule installed. Do not flush the global nftables ruleset.

This source change must not activate before APP migrates every legitimate
ordinary OCI SDK/Vault consumer to concrete authenticated root operations.
Previously cached tokens, copied IMDS certificates/private keys and exposed
root material need their separate controlled cutover and rotation; installing
a firewall does not revoke previously acquired credentials. Image construction,
kernel packet checks and live activation require their own QA authorization.

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

A green ts-auth `main` CI releases ts-auth to every region with no human
step ([automatic service releases](continuous-delivery.md#automatic-service-releases-ts-610)):
the region's leader runs this same gate and rollback, one node at a time
behind the cell spec's `release_fence`. The operator command stays for a
release by hand; it bypasses the fence and restarts every replica at
once, so drain the backends first.

`operator ts-auth-release` is `operator terrabase-release` for role
`ts-auth` (see [TerraBase deployment](terrabase-deployment.md#run) for the
steps, interrupt handling and rollback). It waits for 3 replicas that report
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

The stable bootstrap service actor is `01M4EB0GDPPHGJPPVY77EMZQKT`
(`tsauth.BootstrapUser`). Management requests send that ULID as
`X-TerraBase-User-Id`. Phase B requires a canonical uppercase user ULID
distinct from this service actor; prefixed and UUID user IDs are rejected.

| Object | Name | How |
| --- | --- | --- |
| Organization | `terrascale`, owner `01M4EB0GDPPHGJPPVY77EMZQKT` until phase B, then the person | Management API on the member's client listener (9465), or from TerraBase TS-519 its loopback admin listener (9464) |
| Project, database | `ts-auth`, `auth` (`TS_AUTH_DATABASE`) | Management API |
| Project, database | `ts-dashboard`, `dashboard` | Management API |
| API keys | one per project, scopes `documents:read`, `documents:write`, narrowed to that project's organization, project and database | `POST /admin/api-keys` on the member's loopback admin listener (9464) |

| Vault secret | Content |
| --- | --- |
| `gru-1-ts-auth-terrascale-project-id` | ts-auth's project ID |
| `gru-1-ts-auth-terrascale-api-key` | ts-auth's key (a secret the ts-auth profile names) |
| `gru-1-ts-dashboard-terrabase-project-id` | the dashboard's project ID |
| `gru-1-ts-dashboard-terrabase-api-key` | the dashboard's key |

The names are stable: `<cell>-<key lowercased, _ replaced by ->`.

### Phase A: tenants and keys (always)

`ouroboros bootstrap` acts as the fixed service identity `01M4EB0GDPPHGJPPVY77EMZQKT`
(header `X-TerraBase-User-Id: 01M4EB0GDPPHGJPPVY77EMZQKT`, with the member's Management
service credential). The Management API needs that credential
(`TERRABASE_MANAGEMENT_CREDENTIAL_FILE` from TerraBase TS-519 on, before it
`TERRABASE_DASHBOARD_CREDENTIAL_FILE`); without one it answers 401 and the
command stops. Phase B refuses to add a member once another user owns the
organization, so a rerun with a different address changes nothing. The creator of an organization becomes its first owner, so a
new organization is owned by `01M4EB0GDPPHGJPPVY77EMZQKT`. The command reaches both
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

1. Add the user as a member, acting as the bootstrap actor. TerraBase records
   the address only in the audit event `member.added`.
2. Start the ownership transfer to the user (as the bootstrap actor) and
   confirm it acting as the user. Confirming demotes the bootstrap actor to
   member.
3. Make the bootstrap actor admin again, acting as the new owner.

The bootstrap actor is never removed. The command prints
`{"organization_id","owner","admin":"01M4EB0GDPPHGJPPVY77EMZQKT","steps":[...]}`; a rerun
prints `"steps":[]`. Phase A reruns still work afterwards: an admin may list
and create projects and databases.

## Automatic deployment and recovery boundaries

The manual regional setup, production secret extraction and dashboard handoff
recipes are retired. The [operating contract](zero-configuration.md) requires
private NetBird admission, region discovery/inference and Vault creation/delivery
to be automatic. The current reviewed plan, profile and first-controller paths
are TS-796 gaps; this documentation does not certify their completion.

Safe serving still requires:

1. Verified deployment identity, exact resource ownership, scoped trust grants,
   artifact source/digests and a qualified runtime/SDK contract. Do not adopt a
   resource based on tags or names alone.
2. A dedicated service dataset and least-privilege database key. Provisioning
   must not use a ts-auth self-issued token to create its own storage authority.
   Customer identity, project tenancy and issuer/callback verification remain
   owned by ts-auth. Never seed a production demo account or memory store.
3. Protected instance metadata, valid TLS, exclusive retained-volume ownership,
   storage consistency and fresh readiness. No loopback/bootstrap credential
   may authenticate public client routes; the backend carries the verified user.
4. Healthy controller quorum, current peer proofs and single-writer authority.
   Keep one-replica-at-a-time rollout, rollback artifacts, drain/writer-stop proof
   and post-rollout health/native-login checks. Discovery alone proves none of
   the required storage or failover guarantees.
5. Explicit approval of verified targets for destructive resets, ownership
   recovery or resource deletion. Record only object IDs, secret-version IDs
   and redacted evidence. Existing authorization never permits unrelated fleet,
   infrastructure or operator-host changes.

Automatic dashboard provisioning must deliver its database and confidential-client
credentials directly from Vault, preserve CSRF and exact issuer/redirect bindings,
and verify persistence and native login.

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
  transfer with the bootstrap actor kept as admin, a no-op rerun, and a phase A
  rerun after the transfer. Passed locally against
  `ci-7f743f1abe3180aeca77fe23d0eabefdf8c6a5af-run-13654`
  (`terrabase-linux-amd64`, SHA-256
  `68b8c15719a5f2d59ef6934b0312fab1fc587a696e5621932f56a7d9116da897`).
- `internal/tsauth` (T0): `TestEnsureOwnerAddsTransfersAndKeepsTheBootstrapAdmin`
  (phase B's calls and acting users against a fake admin listener with
  TerraBase's role rules; a rerun only lists members),
  `TestOuroborosTSAuthUserLookup` (paging;
  unverified, banned, duplicate and missing users; HTTP errors without the
  key). Also profile rules and secret refs, `TestValidateSecrets`
  (value forms, no value in any error), probe, release verification, the
  backend set from the real `plan.json`, and Vault create-once with a fake OCI
  Vault (existing, pending deletion, duplicate and paged secrets, retry token).
  `TestRenderedMetadataRulesReserveMetadataForRootAndController` checks the rendered
  output rule, its root/controller allowlist, its timesync-only UDP exception,
  and the unit's required boot ordering.
- `internal/host` (T0): `TestTSAuthReplicaGetsVaultSecrets`,
  `TestTSAuthRefusesBadProfileOrSecrets`,
  `TestTSAuthRootBelowManagedRuntimeRoot` (the image layout),
  `TestTSAuthRefusedWithoutRoot`, `TestTSAuthRunningOnlyWhenReady`,
  `TestTSAuthRootMustBeSeparate`, `TestTSAuthExitReportedOnceBeforeRelaunch`.
- `internal/ociregion` (T0): `TestPublicSubnetReachesControllersOnlyOnTSAuthPort`.
- `internal/app` (T0): `TestTSAuthGRUConfigIsValid` checks the committed
  profile and spec against signed-config validation;
  `TestTSAuthReleaseGateWithFakeReplicas` runs `operator ts-auth-release`
  against an in-process controller whose reconciler owns ts-auth and two host
  agents in two failure domains that read the profile's secrets from a fake
  Vault, with a stand-in for the unpublished ts-auth binary: deploy, upgrade,
  and a crashing release rolled back.

Not tested: OCI Vault, instance principal reads, the real ts-auth binary
(TS-488 has not published it), and the load balancer.
