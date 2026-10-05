# ts-auth deployment on gru-1

Status: **implemented in source and tested locally with fake OCI Vault,
the real TerraBase release and fake replicas; not run on OCI.** ts-auth (repository
`TerraScale/ts-auth`, C# .NET 10) runs as a native single-file workload of
role `ts-auth` on the gru-1 controllers and is served publicly at
`https://auth.terrascale.tech` through the OCI L7 load balancer `gru-1-api`
(TS-486). Package
[`internal/tsauth`](../internal/tsauth) holds the contract, the Vault secrets,
the TerraBase tenant bootstrap and the `ts-orch ts-auth` command; the host
side is [`internal/host/tsauth.go`](../internal/host/tsauth.go).

| Command | Where | Effect |
| --- | --- | --- |
| `ts-orch ts-auth secrets --plan FILE` | operator host, `~/.oci/config` | Generates `TS_AUTH_MASTER_KEY`, `TS_AUTH_AUDIT_SIGNING_KEY` and `TS_AUTH_OPERATOR_KEY` once into the cell's Vault. |
| `ts-orch ts-auth terrabase-bootstrap --plan FILE --client-url URL --admin-url URL --member NODE --member-ca FILE --dashboard-credential-file FILE` | operator host, SSH forward to `gru-1-db-1` | Finds or creates ts-auth's TerraBase organization, project and database; stores the project ID and, once, a new API key in the Vault. |
| `ts-orch ts-auth env-file --host-config FILE --vault-id OCID` | each controller, as root | Reads the five secrets with the instance principal and writes `<ts_auth_root>/ts-auth.env`, mode 0600, owned by the workload user. |
| `ts-orch ts-auth metadata-rules` | operator host, no OCI access | Renders the nftables metadata block installed on each controller in step 3. |
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
| `TS_AUTH_PUBLIC_ORIGIN` | Exactly `https://auth.terrascale.tech`. |
| `TS_AUTH_TERRASCALE_API_URL` | Exactly `https://gru.api.terrascale.tech`. |
| `TS_AUTH_DATABASE` | Exactly `auth`, the database `terrabase-bootstrap` creates. |
| Env file keys, `TS_AUTH_LISTEN`, `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | Must not be set. |
| `TS_AUTH_SMTP_PASSWORD`, `TS_AUTH_STRIPE_SECRET_KEY`, `TS_AUTH_STRIPE_WEBHOOK_SECRET`, `TS_AUTH_SENTRY_DSN`, `TS_AUTH_AUDIT_VERIFY_KEYS`, `OTEL_EXPORTER_OTLP_HEADERS` | Must not be set: they are secrets, and the env file does not carry them yet. Non-secret optional settings (SMTP host, OTEL endpoint) may be added. |
| `args` | Must be empty: an argument overrides any setting. |

### Secrets and the env file

| Env file key | Source | Vault secret |
| --- | --- | --- |
| `TS_AUTH_MASTER_KEY` | `ts-auth secrets`: 32 random bytes, base64 | `gru-1-ts-auth-master-key` |
| `TS_AUTH_AUDIT_SIGNING_KEY` | `ts-auth secrets` | `gru-1-ts-auth-audit-signing-key` |
| `TS_AUTH_OPERATOR_KEY` | `ts-auth secrets` | `gru-1-ts-auth-operator-key` |
| `TS_AUTH_TERRASCALE_API_KEY` | `terrabase-bootstrap`: TerraBase `POST /admin/api-keys` | `gru-1-ts-auth-terrascale-api-key` |
| `TS_AUTH_TERRASCALE_PROJECT_ID` | `terrabase-bootstrap`: the project the key is narrowed to | `gru-1-ts-auth-terrascale-project-id` |

The project ID is not secret; it travels with the API key because the key
reaches only that project's database.

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
| `<root>/ts-auth.env` | workload user, 0600 | The five secrets |
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

`auth.terrascale.tech` is a proxied Cloudflare record for the OCI L7 load
balancer `gru-1-api` in the public API subnet (`10.251.0.128/26`), which
TS-486 creates. TLS ends at the load balancer with a Cloudflare Origin CA
certificate; a hostname rule sends `auth.terrascale.tech` to the ts-auth
backend set over plain HTTP. These are the values it consumes,
`tsauth.BackendSet(plan)`:

| Value | gru-1 | Source |
| --- | --- | --- |
| Hostname | `auth.terrascale.tech` | `tsauth.Hostname` |
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

## TerraBase tenant

ts-auth keeps its data in the production TerraBase, the same release end
users reach at `https://gru.api.terrascale.tech`, as an ordinary tenant: there
is no private TerraBase instance.

| Object | Name | How |
| --- | --- | --- |
| Organization | `terrascale-internal`, owner `ts-orchestrator` | Management API on the member's client listener (9465) |
| Project | `auth` | Management API |
| Database | `auth` (`TS_AUTH_DATABASE`) | Management API |
| API key | `ts-auth`, scopes `documents:read`, `documents:write`, narrowed to the database | `POST /admin/api-keys` on the member's loopback admin listener (9464) |

The Management API needs the member's dashboard credential
(`TERRABASE_DASHBOARD_CREDENTIAL_FILE`); without one it answers 401 and the
command stops. The command reaches both listeners through an SSH forward to
`gru-1-db-1`, trusts the cell's member CA and checks the member certificate
names `--member`. Each object is created only when the acting user has none
of that name; two of one name stop the command. A key is issued only when the
Vault holds no `gru-1-ts-auth-terrascale-api-key`. TerraBase has no key
revocation yet: a key issued while the Vault write then fails stays unused,
and the rerun issues one more. Every run reads both secrets back: the stored
project ID must be the tenant's project, checked before any key is issued,
and the stored key must list the database's collections, so a stale Vault
entry (for example after a TerraBase reset) stops the command instead of
passing. Each TerraBase request times out after 30 s.

The admin listener is loopback-only, so both APIs are reached on one member,
`gru-1-db-1`, through the forward. **Open (TerraBase TS-464):** until
replication exists each member is an independent database, so the tenant and
key exist only on `gru-1-db-1`, while `gru.api.terrascale.tech` balances over
every member. ts-auth works only once replication carries the tenant to every
member, or while the API's backend set holds `gru-1-db-1` alone.

## gru-1 live runbook

**Prepared, not executed. Requires human confirmation before every step that
changes the cell, the Vault or TerraBase.** Blast radius: one controller NSG
rule, the gru-1 Vault (five new secrets), the production TerraBase on
`gru-1-db-1` (one organization, project, database and API key) and the three
controllers (`host.json`, one env file each, one ts-auth replica on two of
them).

### Prerequisites

1. **Phase 1.** `deploy/oci-region/plan.json` `resource_ids` names the live
   `control_compartment`, `vault` and `key` (TS-470).
2. **TerraBase.** `gru-1-db-1` serves the C# TerraBase release
   ([TerraBase deployment](terrabase-deployment.md)) with
   `TERRABASE_CLIENT_PORT=9465` and a dashboard credential:
   `TERRABASE_DASHBOARD_CREDENTIAL_FILE` names a file of at least 32
   characters that the workload user can read. **Open:** the committed
   [`terrabase-gru-1-profile.json`](../deploy/oci-region/terrabase-gru-1-profile.json)
   does not set it yet; TS-470 adds it with the TerraBase deployment.
3. **Controller hosts (manual TS-470 prerequisite).** Prepare host-agent
   registration, NATS/TLS credentials and `/etc/terrascale-orchestrator/host.json`
   on `gru-1-ctl-1`, `-2` and `-3`, with role `ts-auth`, environment `canary`,
   `failure_domain` `fault-domain-1`, `-2`, `-3` (lowercase tokens),
   no managed bindings and capacity for the profile's `resources` (1 CPU,
   1 GiB memory, 2 GiB disk). Use the qualified image's distinct workload
   UID/GID `2000:2000`; keep the host agent stopped until step 3 prepares its
   env file and firewall dependency. TS-484 enrolls database hosts; controllers
   lack the host descriptor, so their automatic `host-setup` does not create
   these files or registrations. An authorized operator registers each reviewed
   host record with `ts-orch operator host-register --config /var/lib/terrascale-operator/operator.json --registration FILE`.
   Stop before step 3 if this manual preparation is incomplete.
4. **Load balancer.** TS-486 is merged and applied: `gru-1-api` with the
   ts-auth backend set and hostname rule, its Origin CA certificate and the
   proxied DNS record for `auth.terrascale.tech`. Step 0 opens the controller
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

Prepare each controller's ts-auth configuration **before its initial manifest
is signed and accepted**. The installer is write-once, and restart admission
binds the config digest to that accepted manifest. Adding ts-auth to an already
accepted controller config is unsupported; do not edit its installed JSON or
delete its acceptance marker. TS-470 must include these inputs in the initial
gru-1 rebuild/bootstrap.

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
CRED=<path that TERRABASE_DASHBOARD_CREDENTIAL_FILE names on gru-1-db-1>
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

1. Generate the three keys into the Vault. Expect three lines with
   `"created":true` (a rerun prints `"created":false`):

   ```sh
   terrascale-orchestrator ts-auth secrets --plan "$PLAN"
   ```

2. Bootstrap the TerraBase tenant on `gru-1-db-1`. Keep the forward open in a
   second terminal, copy the dashboard credential into an owner-only file,
   run the bootstrap, then delete the copy:

   ```sh
   netbird ssh -L 19464:127.0.0.1:9464 -L 19465:127.0.0.1:9465 root@gru-1-db-1.nb.ts.internal   # terminal 2
   (umask 077; netbird ssh root@gru-1-db-1.nb.ts.internal cat "${CRED:?}" > "$WORK/dashboard-credential")
   sudo cat /var/lib/terrascale-operator/terrabase-ca-gru-1/member-ca.pem > "$WORK/member-ca.pem"   # public certificate
   terrascale-orchestrator ts-auth terrabase-bootstrap --plan "$PLAN" \
     --client-url https://127.0.0.1:19465 --admin-url http://127.0.0.1:19464 --member gru-1-db-1 \
     --member-ca "$WORK/member-ca.pem" \
     --dashboard-credential-file "$WORK/dashboard-credential"
   shred -u "$WORK/dashboard-credential"
   ```

   Expect one line `{"tenant":{...},"secrets":[...]}` with the organization
   `terrascale-internal`'s IDs, database `auth` and both secrets
   `"created":true`. A rerun prints `"created":false` and issues no key.

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
   curl -fsS https://auth.terrascale.tech/readyz
   ```

   Expect two `ts-auth` reports `running` with the new digest on two
   different controllers, and `{"status":"ready",...}`.

A later release repeats step 5. A changed secret needs step 3's `env-file`
on every controller and a new release (or replica restart) to load it.

## Qualification

TerraBase is never faked: the tenant bootstrap runs against the real
TerraBase release binary.

- `internal/tsauth` (T2, suite `ts-auth-terrabase` of
  `scripts/ci/qualify-image.sh`; locally
  `make terrabase-release-process TERRABASE_BINARY=<terrabase-linux-amd64>`):
  `TestBootstrapAgainstTerraBaseRelease` starts a member of the release
  named by `TS_TERRABASE_BINARY` with a cell-CA member certificate on its
  client listener and a dashboard credential, runs `bootstrap` twice
  (organization `terrascale-internal`, project `auth`, database `auth`, one
  key that lists the database; the rerun issues none) and checks that another
  tenant's key, a wrong credential and a certificate for another member are
  refused. Passed locally against
  `ci-0248ad3ac6fb82ac900e38005840a619e5d0beac-run-13267`
  (`terrabase-linux-amd64`).
- `internal/tsauth` (T0): profile rules, env file parse and render (no value
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
