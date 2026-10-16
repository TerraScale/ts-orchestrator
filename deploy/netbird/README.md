# Dedicated GRU NetBird foundation

The control binary embeds the upstream manager deployment in
[`manager/bundle.go`](manager/bundle.go). `internal/netbird/foundation` installs
and supervises the components on the dedicated admitted GRU host, independently
of NetBird admission, NATS and the workload scheduler. It consumes an OCI-owned
foundation Vault target and a current authority check; host names, private IPs,
manual PAT files and dashboard setup are not bootstrap inputs.

| Component | Fixed deployment |
| --- | --- |
| Combined management/signal/relay/STUN | NetBird server 0.80.0, direct containerd task; HTTP on `127.0.0.1:18081`, STUN UDP 3478 |
| Dashboard | Dashboard v2.94.0, direct containerd task; HTTP on `127.0.0.1:18080` |
| Public TLS ingress | Caddy 2.10.2-alpine containerd task; `netbird.terrascale.tech` HTTPS/gRPC/WebSocket endpoints; `/api/setup` always returns 404 |
| Identity/store | `/var/lib/terrascale/netbird/data`, protected persistent storage; config `/run/terrascale-netbird/config.yaml`, mode 0600 |
| Lifecycle | `netbird-foundation.service` before public ingress; 15-second task health checks, six-hour credential renewal, 30-second systemd retry after reconciliation errors |

The supervisor uses qualified containerd **2.4.2** and runc **1.5.2**, native
snapshots, fixed architecture-specific image digests and the bounded binary
runtime logger. Its namespace is `terrascale-netbird`; task IDs are
`netbird-server`, `netbird-dashboard` and `netbird-ingress`. Persistent state is
mounted from the host; replacing a task or snapshot does not replace that state.
Operational Podman/Quadlets are not used. Server host images must already include
the pinned native NetBird client and its systemd service. Enrollment reads the
regional setup key directly from OCI Vault through admitted host authority; no
first-party key is copied into files or passed through an operator shell.

## Bootstrap and credential recovery

1. Admit the host and resolve its scoped OCI foundation record before calling
   `foundation.Supervisor.Install` or `Reconcile`. The record supplies a scoped
   Vault/key/compartment and immutable authenticated operation/generation, not
   secret values. Bootstrap refuses absent authority or store generation.
2. Create encryption/authentication keys through the existing OCI SDK clients.
   Existing data refuses new replacement keys if its original Vault material
   is missing. Deliver configuration into the protected runtime directory.
3. Start the upstream services with management HTTP bound to loopback. Store a
   generated owner recovery password in Vault and fsynced protected local
   escrow **before** creating the initial owner through `POST /api/setup`.
   No setup-time PAT environment switch is used.
4. Use embedded Dex's authorization-code flow with PKCE over loopback to create
   the account's `ts-orchestrator` admin **service user** and its PAT. Publish
   `gru-1-netbird-admin-pat` into Vault and verify its CURRENT value through the
   authenticated API. Controllers receive that service PAT, not the owner password.
5. Verify `GET /api/instance` reports closed setup, then start public ingress.
   Reconciliation renews service PATs with less than fourteen days remaining;
   the old token survives until the replacement is stored and authenticated.
   Successful publication removes previous or unpublished same-name tokens.

The owner password is `gru-1-netbird-owner-password`, read only by foundation
recovery authority. A lost setup response is recovered by checking instance
status and logging in with that existing password. A lost PAT response or failed
Vault publication is recovered by the same owner login, publishing a replacement
and removing the unpublished token. Existing upstream identity is never reset.
The protected `data/terrascale-identity/owner.json` escrow contains the owner
password, retained owner ID, admitted store generation, durable setup attempt
and exact genesis Vault target. The setup attempt is fsynced before the first
owner write. A manager reporting
setup required after that intent refuses a new account, even if owner capture
never finished. A lost store requires restoration or authenticated recovery; an
attempt that never reached upstream also remains pending without exact proof.
A changed Vault target requires
a separately authenticated recovery handoff; this slice does not infer one from
replacement host placement.

All account and Vault writes check current authority; OCI mutation requests do
not retry internally across authority changes. Each reconciliation stops and
waits for the prior server before starting another bootstrap attempt, closing
handlers that may have an uncertain write. The public setup endpoint stays
blocked even after recovery.

Upstream protocol source: NetBird tag `v0.80.0`, commit
`fca64287cf51a85552a41b022013abbfdb335452`,
`management/server/instance/setup_service.go`,
`management/server/http/handlers/instance/instance_handler.go`,
`management/server/idp/embedded.go`, and
`management/server/http/handlers/users/pat_handler.go`.

## Backup and restore

The backup owner snapshots a stopped upstream store together with the rendered
configuration, encryption material and enrollment journal/escrow below the data
tree. `Supervisor.Pause` returns a restart action; it waits for the same store to
reopen and authenticated readiness before restoring public ingress. Runtime
configuration survives a service stop. Copies belong in protected OCI Object
Storage in GRU and outside GRU, with verified bucket/KMS identities.

`ts-orch netbird foundation backup` is the timer boundary. Restore selects an
existing archive into an absent replacement directory; it does not overwrite
or activate a serving manager. Admission, matching Vault material, private
routing, DNS/TLS and ownership must be established before activating a replacement.
A snapshot on the live host alone is not disaster recovery.

## Qualification boundary

`TestBootstrapPinnedUpstreamAndLostVaultPublication` runs the actual pinned
upstream process, embedded Dex and SQLite, plus real OCI SDK HTTP requests to an
isolated protocol simulator. It exercises failed PAT publication, restart reuse,
protected owner escrow,
Vault-target/generation mismatch refusal, uncertain conditional PAT renewal,
closed setup and lost-store refusal before owner capture. The fixture requires
Podman and the cached pinned image;
provider simulation is not live OCI qualification.

`TestFoundationContainerdLifecycle` requires the disposable qualified containerd
socket and a compiled binary with the runtime logger dispatcher. It exercises
actual native snapshots, process reuse/restart/replacement, persistent mounts,
authority refusal, ownership refusal, interrupted snapshot attachment and shim
logging. It uses a pinned minimal image; it does not qualify the complete public upstream stack.

The legacy shared ts-ops installer and manual owner/PAT handoff were removed.
No live manager, account or Cloudflare record was changed by this implementation.
Trusted OCI host-record discovery and CLI dispatch are integration prerequisites;
this package does not establish paid capacity, private-subnet reachability,
ARM64 qualification, live TLS, or off-host restore acceptance. Upstream metrics
binds `:9090`; admitted-host network policy must keep that listener private. A
delayed account HTTP commit during supervisor termination is not yet qualified.
