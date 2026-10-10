# Managed NetBird clients (TS-674)

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

Change a serving cell's NetBird version with a signed cell-spec amendment.
The `netbird` section lives in the replicated `TS_SERVICE_SET` NATS KV
record; the authority leader compares each node's **running daemon** version
and confirmed target hash with its pin and rolls one node at a time. The hash
includes binary digests and enrollment settings, so a same-version amendment
still rolls out. A node's root worker installs the
verified binary; its sandboxed host agent relays signed commands and bytes.
No cell is re-founded and no serving node is re-enrolled from scratch.

## Before the first deployment

1. Roll out a ts-orch binary that understands **cell-spec level 20** to every
   controller through the [existing self-update path](continuous-delivery.md#leader-run-controller-self-update).
   Check `ts-orch rollout status --config "$OPERATOR"` reports the release
   healthy before changing the pin.
2. Check `ts-orch node status --config "$OPERATOR"` and the current spec's
   `host_grants` against the actual GRU or SFO instances. The cell needs a
   `release_fence`, healthy peers satisfying every set's `min_serving`, and
   ordinary SSH on each node's OCI VCN address. Keep the public/OCI recovery
   path available throughout. Resolve existing maintenance, rename, release
   or failed-operation holds through their owning operation before proceeding.
3. Adopt the current host runtime on each existing colocated controller/host
   with `ts-orch node reboot --config "$OPERATOR" --node "$NODE" --wait 30m`,
   **one node at a time**. Wait for `done` and healthy backends before choosing
   the next node. TS-632 drains first, checks controller quorum and workload
   readiness, then returns the node. This is an in-place soft reboot, not a
   bootstrap or cell replacement.

Controller self-update starts `terrascale-netbird-agent.service`, but it does
not restart an already running colocated host process. That old process has
no NetBird command/status relay. The one-time node reboot above starts both
the current host binary and the worker. Later NetBird pin changes need no
operator reboot. Standalone hosts receive the current host binary through
their normal host rollout.

Managed NetBird unit adoption requires the image's default self-update root,
`/var/lib/terrascale-orchestrator`. With a custom `--root`, `selfupdate prepare`
warns and skips NetBird unit installation and startup because the packaged
worker and enrollment units execute the default root. Custom-root deployments
must configure those units to use their own current release before enabling
the cell's NetBird rollout; binary self-update continues normally.

## Pinned release and configuration

GitHub's latest stable `0.80.x` release was **v0.80.0**, published
2026-10-01, when rechecked on 2026-10-08. Recheck
[netbirdio/netbird releases](https://github.com/netbirdio/netbird/releases)
before a later bump; exclude drafts and prereleases. Match the archive hashes
to the release's `netbird_0.80.0_checksums.txt` (SHA-256
`120b6c8d4e15ad545fd73adbf06b4ea5df2806a290163439269714bddebbc700`),
then verify the extracted ELF separately. The reviewed GRU section is:

```json
{
  "netbird": {
    "pin": {
      "version": "0.80.0",
      "archives": {
        "arm64": {
          "url": "https://github.com/netbirdio/netbird/releases/download/v0.80.0/netbird_0.80.0_linux_arm64.tar.gz",
          "bytes": 14601271,
          "sha256": "8cbd99fa068a7b0f3968b2d31dc341acc17dd1e97c3053e61ed5905dbdae7341",
          "binary_sha256": "b3f589a873ed02c9cf1cf81a085976e4648b85333338de5cbb522f2e8cb540d0"
        },
        "amd64": {
          "url": "https://github.com/netbirdio/netbird/releases/download/v0.80.0/netbird_0.80.0_linux_amd64.tar.gz",
          "bytes": 15959645,
          "sha256": "47ffaba4fc3929f31795bd6c5232d6c29744d3169e2c93e6d9c84624f0ef6405",
          "binary_sha256": "777ab46ceb0ca1a3e8336e336b076a37b34255eee8c082ccc071ad954a28d2a2"
        }
      },
      "enrollment_config": {
        "path": "deploy/image/inputs/netbird-gru.json",
        "sha256": "f185e882ed7a859922d2db34e58835aa7668aeac3cae5662dc4cbdba918ab14d"
      }
    },
    "enrollment": {
      "management_url": "https://netbird.terrascale.tech",
      "management_ip": "10.250.10.155",
      "region": "sa-saopaulo-1",
      "setup_key_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaj7iuycp5pjd36u35pmekfwrubyvhtalvzvjun2xtdv3q",
      "admin_pat_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa47dfouwhtievxunck43w4pyccvjgwkfvfglthsopvszq",
      "peer_names": {
        "10.251.0.11": "ts-gru-1",
        "10.251.0.12": "ts-gru-2",
        "10.251.0.13": "ts-gru-3",
        "10.251.0.21": "gru-1-db-1",
        "10.251.0.22": "gru-1-db-2"
      }
    }
  }
}
```

`enrollment` contains public Vault references, never setup-key or PAT values.
Use `deploy/image/inputs/netbird-sfo.json` for SFO, with its own input hash,
`us-sanjose-1` Vault secret and peer names. The enrollment region and names
must belong to the cell. New nodes receive this configuration in their
authenticated enrollment response; a missing agent is installed and enrolled
with an instance-principal read of the setup key from OCI Vault. Neither the
key nor raw daemon output is logged. The image carries a verified fallback;
when it differs from the live pin, the worker uses authenticated artifact
delivery instead.

## Bump the pin

Set `OPERATOR` to that cell's operator JSON. Keep the signing keys owner-only;
use its existing valid leaf delegation for ordinary amendments. Adding the
section or changing `enrollment` requires the root. Preserve every unrelated
section of the live spec and increment its generation exactly once.

1. Update `deploy/image/image-inputs.json` with the reviewed `0.80.x` version,
   archive byte counts, archive hashes and extracted ELF hashes. Prepare the
   verified binaries locally before publishing the pin:

   ```sh
   umask 077
   WORK=$(mktemp -d)
   ts-orch netbird client fetch --inputs deploy/image/image-inputs.json \
     --architecture arm64 --out "$WORK/netbird-arm64"
   ts-orch netbird client fetch --inputs deploy/image/image-inputs.json \
     --architecture amd64 --out "$WORK/netbird-amd64"
   ```

2. Get the live spec and prepare the next generation. This example uses GRU;
   select SFO's enrollment input when targeting SFO:

   ```sh
   ENROLLMENT=deploy/image/inputs/netbird-gru.json
   ENROLLMENT_SHA=$(sha256sum "$ENROLLMENT" | cut -d ' ' -f1)
   ts-orch get --config "$OPERATOR" > "$WORK/current.json"
   jq --slurpfile inputs deploy/image/image-inputs.json \
     --slurpfile enrollment "$ENROLLMENT" \
     --arg path "$ENROLLMENT" --arg sha "$ENROLLMENT_SHA" \
     '.generation += 1 | .requires_binary = 20 |
      .netbird = {pin: ($inputs[0].netbird |
        .enrollment_config = {path: $path, sha256: $sha}),
        enrollment: $enrollment[0]}' \
     "$WORK/current.json" > "$WORK/netbird.candidate.json"
   ts-orch diff --config "$OPERATOR" -f "$WORK/netbird.candidate.json"
   ```

   The plan must show only `netbird: added` or `updated`, the next generation,
   and `requires_binary: 20`. A first addition lists `netbird enrollment` in
   `root_required`; an unchanged enrollment allows the leaf to sign a pin bump.

3. Sign the candidate through the existing offline workflow. For an ordinary
   pin bump:

   ```sh
   ts-orch release sign-spec --candidate "$WORK/netbird.candidate.json" \
     --delegation spec-delegation.json --root-key root.pub.pem \
     --signing-key leaf.key.pem --out "$WORK/netbird.signed.json"
   ```

   If the plan requires a root, use this instead:

   ```sh
   ts-orch release sign-spec --candidate "$WORK/netbird.candidate.json" --root \
     --root-key root.pub.pem --signing-key root.key.pem \
     --out "$WORK/netbird.signed.json"
   ```

4. Review the signed diff, apply the pin, and stage its verified bytes into
   the cell's existing artifact store. Staging requires the **active** pin, so
   it follows apply; prepare downloads beforehand. Stage **both pinned
   architectures**, even when the cell currently has only ARM64 nodes. The
   leader starts no drain until both ELF objects are available:

   ```sh
   ts-orch diff --config "$OPERATOR" -f "$WORK/netbird.signed.json"
   ts-orch apply --config "$OPERATOR" -f "$WORK/netbird.signed.json"
   ts-orch operator netbird-stage --config "$OPERATOR" \
     --file "$WORK/netbird-arm64" --architecture arm64
   ts-orch operator netbird-stage --config "$OPERATOR" \
     --file "$WORK/netbird-amd64" --architecture amd64
   ```

   Nodes need no GitHub access: the authenticated host session fetches the
   exact ELF digest over NATS. The operator, controller and root worker each
   verify the binary hash and architecture. If another amendment won the
   generation race, get the spec again and re-plan; never drop its changes.

5. Observe the automatic rollout and record before/after daemon versions on
   the ticket:

   ```sh
   ts-orch node status --config "$OPERATOR"
   ts-orch get --config "$OPERATOR"
   ```

   `netbird_nodes` must show every intended node at the pin, connected, with
   fresh observations and no pending transaction. `netbird` shows the active
   node and phase; completion is `done`. Check all backends returned and no
   unresolved fence remains before finishing the cell or moving to another.

## Health checks and rollback

The leader first reads both staged objects in full and verifies their chunks,
SHA-256 hashes and ELF architectures within a 30-second deadline. Missing,
corrupt or oversized artifacts hold before admission and resumed drains. It
also requires a fresh worker report from every node, healthy peers, controller
quorum, and an independent OCI SSH listener. Before admitting a drain it
touches both binaries' object metadata, preventing a collector that selected
the previously unused pin from deleting them after admission. Failed retention
holds the rollout. It reuses the TS-632 fence to drain and offline the selected
node's load balancer backends without violating `min_serving`. It never changes
SSH, public addresses, OCI networking or the recovery path.

Each drain attempt has a deadline of the configured drain grace plus 30
seconds, capped by the original drain phase's persisted deadline. Quorum and
shared-lock waits honor that deadline, so the controller can record a timeout
and continue reconciliation. Rollback re-drains remain bounded and retryable
after quorum repairs; the six-minute acknowledgment window starts when safe
re-draining and rollback command delivery succeed.

Admission persists the original fence and verified OCI address before any
drain. Removing the live pin, fence or node grant cannot erase that recovery
configuration or lower its recorded quorum. A resumed drain preflight uses
that admission while still checking current peer health and controller quorum.
The authenticated OCI SSH proof checks controller grants and authority even
after the live fence is removed. New managed candidates require a
live host session and an exact, owned, RUNNING OCI instance; recovery checks
keep the admitted node's persisted OCI address while refreshing live peers,
including after leader failover. A failed peer refresh holds the initial drain;
later phases retain cached peers and continue the admitted recovery checks.
Peer discovery is bounded to eight seconds and cannot strand rollback behind
an unrelated retired registration.

The rollout journal and current worker command share one record in the
authority control log. Each tick commits against the revision it loaded, with
the authority lease and write in the same durable order. A paused old leader
cannot overwrite a successor's journal or command. Worker observations remain
in NATS KV; node status reads the authoritative rollout record.
Command exchanges may advance the revision with an identical payload. A tick
can retry those conflicts without repeating its health/return work; any change
to the original journal or command requires a fresh tick.

When upgrading the leader, another controller must prove its OCI SSH path
through a fresh authenticated recovery probe. The leader's own locally routed
SSH connection cannot provide that proof. Missing or failed proof holds the
rollout before draining.

After replacement, confirmation requires the running version, management and
signal connection, NetBird IP, a DNS answer containing that IP, current
workload readiness, and TerraBase/ts-auth/NATS traffic over the mesh for the
roles the node runs. Only then does the node return to rotation; the next
node waits for this transaction to finish.

Joining or idle hosts need an active TerraBase/ts-auth endpoint or a controller
NATS listener before confirmation. Hosts with no applicable service endpoint,
including hosts whose roles are all withdrawn, remain unconfirmed: management
connectivity, DNS and local ready reports cannot prove traffic to the selected
mesh IP.

Remote controllers precede workload nodes and the leader. Missing or
unhealthy peers cannot mask an installed healthy alternative for leader
confirmation. An installed leader can admit its first missing remote peer;
that peer must pass full mesh probes after installation. A legacy leader
without a working NetBird client cannot perform those probes, so its cell
holds before draining. Restore its verified image enrollment over OCI first;
new images install and enroll through their bootstrap service automatically.

Bootstrap enrollment recovers its pending journal before trusting an installed
binary. An interrupted bootstrap resumes with its original `bootstrap-`
transaction ID and confirms only after installation and enrollment succeed.
A pending controller transaction holds bootstrap enrollment; the bootstrap
service cannot confirm it. Once a controller transaction exists, replacement
of a missing executable also belongs to the fenced rollout. Expired transactions
recover before public settings are loaded, so enrollment uses the restored
configuration.

An installed host's credential renewal preserves its NetBird pin and enrollment
settings. Before `host.json` exists, setup seeds those files under the managed
transaction lock only when no prior transaction exists, including a completed
rollback. This also covers a first local installation recovered through renewal
after the original response was lost. Subsequent setting changes belong to the
fenced NetBird rollout.

The controller's NATS mesh listener binds its exact NetBird IPv4 address
on the regional NATS client port. It uses the same TLS-first/mTLS, JWT and
authority-ticket gate as the OCI listener; OCI remains available during
enrollment and upgrades. Enrollment and address changes rebind this listener
automatically, without a NetBird rollout pin. Losing the local
mesh address closes it until NetBird reconnects. Managed same-cell
policies allow TCP 4222, 8080 and 9465 for NATS, ts-auth and TerraBase health;
sync these policies before applying the pin. Interregion port 7422 uses the
leaf protocol and separate credentials and cannot replace this probe. Verify
every target's mesh services and independent OCI SSH recovery path first.

The service policy grants TCP access to those three ports between enrolled
servers of the same region; it does not restrict HTTP paths. NATS requires
mTLS, broker credentials and authority tickets. ts-auth and TerraBase
readiness endpoints intentionally accept unauthenticated probes; TerraBase
probes still verify server TLS. Their API authorization remains a separate
service contract (see [ts-auth](ts-auth-deployment.md#runtime-contract) and
[TerraBase](terrabase-runtime-contract.md)). The manager currently maintains
regional server groups, not verified controller-role membership. A narrower
controller-only source group requires that trusted membership binding before
switching the policy; assigning the shared server setup key to it would give
every server the same access again. This policy is limited to regional servers,
not operators, development hosts, tenant peers or other regions.

The local installer retains the previous binary and arms a **5-minute
systemd rollback timer before replacing it**. Missing confirmation or failed
mesh health restores that binary and its saved enrollment, daemon configuration,
service unit and managed hosts entry automatically, including if the controller
or NetBird connection is lost. The leader checks the restored mesh before
returning the node. A failed transaction holds that pin for operator review;
an unresolved rollback leaves the node drained. Removing the pin keeps the
recovery exchange active until rollback is acknowledged, fresh health passes
and the fence returns successfully. Repair through the retained
OCI access path, prove health, and publish a reviewed corrected pin to retry.
`rollout resume` controls ts-orch binary rollouts, not this NetBird hold.

Installation work shares the pending journal's rollback deadline, including
OCI credential initialization, so command timeouts cannot cumulatively keep
the installer lock beyond local recovery. The timer rounds its scheduled
trigger up to avoid firing before that deadline. Snapshot and watchdog reads
reject special files without blocking. An operational error or unrecognized
service-state response holds installation before it records a rollback snapshot
or changes the service. A failure before journal commit can acknowledge a no-op
rollback only with durable private worker progress and a matching unchanged
journal baseline. Persisting rollback
authority first prevents any delayed install after that acknowledgment;
observing an unchanged version alone never releases the fence.

A failed first install restores the original absence of NetBird. Recovery
requires a fresh worker report explicitly proving that absence, plus the
exact rollback acknowledgment if installation began. Workload readiness over
the retained OCI path and LB backend health still gate return. Installed
agents continue to require restored mesh health. An early watchdog invocation
is a no-op until its persisted deadline; explicit signed rollback remains
available immediately.

The worker repairs an unexpired watchdog on startup and rolls back expired
pending journals before reporting daemon status. Transaction-specific backups
retain a verified private copy of the rollback executable, so ts-orch
self-update pruning cannot remove the watchdog's recovery command. The current
transaction's binary and enrollment snapshots remain available for explicit
rollback after confirmation. Superseded snapshots and interrupted preparations
are reclaimed under the transaction lock; preparing a successor preserves the
current snapshot until the successor journal is durably committed. The host relay
cannot access the private worker ledger or rollback snapshots; its `result.json`
is diagnostic output only. Returning a rolled-back node requires acknowledgment
of that exact rollback command plus fresh health checks, even after a pin change.
Every return phase persists intent before clearing backend flags. A failed
or interrupted return re-drains before the next status or health check, so an
unhealthy observation cannot prevent retrying that fence. Relay artifact files
and their rename are synced before publishing installation intent.

## T3 NixOS dev hosts

`delta`, `beta` and `mariogk-dev` are dev hosts, outside this cell reconciler.
Change their package through each host's NixOS configuration, nixpkgs pin or
NetBird overlay/module. Keep a working Tailscale session as the second access
path, rebuild one host at a time, and verify its daemon version, mesh peers
and T3 connections before moving to the next. Do not install the managed
server worker or replace `/usr/local/bin/netbird` on these hosts. If the
configuration repository or sudo is unavailable, stop that host update and
report a `NEEDS-USER` block with the missing access.
