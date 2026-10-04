# TerraBase deployment into a running cell

This is the operator workflow for the C# TerraBase binary after the regional
controllers have formed. One local command creates the cell's member CA; one
operator command verifies a published release, admits it, deploys it to
every member, waits for readiness and rolls back a release that fails. The
binary and host contract are in
[TerraBase runtime contract](terrabase-runtime-contract.md).

| Command | Effect |
| --- | --- |
| `ts-orch terrabase member-ca --cell CELL --out DIR` | Creates the cell's member CA: `DIR/member-ca.pem` and owner-only `DIR/member-ca.key`. Local; no NATS. |
| `ts-orch operator terrabase-release --config FILE [--nats-forward ...] --binary F --sha256 F --source-checkout DIR --commit SHA --environment ENV --profile F [--wait 10m]` | Verifies, admits and rolls out one release to all members; see [Run](#run). |
| `ts-orch operator hosts --config FILE [--nats-forward ...]` | Prints each host's registration, session and latest reports, including each member's digest and state. |

On the operator host the installed binary is `terrascale-orchestrator`; it
exposes the same commands. The operator config is
`/var/lib/terrascale-operator/operator.json`. Add
`--nats-forward CONTROLLER_IP:4222=127.0.0.1:PORT` only when reaching a
controller through an OCI Bastion forward.

## Prerequisites

1. **Orchestrator revision.** Controllers, host agents and the operator CLI
   run a revision that contains this contract (the `terrabase-peer` host
   operation, `host.terrabase_root`, `controller.terrabase_ca_*` and
   `operator terrabase-release`). Signed command and artifact claims change
   between revisions, so a CLI from another revision can be rejected by the
   controllers; `ts-orch oci-region attempt operator` verifies the cell's
   qualified CLI and prints its path.
2. **ARM64 release asset.** OCI hosts are ARM64. TerraBase CI publishes only
   `terrabase-linux-amd64` today; it must also publish
   `terrabase-linux-arm64` and its `.sha256` before an OCI deployment.
3. **Member CA on every controller.** Any controller may be the authority
   leader that signs member certificates, so each needs the files named by
   `controller.terrabase_ca_cert_file` and `controller.terrabase_ca_key_file`.
   Without them member certificate requests are refused and members never
   start.
4. **Workload profile.** The signed controller config carries
   `controller.workloads.terrabase`; see [Workload profile](#workload-profile).
5. **TerraBase hosts.** The hosts named in `TERRABASE_PEERS` are registered
   in the target environment with role `terrabase`, without `managed_oci`,
   `managed_placement` or `managed_member` bindings, with a current host
   session and capacity for the profile's `resources`. Their `host.json`
   sets `terrabase_root` (`/srv/ts-managed/terrabase`). The controller
   places exactly one member on each of these hosts and never moves a
   member: while a listed host is unavailable, a release cannot be placed;
   its delivery is retried and eventually held without writing any member. Hosts that
   self-enroll through host setup register a `managed_oci` binding to a
   schema-5 placement seat and cannot run C# members.
6. **Network.** The workload NSG allows the peer port (9443) between member
   IPs and the client port (9465) from clients and the Bastion endpoint.
   The admin port (9464) is loopback-only and needs no rule. Hosts reach
   controllers on 4222 (NATS).
7. **Operator grant.** The operator's signer grant lists role `terrabase`
   and the target environment; if it lists repositories, it includes
   `https://git.terrascale.tech/TerraScale/terrabase`.

## Workload profile

The profile is `controller.workloads.terrabase` in the signed controller
config, and the same JSON is passed to `--profile`. The controller compares
the configuration digest of `args` and `env` and rejects a rollout whose
profile differs. For cell `gru-1` with three members:

```json
{
  "resources": {"cpu": 1, "memory_bytes": 4294967296, "disk_bytes": 21474836480},
  "env": {
    "TERRABASE_PEER_PORT": "9443",
    "TERRABASE_CLIENT_PORT": "9465",
    "TERRABASE_PEERS": "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443"
  }
}
```

The `resources` values are an example; size them to the registered host
capacity. The controller config also names the member CA:

```json
"terrabase_ca_cert_file": "/etc/terrascale-orchestrator/terrabase/member-ca.pem",
"terrabase_ca_key_file": "/etc/terrascale-orchestrator/terrabase/member-ca.key"
```

These paths are an example. `TERRABASE_PEERS` is a proposed setting that the
current binary ignores; see the
[runtime contract](terrabase-runtime-contract.md#workload-profile).

## Release files

```sh
TAG=ci-<commit>-run-<run id>   # or v<Version>
COMMIT=<full 40-character commit of the release>
WORK=$(mktemp -d) && cd "$WORK"
fj -H git.terrascale.tech release asset download -r TerraScale/terrabase "$TAG" terrabase-linux-arm64
fj -H git.terrascale.tech release asset download -r TerraScale/terrabase "$TAG" terrabase-linux-arm64.sha256
sha256sum -c terrabase-linux-arm64.sha256
fj repo clone -H https://git.terrascale.tech TerraScale/terrabase "$WORK/terrabase"
```

Keep the asset file names: the command checks them. `--commit` must be a
full lowercase commit SHA present in the checkout; for a `v<Version>` tag
use `git -C "$WORK/terrabase" rev-parse "v<Version>^{commit}"`.

## Run

```sh
F=(--nats-forward 10.251.0.11:4222=127.0.0.1:14222)   # Bastion only
sudo terrascale-orchestrator operator terrabase-release \
  --config /var/lib/terrascale-operator/operator.json "${F[@]}" \
  --binary "$WORK/terrabase-linux-arm64" --sha256 "$WORK/terrabase-linux-arm64.sha256" \
  --source-checkout "$WORK/terrabase" --commit "$COMMIT" \
  --environment canary --profile /var/lib/terrascale-operator/terrabase-gru-1-profile.json \
  --wait 10m
```

The member count is the number of `TERRABASE_PEERS` entries. The command:

1. Verifies the asset name (`terrabase-linux-amd64` or `-arm64`), ELF magic,
   size (at most 512 MiB) and SHA-256 against the `.sha256` asset. That
   digest is pinned for the rest of the run.
2. Builds the source claim: the TerraBase repository, `--commit`, and the
   SHA-256 of `git archive --format=tar <commit>` in the checkout.
3. Reads the members' reports in `--environment`: the digest the `running`
   members serve (it refuses when they disagree) is the rollback target, and
   the command resolves its admitted artifact before changing anything. The
   next generation is above every committed `terrabase` desired, withdrawals
   included.
4. Pushes the binary and obtains the signed artifact admission; prints
   `{"step":"artifact", ...}` with the digest and the previous digest.
5. Submits the signed delivery intent for one member per peer; prints
   `{"step":"deploy", ...}` with the digest and generation once accepted.
6. Waits for the readiness gate: every replica in `--environment` reports
   the new digest `running` within `--wait`. A `failed` member, including one whose
   process exited, fails the gate at once; read errors are retried until
   `--wait`. Prints `{"step":"ready", ...}` with the member count.
7. On a gate failure, rolls back: a new intent with generation + 1 and the
   previous digest, which must pass the same gate. It does so whenever the
   release may have written members or may still write them. A submit that
   failed before the intent was signed and published changed nothing and is
   not rolled back. After any later submit error, an interrupt, or a
   delivery still undecided at `--wait`, the intent may have been
   published: the command reads the durable operation back (once more on a
   fresh context after an interrupt), gates it like any release when it was
   accepted, and rolls back unless a receipt proves that no member changed:
   `rejected`, or held because placement never planned it (for example a
   listed host is unavailable). The rollback's higher generation also keeps
   a late original from landing. The rollback runs on a fresh context with
   its own deadline, so it completes after Ctrl-C or SIGTERM. The command exits non-zero either way and says whether the
   rollback succeeded. A first deployment has no previous digest and is not
   rolled back. A failure to write progress to stdout never counts as a
   gate failure; the command reports it when it exits.

All members switch together: the delivery path writes every host's desired
at once, so every member restarts on the new binary. Per-member canary or
rolling updates are future work once replication exists. Old binaries stay
installed on the hosts, so a rollback reuses the cached file. A member's data
lives on its host, so the controller replaces a failed member in place
instead of moving it to another host, which is what lets the rollback land on
the hosts the failed release took over. When members
report different digests, for example after a failed rollback, the command
refuses until they agree.

Until replication exists (TerraBase TS-464), each member is an independent
database: a write to one member is not on the others.

## gru-1 live deployment runbook

**Prepared, not executed. Requires human confirmation before any step that
changes the cell.** Blast radius: every TerraBase member of cell `gru-1`
starts, or restarts, on the new binary at once. GRU is being wiped; there is
no terrabase-rust data to migrate.

1. Wait for a TerraBase release that publishes `terrabase-linux-arm64`, then
   download and verify it as in [Release files](#release-files).
2. On the operator host, create the member CA:
   `sudo terrascale-orchestrator terrabase member-ca --cell gru-1 --out /var/lib/terrascale-operator/terrabase-ca-gru-1`.
3. Install `member-ca.pem` and `member-ca.key` (root-owned, key 0600) on all
   three controllers at the paths the controller config names. **Open:** no
   current command distributes these files; the signed config installer
   installs only `controller.json`, the manifest and its three sidecars.
4. Add `terrabase_ca_cert_file`, `terrabase_ca_key_file` and
   `workloads.terrabase` to the controller config and install it through
   the signed controller config path
   ([production role configuration](production-role-config.md)). **Open:**
   `ts-orch bootstrap render-controller-config` does not render these fields
   today.
5. Make sure `gru-1-db-1`, `gru-1-db-2` and `gru-1-db-3` are registered as in
   [Prerequisites](#prerequisites) item 5 and the NSG as in item 6. Check
   with `sudo terrascale-orchestrator operator hosts --config /var/lib/terrascale-operator/operator.json`.
   **Open:** there is no documented procedure yet for provisioning and
   registering non-managed TerraBase hosts on OCI.
6. Check the rebuilt hosts read-only and take `TERRABASE_PEERS` from the
   log line it prints:
   `TS_OCI_LIVE_COMPARTMENT_ID=<gru-1 compartment> go test -count=1 -v -run '^TestLiveOCITerraBaseHostsReadOnly$' ./internal/terrabase`.
   It fails when a host is not A1, two hosts share a fault domain, or an
   NSG keeps a member from another member's peer port.
7. Write the profile file with the same `resources` and `env` as the signed
   config and run `operator terrabase-release` as in [Run](#run).
8. Confirm three `ready` members, and that `operator hosts` shows a
   `terrabase` report `running` with the new digest on each host.

## Qualification

Unit and real-binary tests are listed in the
[runtime contract](terrabase-runtime-contract.md#qualification).
`make terrabase-release-process TERRABASE_BINARY=<path>` runs the real-binary
deploy, upgrade and rollback test against an in-process controller and host
agent. Nothing in this workflow has run on OCI.

## Retired terrabase-rust managed path

The previous workflow deployed the Rust `tb-server` as a two-member managed
partition with `operator terrabase-deploy`, `terrabase-status`,
`terrabase-update`, `terrabase-sync` and `terrabase-walkthrough`, using
schema-5 placement, controller-prepared member material and retained OCI
volumes. Those commands and their code remain, but they target the retired
binary and must not be used for the C# binary. Git history keeps the full
previous text of this document.
