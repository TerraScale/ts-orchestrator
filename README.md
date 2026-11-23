# ts-orchestrator v2

TerraScale's orchestrator and global discovery plane. It replaces the v1 Go daemon (SwarmKit, embedded NATS, vendored OCI SDK) with:

- **`worker/`**: one Cloudflare Worker with two isolated Durable Objects. `FleetDO` (SQLite, `locationHint: "sam"`) is the control backplane and serves only `orch.terrascale.tech`. `AtlasDO` keeps database placements and serves only `atlas.terrascale.tech/v1/*`. Public reads come from `ATLAS_KV`; nightly snapshots go to the `FLEET_BACKUPS` R2 bucket.
- **`src/`**: the .NET 11 (C# 15, framework-dependent JIT) node binary `ts-orch`:
  - `TsOrch.Protocol`: the locked wire contract, mirrored 1:1 in `worker/src/protocol.ts`.
  - `TsOrch.Oci`: the OCI instance-principal signer and Vault client.
  - `TsOrch.Agent`: the Docker and cgroup v2 reconciler.
  - `TsOrch.Edge`: the Kestrel + YARP HTTPS and Postgres SNI edge.
  - `TsOrch.Cli`: the operator CLI and MCP server.
  - `TsOrch.AppHost`: the .NET Aspire local stack.
- **`deploy/`**: the declarative production inventory (`fleet.json`, `services/*.json`).

Every region has two node pools. The `stateful` pool (default 2 nodes) holds TerraBase data volumes. The `worker` pool is stateless and scales from 0 to 50 nodes. There is no manager quorum, no Raft and no NATS.

## Toolchain

`mise install` provides .NET SDK 11.0.100, Node 22 and OpenTofu 1.13.9.

## Checks

```sh
dotnet build TsOrch.slnx -c Release
dotnet format whitespace TsOrch.slnx --verify-no-changes
cd worker && npm ci && npx tsc --noEmit
```

## NetBird

`netbird-server` (management, signal, relay, STUN) and `netbird-dashboard` run in `gru` behind the edge at `netbird.terrascale.tech`, declared in `deploy/services/`. The edge blocks `/api/setup` publicly. `fleet.json` `netbird` names the management URL, DNS domain, network range, owner and the OCI Vault secrets for setup keys, admin PAT and owner password.

```sh
ts-orch netbird init --write-setup-keys-dir /tmp/netbird-keys
ts-orch netbird join
ts-orch netbird status
```

`init` is idempotent: it claims the initial owner if needed, configures `10.200.0.0/16` and `nb.ts.internal`, reconciles groups (`operators`, `ops-automation`, `<region>-servers`), replaces the default allow-all policy with least-privilege SSH and inter-server rules, and ensures valid reusable 90-day setup keys (writing any newly minted PAT or setup keys as `0600` files in `--write-setup-keys-dir` for OCI Vault upload without printing secrets). `join` fetches the operator setup key from OCI Vault (or `--setup-key-file`) and enrolls an operator machine via stdin.

Every node installs the `netbird` package at boot. `ts-orch-netbird.timer` runs `ts-orch netbird enroll` 45 s after boot and every 15 minutes, joining the node with the setup key named in instance metadata (`ts_netbird_url`, `ts_netbird_setup_key_secret`). Nodes accept WireGuard on UDP 51820; `gru` nodes also accept STUN on UDP 3478 through the NLB.

## Releases

v2 builds are tagged `v2-<sha>` only. Live v1 nodes follow `ci-*` release tags from `main` and ignore v2 tags until each region is cut over.
