# Unified orchestrator CLI

The [cluster CLI and dashboard contract](cluster-visibility.md) defines the
desired complete human/AI interface, structured output, shared APIs and metric
coverage. The inventory below describes existing commands; it does not claim
that every desired operation is implemented.

The [zero-configuration contract](zero-configuration.md) governs production.
This is current command inventory, not a per-region setup or tuning recipe.
Runtime input removal and automatic Vault delivery remain TS-796; read-only
verification and explicit destructive-operation safeguards still apply.

TerraScale Orchestrator ships one Go executable. It has one runtime,
`single-host`, which every production node runs from `deploy/m1/ts-orch.service`;
every other command is operator or CI tooling. `make build` writes
`dist/ts-orch`. Published Linux artifacts and the installed binary keep the
`terrascale-orchestrator` name.

## NetBird configuration

`ts-orch netbird` also reconciles the NetBird manager with the desired state
embedded in the binary; see [NetBird](../deploy/netbird/README.md#desired-state-and-reconciliation).
Without `--apply` these commands only read.

| Command | Effect |
| --- | --- |
| `ts-orch netbird sync [--apply] [--pat-file FILE]` | Plan, or with `--apply` reconcile, groups, policies, network, DNS and settings |
| `ts-orch netbird prune-peers [--apply] [--offline-for DURATION]` | List, or with `--apply` delete, offline GRU server peers of replaced revisions |
| `ts-orch netbird remove-peers (--slot NAME... \| --all) [--apply]` | List, or with `--apply` delete, the disconnected GRU server peers of decommissioned slots |
| `ts-orch netbird setup-key --out FILE [--servers-group GROUP] [--apply]` | Plan, or with `--apply` create, the GRU (or GROUP, e.g. `sjc-servers`) server setup key; its value goes only to the new owner-only FILE |
| `ts-orch netbird inventory` | Print the manager's groups, policies, networks, DNS and peers |
| `ts-orch netbird dns [enable] [--apply] --netbird COMMAND` | Plan, or install, native operator DNS with a brief overlay reconnect; use another SSH transport or a detached invocation |
| `ts-orch netbird dns --config-dir /etc/netbird-wt0/config.d --netbird netbird-wt0 --apply` | Enable NixOS operator DNS and persist an owned `90-ts-orchestrator-dns.json` override |
| `ts-orch netbird dns --split-resolver --upstream IP --netbird COMMAND --apply` | Route `nb.ts.internal` through a local host-network container's resolver; preserve existing search/options and route other queries to the explicitly supplied current upstream |

## Secrets

`ts-orch vault` keeps secrets in OCI Vault; see [secrets](secrets.md) for the
naming scheme and who may read what.

| Command | Purpose |
| --- | --- |
| `ts-orch vault deliver --cell REGION --service SERVICE --refs FILE --dir DIR [--refresh 1m] [--once] [--file-names]` | Fetch CURRENT at startup and atomically refresh private tmpfs files on newer versions; output metadata only |
| `ts-orch vault version --vault-id OCID --name NAME --secret-id OCID --expect-current N --file /dev/stdin [--instance-principal]` | Publish owner-provided bytes with an ETag and verify CURRENT readback; never generate or blindly retry a value |
| `ts-orch region plan LABEL OCI_REGION --out FILE [--from PLAN]` | Derive a non-home region's plan from another region's reviewed plan; reads OCI, creates nothing ([new region](new-region.md)) |
| `ts-orch region create LABEL OCI_REGION --state DIR --attempt-base FILE --home-plan FILE` | Bring the region up: foundation, private peering with gru-1, NetBird, founding attempt, edge, DNS, verify; resumable, prints each step's wall time |
| `ts-orch region verify LABEL --plan BOUND_PLAN [--wait D]` | Fail unless api and auth answer, the api answers the dashboard's browser ping (`Access-Control-Allow-Origin`, `Timing-Allow-Origin`, `Cache-Control: no-store` on `/healthz`) and every load balancer backend is healthy |

## Services

`ts-orch service` applies and removes services in every region and inspects
this host's.

| Command | Purpose |
| --- | --- |
| `ts-orch service apply -f <spec.json> [--hold-after <region>]` | Apply a service spec in every ordered region over this host's mesh; without a mesh node it applies on this host only; `--hold-after` stops the rollout once that region is done |
| `ts-orch service resume <name>` | Continue a rollout held with `--hold-after`; needs this host's mesh |
| `ts-orch service ls` | List this host's services: name, running replicas, image |
| `ts-orch service rm <name>` | Remove the service in every region over the mesh and on this host |
| `ts-orch service ps <name>` | Print the service's tasks on this host |
| `ts-orch service logs [-f \| --previous] <name>` | Print the service's task logs on this host; `-f` follows the current task, `--previous` prints the ended task's snapshot |
| `ts-orch service inspect <name>` | Print the service's live spec and state as JSON |

## Fleet deployment

CI runs `ts-orch release push` and `ts-orch release nudge` for every `main`
merge; see [platform design](platform.md#releases).

| Command | Purpose |
| --- | --- |
| `ts-orch release push --dir D --sha SHA [--regions F]` | CI only: send a main build one region at a time, waiting for JetStream and the region's services |
| `ts-orch release app --service NAME --image REF@SHA256 [--regions F]` | CI only (app image): release an app image to every region over the mesh |
| `ts-orch release digests --out F [--regions F]` | CI only (app digests): record every mesh service's desired image to a file |
| `ts-orch release mesh-check [--spec F] [--regions F]` | CI only: re-prove mesh ping, `service apply` and HTTPS in every region after a fleet push |
| `ts-orch release verify-provenance --image REF@SHA256 --workflow OWNER/REPO/.github/workflows/W.yml@refs/heads/main --revision SHA` | Operators: verify the image's Sigstore provenance attestation is signed by that workflow for that commit (prints `ok`) |
| `ts-orch release pin [--state DIR]` | Print the SPKI pin of the single-host listener certificate in a state directory |
| `ts-orch release manifest --sha SHA --sequence N --out FILE` | Operator: build a production release manifest from a CI release's Linux binaries, hashing each download |
| `ts-orch release sign --manifest FILE --key KEYFILE` | Operator: sign a manifest with `ssh-keygen -Y sign` (namespace `ts-orch-release`, works with ssh-agent and hardware keys); writes `FILE.sig` |
| `ts-orch release verify --manifest FILE [--sig FILE.sig] [--allowed FILE]` | Verify a manifest's signature against the embedded allowed SSH keys (or a test list with `--allowed`) |
| `ts-orch release preflight [secrets]` | Run by a host on a candidate binary before it accepts it: reads the host's service secrets |
| `ts-orch release recover` | Run by the host's recovery unit: finish or roll back the pending release trial |

## Signed release manifests

Create a manifest from the newest matching CI release, then sign its exact bytes
with an SSH key. Each Linux binary is downloaded and hashed with SHA-256.
Set GITHUB_TOKEN to authenticate release-list requests if needed.
The sign command attaches the terminal to ssh-keygen, including hardware-key prompts.
Verification checks the ts-orch-release namespace, manifest fields and signer's
release role, printing ok sequence=<n> sha=<sha> signer=<name> on success.
The embedded deploy/m1/allowed-keys.json is initially empty; supply --allowed FILE
until release keys are enrolled. The file has the shape
{"keys":[{"name":"operator","key":"<authorized_keys line>","roles":["release"]}]}.

## Feature boundaries

`ts-orch usage --region <gru|sjc> --from <RFC3339> --to <RFC3339>
[--format json|table]` reads authenticated node and service CPU/memory history.
`ts-orch bench run --region <gru|sjc> --workload <name> --clients go,dotnet,rust`
runs isolated load-generator jobs and attaches that usage window. See
[capacity benchmarking](capacity-benchmarking.md) for setup, current SDK
blockers, bounds and cleanup guarantees.

Prefer `ts-orch` for new operational features. Implement them as Go commands
in their feature packages instead of adding Python scripts or separate
executables. CI and operator automation should invoke those commands. Keep
business logic, validation, and provider effects in Go; use thin wrappers only
for environment setup and invocation. See [contributing](../AGENTS.md).

`internal/cli` dispatches commands. The runtime and its local commands live in
`internal/app`; domain and provider code stay in their feature packages. CLI
command packages receive cancellation and output from the executable without
changing global process output or starting NATS. Release commands keep normal
SIGINT/SIGTERM termination.

## Operational dependencies

`ts-orch verify --live` runs opt-in, read-only production observations; see
[live verification](live-verification.md) for evidence requirements and gaps.

Operations against an established cell should use the authenticated operator
path and controller-owned reconciliation. Initial bootstrap must support direct
OCI operations before the regional cluster exists.
