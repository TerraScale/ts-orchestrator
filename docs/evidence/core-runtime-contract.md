# CORE runtime contract — local candidate, 2026-10-16

This slice embeds upstream SwarmKit and executes its generic tasks through the
real containerd client. It does not yet replace the production host/controller
entrypoints. A package build or local runtime result is not a fleet cutover.

## Pinned dependencies

| Component | Pin | Scope |
| --- | --- | --- |
| SwarmKit | `github.com/moby/swarmkit/v2 v2.1.2`, tag commit `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb` | Embedded manager, agent, Raft, certificate exchange and service/task authority. |
| containerd | `github.com/containerd/containerd/v2 v2.4.2` | Local privileged daemon and runc-v2 shim; `native` snapshotter. |
| runc | `v1.5.2` | Matches containerd v2.4.2's upstream `script/setup/runc-version`. |

CAP owns architecture-specific image installation and release checksums.
The first executed disposable prototype is native Linux/amd64. Linux/arm64,
regional HA and paid OCI capacity remain unqualified by this evidence.

## Boundaries

1. `StartNode` consumes a verified `Admission` containing region, stable host
   identity, OCI instance identity, fenced founder identity and host isolation
   role. Joining uses upstream Vault-delivered join tokens. It never infers a
   founder from an empty discovery response. A worker cannot use a manager token
   to start a manager. Certificates, Raft and upstream task identities persist.
2. `AdmitNode` maps independently verified membership to an upstream certificate
   node identity. Manager writes bind its name, region, instance and role;
   worker descriptions do not authorize placement. `manager` and `container`
   hosts have platform execution scope; `wasm` hosts have tenant scope.
3. Product intent maps to one stable SwarmKit service. SwarmKit owns replicas,
   task assignment and lifecycle rollback. Existing-service updates preserve
   the autoscaler's replica count. Production application must consume the typed
   signed OCI container claim, never reinterpret a native tarball digest.
4. `NewExecutor(socket,stateDir)` consumes generic kind
   `terrascale.container.v1`, type URL
   `terrascale.tech/runtime/container/v1`, containing the protobuf bytes of an
   upstream `api.ContainerSpec`. The accepted subset is digest-pinned child
   image, command/arguments, environment, working directory and numeric non-root
   UID/GID. CPU/memory limits are mandatory. Unsupported settings are rejected.
5. Container identity is `terrascale` namespace / `ts-<SwarmKit task ID>`.
   Container metadata binds task, service and immutable specification. Agent
   exit disconnects; it does not stop the container or shim-owned capped logs.
   An exited identity cannot restart as a new process. Removal is idempotent.

## Readiness, ports and isolation

Task `RUNNING` is execution state. Application readiness requires an actual
bounded probe before ingress registration. Public observation types omit
container specifications, environment values and raw runtime error strings.

The upstream inert allocator leaves generic tasks' allocated
`Endpoint.Ports` empty even when `Endpoint.Spec.Ports` declares host ports.
The upstream scheduler therefore does not reserve these ports. The narrow local
adapter serializes reservation against existing container metadata using a
canonical-runtime-socket file lock. It rejects duplicate ports across executor
restart and releases ownership only when the owning container is removed.
Missing container/port observations never authorize freeing a reservation.
This is a runtime resource check, not a second host/task scheduler.

Initial trusted stateless containers use host networking, read-only rootfs,
non-root credentials, dropped capabilities, no-new-privileges, seccomp and bounded
CPU/memory/processes. Host networking does not isolate metadata or control-plane
access. These containers are not qualified customer-function sandboxes. No
volumes, secrets or arbitrary network attachments are silently accepted.
All TerraBase/stateful tasks fail closed until DATA's actual writer, volume,
drain, process binding and compatibility proofs are connected.

## Evidence and remaining integration

The executor's preliminary real-runtime scenario passed in 2.51 seconds: two
distinct agent processes recovered the same running PID, identity changes were
rejected, bounded logs survived agent exit, usage was observed, shutdown worked
and removal was idempotent. The final exact source adds further checks and must
retain its own result. No fleet or architecture claim follows from that timing.

The combined manager/agent/containerd/runc/HTTP scenario and duplicate-port
recovery scenario live beside the executor integration test. They require an
explicit disposable daemon socket; an absent daemon fails rather than skips.
Runtime logger subprocesses use the same binary through its internal
`--runtime-logger <log-root>` entrypoint.

Production wiring still needs the verified foundation/admission producer,
automatic Vault join-material delivery, typed admitted OCI release consumer,
actual readiness-backed ingress and safe ownership transfer from the old engine.
The old native task owner remains reachable until those replacements are
integrated. It must be quiesced/fenced before the same workload is handed over.

The node wrapper deliberately refuses partial founder initialization or missing
Raft/certificate state. Recovery from that crash window and total disk loss
requires durable external founder authority; deleting the local admission marker
is not a recovery procedure.
