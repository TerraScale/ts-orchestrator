# Generic workloads

TS-572 lets ts-orch deploy any service with its own requirements: a
TerraScale service such as ts-dashboard, a tenant's service, or third-party
software that only ships as an image. A new service deploys with
`ts-orch apply -f app.yaml` or the Machines API (TS-564), with no orchestrator
code change. TerraBase and ts-auth become built-in templates on the same path
instead of code paths of their own.

The spec extends the [apps and machines](apps-machines.md) model of TS-563,
which owns `App`, `MachineConfig` and the `TS_APPS` store. Package
[`internal/workloadspec`](../internal/workloadspec) holds what this ticket
adds: `MachineSpec` is embedded anonymously in `MachineConfig` and `AppSpec`
in `App`, so their fields sit flat in an app's JSON. It imports no
orchestrator package, so the model, the scheduler and the host agent can all
use it.

The split follows the model's extension rules. What a host runs is in
`MachineSpec`, so changing it bumps the app's version and reaches its
machines; scheduling and rollout policy is in `AppSpec` and does not. Every
field is optional: a record without it keeps its meaning. Stores decode
strictly, so the controller binary that knows a field ships before anything
writes it.

## The spec

One app file, here a stateful service, shows every part. Fields marked with
their ticket belong to that ticket's types; the rest are `workloadspec`'s.

```json
{
  "name": "store",
  "class": "platform",
  "regions": {"gru": 3},
  "node_pool": "db",
  "config": {
    "role": "store",
    "digest": "<sha-256 of the admitted artifact>",
    "artifact": "tarball",
    "command": ["bin/store", "serve"],
    "args": ["--data", "/var/lib/store"],
    "env": {"STORE_LOG": "info"},
    "files": [{"path": "/etc/store/store.toml", "content": "peers = 3\n"}],
    "resources": {"cpu": 2, "memory_bytes": 8589934592, "disk_bytes": 21474836480},
    "services": [{"name": "api", "port": 9000}],
    "checks": [{"name": "ready", "type": "http", "port": 9000, "path": "/readyz"}],
    "restart": {"policy": "always"},
    "mounts": [{"volume": "data", "path": "/var/lib/store"}],
    "lifecycle": {"pre_stop": ["bin/store", "drain"], "drain_seconds": 45}
  },
  "placement": {"max_per_failure_domain": 1},
  "update": {"strategy": "rolling", "max_unavailable": 1},
  "stateful": {"quorum": 2},
  "depends_on": ["ts-auth"]
}
```

| Part | Fields | Owner |
| --- | --- | --- |
| Identity | `name`, `class`, `tenant` | TS-563 |
| Region pinning and count | `regions`, `node_pool` | TS-563; TS-565 changes the counts |
| Artifact | `role`, `digest` | TS-563 |
| Artifact kind | `artifact`, `image`, `command` | TS-572 |
| Process | `args`, `env`, `resources`, `restart` | TS-563 |
| Secrets | Vault refs in the role's cell spec profile | TS-554 |
| Config files | `files` | TS-572 |
| Ports | `services` | TS-563; TS-572 adds `protocol` and `public` |
| Health | `checks` | TS-563 |
| Volumes | `mounts`; the volume record | TS-572; TS-567 |
| Lifecycle | `lifecycle` | TS-572 |
| Placement | `placement` | TS-572; the scheduler is TS-563, dedicated hosts TS-566 |
| Scaling | policy and bounds | TS-565 |
| Update | `update` | TS-572; stateful rollouts are TS-571 |
| Stateful | `stateful` | TS-572 |
| Dependencies | `depends_on` | TS-572 |

### Artifacts and drivers

The artifact kind decides the driver; there is no separate driver field.

| `artifact` | What `digest` pins | `command` | Driver |
| --- | --- | --- | --- |
| `binary` (default) | the executable | none | native |
| `tarball` | a gzipped tar archive | first entry is a clean path inside it | native |
| `image` | the image manifest | optional entrypoint override | oci |

An image names a repository on a registry's DNS name (`ghcr.io/acme/web`),
never a tag or a digest: the runtime pulls `<image>@sha256:<digest>`, so a
moved tag or a registry search list cannot change what runs. `localhost` (the
runtime's local store) and IP addresses (such as the instance metadata
service) are refused. Every kind goes through the same admission: a trusted
signature and a role grant for the digest.

A command or hook starts with an absolute path in the machine, a path inside
a tarball, or, for an image, a name the image's `PATH` resolves.

### Secrets

Secrets stay [TS-554](secrets.md) refs in the role's cell spec profile, where
only a root can widen them. The spec has no secrets field: every machine of
the role gets the profile's refs, read from OCI Vault at each start into the
process environment only.

A command override or a hook could run any program of an image, such as
`/bin/sh -c`, inside a process that holds those secrets. So while a role's
profile names secrets, only a root may set or change an image's `command`
or the `lifecycle` hooks, like the refs themselves. A tarball's command
starts inside the admitted artifact, as a binary does, and stays a leaf
change.

### Files and mounts

`files` are UTF-8 configuration files placed read-only at absolute paths
before the machine starts. `mounts` place volumes, by name, at absolute
paths; a volume's size, placement and snapshots are its TS-567 record.
Files and mounts share one namespace: no path may equal or contain another,
or cover `/dev`, `/proc` or `/sys`. Paths use letters, digits, `.`, `_` and
`-` only, so no path can inject a systemd directive or a podman mount
option. The encoded `MachineSpec` is at most 128 KiB, because every machine
record carries its config.

### Lifecycle

`post_start` runs once the process starts and has 60 s; until it succeeds
the machine is not started, so a failing hook fails the update and triggers
its rollback. `pre_stop` runs before SIGTERM; its failure does not block the
stop. The machine has `drain_seconds`, `pre_stop` included and at most 60,
before its cgroup is killed: the host agent unit stops after 90 s and its
machines' drains must fit inside that.

### Placement

The scheduler always keeps one machine of an app per host, because native
machines share the host network. `placement` only adds rules:
`max_per_failure_domain` caps an app's machines in one failure domain.
Dedicated hosts are a property of the tenant and belong to TS-566.

### Updates and quorum

Updates happen in place: a new version stops and restarts machines on their
hosts; servers are never replaced for an update. Every update rolls back to
the previous version when the new one fails its health checks.

- `all-at-once`, the default of a stateless app, updates every machine
  together.
- `rolling` updates at most `max_unavailable` (default one) machines at a
  time. It is the default, and the only strategy, of a stateful app.

`stateful.quorum` is how many machines of the app in one region must stay
started through updates and scale-in. The leader refuses an app whose
region count minus `max_unavailable` is below its quorum, and a rolling
update waits while the region's started machines minus `max_unavailable`
are below it, so a failed machine and an update together never drop the
quorum.

### Dependencies

`depends_on` names apps that must have a started machine in a region before
this app's machines first start there; it gates first starts only, not
restarts or updates. The leader refuses unknown apps, cycles, and a
dependency that runs no machines in one of the app's regions.

## Runtime drivers

The driver interface is the host's existing
[`host.Runner`](../internal/host/runner.go): `Recover`, `Apply`, `Stop`,
`Observe` and `Close`, keyed by role, applying a `host.Workload`. A
dispatching runner picks the driver from the workload's artifact kind.

- **native**, the default for TerraScale services: the native process
  runner today, and the hardened systemd unit of TS-563's runtime slice
  (`DynamicUser`, CPU and memory limits, `ProtectSystem`, seccomp, private
  `/tmp`).
- **oci**, for software that only ships as an image: rootless podman, one
  container per machine, `--network host` like a native machine, a read-only
  root, all capabilities dropped and `no-new-privileges`, under the host's
  workload cgroup subtree.

Both drivers share, in the host agent rather than in the driver:

- **health**: the agent runs the machine's `checks` against its ports and
  reports it started only when they pass;
- **logs**: the journal, from the unit's output or podman's journald log
  driver;
- **metrics**: cgroup v2 statistics of the machine's cgroup;
- **secrets**: resolved by the agent and passed in the process environment
  (`podman --env NAME` without a value), never on a command line or disk.

## Templates

A template is a spec preset: `ts-orch apply -f` with `"template": "ts-auth"`
starts from the preset and applies the file's fields over it.

- **ts-auth**: a stateless binary, port 8080, `http` checks on `/healthz`
  and `/readyz`, a 45 s drain, two machines with one per failure domain,
  Vault secrets from its profile.
- **terrabase**: a stateful binary with the data volume, its member ports,
  `http` health checks, a 45 s drain, and a rolling update with quorum 2,
  TerraBase's two-member floor per region. Its member certificate and peer
  list need a generic capability, a machine TLS certificate from the cell's
  CA and peers from service discovery, which slice 6 adds; until then the
  host's TerraBase preparation stays.

Their bespoke paths (`operator terrabase-release`, `operator ts-auth-release`,
`host/terrabase.go`, `host/tsauth.go`, the TerraBase-only enrollment and
profile rules and `attempt`'s `ts_auth_profile`) go once their templates
reproduce today's behaviour. So does the cell spec's
[`workload.ServiceSpec`](../internal/workload/spec.go), which apps supersede.

## Slices

1. The spec types and this note.
2. The oci driver behind `host.Runner`, with a dispatching runner.
3. The spec on TS-563's `App` and `MachineConfig`, `services` gaining
   `protocol` and `public`, and the leader's cross checks: quorum against
   counts, root-gated commands and hooks for roles with secrets, and
   dependencies.
4. The host agent runs any spec: files, mounts, hooks, drain and checks.
5. The ts-auth template, and removal of ts-auth's bespoke paths and of
   `workload.ServiceSpec`.
6. The TerraBase template, and removal of TerraBase's bespoke paths.
