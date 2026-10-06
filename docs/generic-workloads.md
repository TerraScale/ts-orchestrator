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
    "mounts": [{"volume": "vol_0123456789abcdef", "path": "/var/lib/store"}],
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
| Volumes | `mounts` and the volume record | TS-567 |
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
moved tag or a registry search list cannot change what runs. The host's last
label starts with a letter, which refuses `localhost` (the runtime's local
store) and every spelling of an IP address (`169.254.169.254`, `127.1`,
`0xa9.0xfe.0xaf.0xfe`, such as the instance metadata service's); a port is
within 1..65535. Every kind goes through the same admission: a trusted
signature and a role grant for the digest.

A command or hook starts with an absolute path in the machine, a path inside
a tarball, or, for an image, a name the image's `PATH` resolves.

### Secrets

Secrets stay [TS-554](secrets.md) refs in the role's cell spec profile, where
only a root can widen them. The spec has no secrets field: every machine of
the role gets the profile's refs, read from OCI Vault at each start into the
process environment only.

Only the platform app named after its role gets the role's profile and
its secrets ([apps and machines](apps-machines.md#trust)). Apps are not
signed, and a command override, hook or exec check could run any program of
the host or the image, such as `/bin/sh -c`, beside those secrets. So that
app starts only programs inside its admitted tarball: every `command`,
`lifecycle` hook and exec check begins with a path inside the archive. A
binary or image app of that name runs its artifact's own entrypoint and
nothing else.

### Files and mounts

`files` are UTF-8 configuration files placed read-only at absolute paths
before the machine starts. No file may equal or contain another, or cover
`/dev`, `/proc`, `/run` or `/sys`. Paths use letters, digits, `.`, `_` and
`-` only, so no path can inject a systemd directive or a podman mount
option. The encoded `MachineSpec` is at most 32 KiB, because every machine
record carries its config and a record is at most 64 KiB.

`mounts` are [managed volumes](managed-volumes.md)' (TS-567): a volume ID
and a path, refusing the same system paths. When `mounts` joins the machine
config, its `Validate` also refuses a mount path that equals or contains a
file's.

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
started through updates and scale-in. Zero suits a single member: it still
updates rolling, never together with anything else, and its update is an
outage. The leader refuses an app whose
region count minus `max_unavailable` is below its quorum (`App.Validate`),
and a rolling
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
2. The spec on TS-563's `App` and `MachineConfig`, with the checks that
   need both: quorum against region counts, and the secret holder's
   programs inside its tarball.
3. The scheduler honours `placement`, `update`, `stateful` and
   `depends_on`, refusing unknown dependencies and cycles.
4. The oci driver behind `host.Runner`, with a dispatching runner.
5. The host agent runs any spec: files, hooks, drain and checks.
6. `services` gain `protocol` and `public`, with TS-563's service
   discovery and the edge reconciler.
7. The ts-auth template, and removal of ts-auth's bespoke paths and of
   `workload.ServiceSpec`.
8. The TerraBase template, and removal of TerraBase's bespoke paths.
