# Same-host TBEP observation

`Client` calls the actual `MaintenanceService.SupervisionHealth`,
`TopologyRead`, and `AdminStatus` RPCs. Configuration must bind the local host's
admitted TerraBase SPIFFE identity, certificate trust, and authorized database
scope. The endpoint must be a literal loopback IP with a port. A successful
constructor only configures transport. `Observe` requires TLS 1.3, verifies the
server certificate chain and sole exact admitted SPIFFE URI, presents the
client certificate, and sends exactly one principal/tenant/project/database
metadata value. Each observation has one bounded deadline covering all three
calls. Any failed RPC discards the partial sample.

The observation preserves TerraBase's reported state. Serving health does not
prove replication durability, placement acceptance, backup availability, or
lifecycle completion. The wrapper exposes no mutations. Generated stubs contain
the full producer contract, including unrelated RPCs, to avoid maintaining a
handwritten wire subset.

## Contract provenance and generation

`CONTRACT_VERSION` pins an exact producer worktree snapshot. This is **not a
published contract release**. The producer checkout was
`../terrabase` at HEAD `3e9d34e561d193f279a3895ba4554f982e7cb26f`, with local
modifications to `contracts/proto/terrabase/v1/engine.proto`. Both complete proto
assets were copied from `contracts/proto/terrabase/v1/` without modification.

| Asset | SHA256 |
| --- | --- |
| `engine.proto` | `866350008e820aabc3b0e0d90bdf524eaca562c7c04edff5ca518fdf48b291ed` |
| `family.proto` | `cdae480893d6aa1ff8d88af5a352d8e9ab1f59a60fe13d93ca6da387a7a109ec` |

Generation uses protoc 34.1, protoc-gen-go 1.36.12 and
protoc-gen-go-grpc 1.6.2. Install the two Go generators with:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
```

Put the generator installation directory and protoc on `PATH`, then run from
the repository root:

```sh
go generate ./src/orchestrator/tbep
git diff --exit-code -- src/orchestrator/tbep/wire
go test -race ./src/orchestrator/tbep/...
```

The `M` generator options relocate the Go package within this consumer. They
change no protobuf names, fields, or service paths. Production contract release
publication and producer/consumer drift CI remain separate acceptance work.

## Executable observation

Run this on the admitted TerraBase host:

```sh
orchestrator observe-member --config /etc/terrascale/observe-member.json
```

Example configuration:

```json
{
  "endpoint": "127.0.0.1:8421",
  "serverIdentity": "spiffe://terrascale.example/region/GRU/host/member-a/terrabase",
  "tenant": "tenant-a",
  "project": "project-a",
  "database": "database-a",
  "timeout": "5s",
  "certificateFile": "orchestrator.crt",
  "privateKeyFile": "orchestrator.key",
  "trustBundleFile": "member-ca.crt"
}
```

Use identities and scope accepted by the host's admission configuration.
Relative credential paths resolve beside the JSON file. Every field is required;
unknown or duplicate fields fail. The deadline must be positive and at most one
minute. The command prints one JSON object with `serverIdentity`, `observedAt`,
`health`, `topology`, and `admin`. Closed enum values are their protobuf names.
Draining and stopped are observations, not command failures. Failed RPCs print
no partial observation. Failure messages identify the configuration, TLS,
scope, deadline, or output problem without printing certificate/key contents.

This diagnostic dispatches before control-plane configuration. It provides an
executable consumer of real TBEP observations; it does not replace lifecycle
controllers or complete production runtime composition.

## Actual TerraBase transport evidence

On 2026-09-04 at 23:58:08 UTC, a separately spawned actual static
`terrabase-server` and the built orchestrator executable completed the three
observation RPCs over TLS 1.3 mTLS. The server used `mode = "local-development"`,
an isolated temporary engine directory, generated test-only CA and SPIFFE
certificates, and two available loopback ports for TBEP and observability.
The configured scope was `tenant-a` / `project-a` / `database-a`.

The commands were:

```sh
go build -o /tmp/tbep-observe-orchestrator ./cmd/orchestrator
/home/mariogk/Projects/TerraScale/terrabase/target/x86_64-unknown-linux-musl/release/terrabase-server --config /tmp/tbep-real-observation-2469667832/server.toml
/tmp/tbep-observe-orchestrator observe-member --config /tmp/tbep-real-observation-2469667832/observer.json
/tmp/tbep-observe-orchestrator observe-member --config /tmp/tbep-real-observation-2469667832/wrong-host.json
```

The valid invocation exited zero. Its JSON reports `HEALTH_STATE_SERVING`,
`BINDING_KIND_NETWORK_MTLS`, `CLUSTER_MODE_STANDALONE`, registry `1.4`, and
`engineTopologyAvailable: false`. The wrong-host configuration changed only
the admitted server identity to another host. That invocation exited one,
printed the bounded TLS/identity diagnostic, and produced no observation.
SIGTERM stopped the actual server cleanly; a subsequent process inspection
found no remaining server from either attempt.

| Artifact | SHA256 |
| --- | --- |
| Static TerraBase server | `300d71b2c6e446555aa62eb03c04a07937a83503da1c4393da39074a19444aa7` |
| Built observer executable | `4092e203db863df10328fcc54093015480f6a12496264c0cf7358be9a9904148` |
| [Recorded observation](evidence/real-member-observation.json) | `2f903e3b3963e6135711c09a03a39dfbd5d1fe45d269748a7abcd647b6005bbb` |
| [Wrong-host diagnostic](evidence/wrong-host-rejection.txt) | `6f54a494249ab269e44ff6eb6fbc5108ea102c72f3a703556009ef668a0df75e` |

TerraBase's credential loader now accepts padded PEM certificates and keys.
Its `base64` decoder validates each complete PEM block, including padding;
rustls validates the decoded certificates and keys. Producer regression tests
cover all three certificate-length remainders, certificate chains, CRLF,
malformed padding, private-file permissions, and symlink refusal.

A subsequent real-process check used newly generated padded server and client
certificates. The three observation RPCs succeeded, the wrong server identity
was rejected without partial output, `/ready` remained `503` in local-development
mode, and SIGTERM stopped the daemon cleanly. Temporary private keys were removed
with the test directory.

This evidence proves the actual private transport and exact server identity
check in a single local-development process. It does not qualify production
member admission, replication, backups, lifecycle control, Firecracker guests,
or the six-host topology. Portable tests separately cover malformed and
ambiguous configuration, bounded/no-follow regular-file credential reads,
scoped metadata, mTLS failures, cancellation, deadlines, and closed enums.
