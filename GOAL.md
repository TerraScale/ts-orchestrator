# ts-orchestrator goal

## Authority

The [workspace goal](../GOAL.md) is the sole authority for ts-orchestrator.

## Mission

**Our Kubernetes alternative.** Control plane that reconciles the declared OCI
cloud estate, runs signed workload binaries under systemd on plain hosts, and
rolls out blue-green releases, routing, identity/certs, and TerraBase member
placement. NATS JetStream is its control store. Explicit non-goal: implementing
Kubernetes/Nomad/ECS APIs.

## Verification

```bash
gofmt -l .            # must print nothing
go vet ./...
go build ./...
go test ./...
go test -race ./...
```
