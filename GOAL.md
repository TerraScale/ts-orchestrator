# ts-orchestrator goal

## Authority

The [workspace goal](../GOAL.md) is the sole authority for ts-orchestrator.

## Mission

**Our Kubernetes alternative.** Control plane that provisions the OCI cloud
estate, schedules workloads as rootless podman containers on plain hosts, runs
autoscaling, blue-green rollout, routing, identity/certs, and TerraBase member
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
