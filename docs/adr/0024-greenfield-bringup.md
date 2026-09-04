# ADR 0024: Greenfield bring-up and residual-resource quarantine

- Status: Accepted greenfield boundary; production qualification remains a gate
- Decision owner: Cloud

## Decision

The first TerraScale estate is created from an empty OCI tenancy. The
orchestrator must not adopt an existing resource, identity, route, bucket,
volume, host, or control store merely because a provider can discover it.

Unknown provider state is held until a scoped read-only observation, positive
TerraScale ownership evidence, and an accountable owner establish what the
resource is and whether a disposition is allowed. Missing credentials,
unavailable tooling, stale observations, and unqueried APIs never imply that
an estate is clean or that deletion is safe.

`bootstrap` creates and verifies the declared GRU estate, installs only the
signed Go binaries through `ts-node`, and hands authority to the running
control plane. `add-region` applies the same declaration, ownership, and
fail-closed rules to SFO and FRA. Neither command authorizes an unscoped
provider mutation.

## Consequences and verification

Provider reconciliation must distinguish absent, creating, healthy, failed,
and indeterminate resources and must never repeat an uncertain destructive
operation. D-67 qualification covers deterministic plan, ownership, and
rollback behavior; D-81 covers the local Firecracker/systemd lifecycle. Real
OCI and Cloudflare qualification must still verify account, identity, quota,
eventual-consistency, and production-performance behavior before launch.

This ADR changes no runtime or cloud state. Its rollback is a Git revert, not
a cloud operation.
