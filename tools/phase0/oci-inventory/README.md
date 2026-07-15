# Read-only OCI residual inventory

This Phase 0 tool executes only its hard-coded OCI `list`, metadata `get`, and
cost-report allowlist. OCI stdout and stderr are captured in memory and never
forwarded. The persisted JSON contains counts, hashes, coarse failures, the
exact seven-day UTC window, and redacted command templates.

Inspect the no-call plan:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- oci-inventory --plan
```

Run with the local default profile without changing OCI configuration:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- oci-inventory --live \
  --output docs/audits/oci/phase0-residual-inventory.json
```

The tool reads only the profile's tenancy field to scope list APIs. It never
queries secret contents, keys, auth tokens, private material, or mutation APIs.
Any denied or failed scope prevents an `observed-empty` claim for that category.
Consequently, `oke_absence_proven` is true only when cluster and node-pool lists
succeed in every accessible compartment in every subscribed region.

Run deterministic fixture tests with:

```bash
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```
