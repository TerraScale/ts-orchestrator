# Phase 0 CI descriptor inventory handoff

- Branch: `docs/phase0-ci-descriptor-inventory`
- Changed paths: `docs/audits/delivery/**`, `tools/phase0/delivery-inventory/**`, and this handoff
- Sibling effects: none; all evidence used immutable Git objects
- Workflow/build/deploy execution: none

## Result

The deterministic inventory covers 10 pinned sibling repositories, 156 classified first-party descriptors, 2 referenced local build scripts, 9 delivery summaries, 4 production roles, 4 unresolved policy conflicts, and 4 open coverage gaps. Every descriptor is tied to its repository commit, path, Git blob, mode, and type. Exact line citations for roles and conflicts resolve inside pinned blobs. Ten adversarial fixtures include explicit dependency-lock and referenced-script omissions.

TerraScale.Internals' 13-entry dirty worktree was observed and excluded from evidence. It was not modified, cleaned, staged, or incorporated into the immutable inventory.

Authentication is explicitly represented as a production role with no build target. The document distinguishes all observed workflows/descriptors/policies from the proposed build-once native reconciliation; no proposal is accepted.

## Commands

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- delivery-inventory-generate > /tmp/descriptor-inventory.json
cmp /tmp/descriptor-inventory.json docs/audits/delivery/descriptor-inventory.json
rm -f /tmp/descriptor-inventory.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- delivery-inventory-validate
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format docs/audits/delivery/descriptor-inventory.json
dotnet run --project tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj --no-restore -- --no-progress --output Detailed
git diff --check
```

## Unresolved work

- Choose and document the authoritative feature-PR validation policy.
- Add Authentication test/build/publish targets for both production architectures.
- Reconcile Internals documentation with the consolidated workflow.
- Define the native descriptor v2 and retain semantic dependency/health/promotion behavior.
- Retire Flux/Helm/Kubernetes targets only after linked native replacement tests pass.
- Resolve owner question 7 before accepting an orchestrator bootstrap/recovery workflow.
