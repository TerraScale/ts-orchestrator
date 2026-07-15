# Phase 0 runtime/build descriptor and CI policy inventory

- Audit date: 2026-07-13
- Status: observed pinned-tree evidence; policy reconciliation is proposed, not accepted
- Scope: ten sibling product repositories at exact commits
- Safety: read-only Git object/status inspection; no sibling edit, cleanup, workflow, build, deployment, credential, or external mutation

## Coverage boundary

`descriptor-inventory.json` contains 156 first-party descriptors from immutable Git trees. The classifier covers workflows, `.terrascale` delivery descriptors, Dockerfiles and bake graphs, systemd/Compose runtime definitions, .NET projects/solutions/build policy/tool manifests/NuGet locks, Node manifests and lockfiles, Go modules/workspaces/checksums, Rust manifests/locks/toolchains, Python project files, Makefiles, and Pulumi project/stack files. `node_modules`, `vendor`, `bin`, and `obj` trees are explicitly excluded because they are dependency/generated closure rather than first-party descriptor ownership.

The distribution is 77 .NET projects, 20 .NET build-policy files, 11 workflows, 10 Dockerfiles, 9 delivery descriptors, 6 .NET solutions, 6 Node locks, 6 Node manifests, 4 Pulumi files, 2 NuGet/dependency locks, 2 systemd units, 1 Makefile, 1 Go module, and 1 Go checksum.

Standalone scripts are not silently included under the word “descriptor.” Instead, every local script path referenced by a pinned delivery descriptor or workflow is separately resolved to a pinned Git blob. Two such references exist, both in TerraBase: `build/linux/build-server-payload.sh` and `build/linux/build-studio.sh`. Unreferenced standalone scripts are outside this inventory. The generator and validator share the explicit classifier and script-reference rule; deleting a supported file or referenced script from the checked inventory fails validation against the pinned tree.

The audit observed TerraScale.Internals as dirty with 13 status entries and all other canonical sibling checkouts clean. Dirty contents were not inventoried, modified, staged, cleaned, or used for citations. All evidence comes from `git show`/`git ls-tree` at the recorded commit, so owner worktree changes remain preserved and cannot silently change this report.

## Runtime and release coverage

The four admitted application runtime roles are evidenced directly:

- TerraBase: three local members are wired by the pinned Internals AppHost (`TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:38-74`), and TerraBase declares amd64/arm64 server targets.
- API: AppHost resolves and starts the API behind Authentication/TerraBase/NATS readiness (`TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:44-46`, `:87-97`); the deploy descriptor declares amd64 and arm64 targets.
- Authentication: AppHost resolves and starts the service (`TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:41-43`, `:79-86`), but the deploy descriptor has no Authentication test or build target.
- Dashboard: AppHost treats Dashboard as a runtime with API/Auth health ordering (`TerraScale.Internals@3643df207f9f1129c9f677148e6890d436339141:src/Hosting/TerraScale.AppHost/AppHost.cs:50-55`, `:98-113`), and the deploy descriptor contains its build target.

Nine repositories own `.terrascale/deploy.json`; local-only TerraScale.DevHost intentionally has neither one nor a Forgejo workflow. The machine inventory preserves every dependency edge, PR/release profile name, build target, candidate package, and promotion strategy. It does not infer a build artifact from the presence of a project file.

## Observed conflicts

1. `CI-CONFLICT-001`: eight repository policies state that feature PRs intentionally run no Forgejo automation, but each pinned consolidated `.forgejo/workflows/ci.yml` executes policy, static, and build jobs for PRs targeting `develop`. This is an observed contradiction, not evidence that either side has been accepted as authoritative.
2. `CI-CONFLICT-002`: Internals CI documentation names `api-image.yml`, `authentication-image.yml`, and `dashboard-image.yml`, but none exists in the pinned tree; the only primary workflow is consolidated `ci.yml`.
3. `CI-CONFLICT-003`: Authentication is a controlled production runtime, yet Internals has API amd64/arm64 and Dashboard targets only. It also lacks a dedicated Authentication release regression profile.
4. `CI-CONFLICT-004`: TerraBase and Internals promotion strategies still name Flux, Operator still builds Helm, and Infrastructure still builds rendered Kubernetes GitOps. These are historical observed contracts awaiting native replacement gates, not designs to copy into the orchestrator.

The machine document includes exact repo/commit/path/line evidence for each conflict and verifies every range against the pinned blob. It keeps all four conflicts unresolved and all four coverage gaps open.

## Proposed reconciliation—not accepted policy

The strongest direction is affected feature validation, a protected `develop -> main` release qualification, build-once immutable candidates, and exact-candidate promotion, followed by native GitOps only after replacement evidence exists. That direction comes from the Orchestrator proposal; it does not erase contradictory sibling policy or authorize edits.

Before implementation, the delivery owner must choose one feature-validation authority, add exhaustive Authentication tests and dual-architecture build targets, update stale Internals CI documentation, preserve release dependency/health semantics, and sequence Flux/Helm/Kubernetes removal behind the corresponding native regression gates. Owner question 7 still controls the independent orchestrator bootstrap/recovery exception.

## Verification

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- delivery-inventory-generate > /tmp/descriptor-inventory.json
cmp /tmp/descriptor-inventory.json docs/audits/delivery/descriptor-inventory.json
rm -f /tmp/descriptor-inventory.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- delivery-inventory-validate
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format docs/audits/delivery/descriptor-inventory.json
git diff --check
```

Ten adversarial fixtures prove rejection of a missing repository, changed commit pin, omitted descriptor, omitted dependency lock, omitted referenced build script, invented Authentication target, accepted conflict, falsely closed gap, promoted proposal, and dirty-worktree boundary violation.
