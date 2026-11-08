<!-- shared-rules:start -->

## Shared TerraScale rules

### Shipping code

- Ship every change as a pull request to `main`. Fetch `origin` first and branch from fresh `origin/main` in your own worktree or clone, outside shared checkouts. Commit small changes; no AI attribution. Ignore outside contributors' PRs unless asked.
- Record non-obvious choices in the commit message as `DECISION: <choice>. Reason: <why>`.
- Before pushing, build or type-check only the project you changed. Don't run test suites locally: GitHub CI runs them on the PR. A PR squash-merges as soon as its checks are green and its review passed; rebase it when it conflicts. Never push directly to, force-push or delete `main`.
- Deploy only green main. If your merge makes main red, fix or revert within about 30 minutes. For a red main you did not cause, wait for its owner's fix and rebase.
- Never run anything on or SSH to mariogk-desktop.
- StorageFormat.cs bumps and production resets need the user's approval; otherwise put `Needs format bump` in the commit message.

### Tests

- Keep tests few. Fast covers only the happy path and critical paths. Slow keeps only heavy critical tests; delete everything else.
- A new feature adds at most one happy-path and one critical-failure test. Refactors, renames, docs and config changes add none. Deleting low-value tests is welcome.
- Fast tests run fully parallel. Each single test finishes in under 10 s, each area's Fast suite in under 30 s, and every CI test job in under 5 minutes. Anything slower is a bug.
- Prove flaky fixes with 5 repeats; benchmarks with 3 measured repeats in `benchmark/bench/`. For page changes, report before/after screenshots.

### Secrets and hard gates

- Runtime secrets: OCI Vault in gru via instance principal. CI secrets: GitHub Actions. Ask the user for dev secrets.
- Never expose secret values in chat, arguments, history, logs, git or commits. Use stdin or a 0600 file. Credential installs are one-command handoffs the user runs.
- Ask first before new paid capacity, security permissions or credentials.
- ts-auth and ts-dashboard store data in TerraBase through ts-dotnet; keep the SDK current with TerraBase's API.
- Outside the monorepo, never download or run TerraBase binaries in tests, CI or helpers; use HTTP fakes or contract fixtures. Live ts-status API monitoring is allowed. Never publish TerraBase binaries.
- Use GitHub and `gh`; no polling loops.

<!-- shared-rules:end -->

# ts-orchestrator


- TerraScale's Go orchestrator replaces Kubernetes for its services. Ship one easy-to-update binary. Group related and dependent code by feature.
- Manage regional OCI resources and scale TerraBase up and down. Regional controllers embed NATS and JetStream; use NATS for orchestrator communication. Regions form their clusters automatically.
- Every feature is always on; every region serves automatically. No feature flags, enabled booleans, opt-in settings, deploy toggles or kill switches. Delete guarded paths. Values have one correct setting in code; no tuning knobs. Fakes, demo stores and skip-auth belong only in test binaries.
- Discover NetBird members, regions, placement and releases automatically; infer node identity from execution location. Keep the bootstrap gap documented in `docs/region-bootstrap.md` rather than claiming it is solved. Create and deliver each service's production credentials automatically through the platform secret integration.
- CI rejects switch-style configuration; unavoidable third-party names need a narrow allowance and one-line reason.
- Entry point: `cmd/terrascale-orchestrator`; features: `internal/`; deployment assets: `deploy/`; runbooks: `docs/`; vendored NATS: `third_party/nats-server` (go.mod replacement).
- Build: `make build` produces `dist/ts-orch`; `make release-linux` builds Linux amd64/arm64. `make release-check` validates release binaries.
- Fast: `make test-fast` (`go test -short ./...`). Full tests: `make test`; race/checks: `make verify` or `make ci-check`. `make generate-check` checks committed templ output; `make generate` regenerates it with the pinned Go tool. Use Makefile toolchain selection through mise when available. This area's Fast suite must finish in under 30 s wall time; each single test must finish in under 10 s.
- `make nats-identity-check` runs the separate vendored NATS regression. `make fixturetest-check` validates the fixturetest-only build. Use HTTP fakes and contract fixtures for TerraBase boundaries, per workspace rules.
