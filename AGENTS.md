<!-- shared-rules:start -->

## Shared TerraScale rules

### Shipping code

- No PRs, reviews or merge queue. Push to `main`. Ignore outside contributors' PRs unless asked.
- Fetch `origin` first. Branch from fresh `origin/main` in your own worktree or clone, outside shared checkouts. Commit small changes; no AI attribution.
- Before every push: `git fetch origin && git rebase origin/main`, then pass the changed area's Fast tests on a dev host with `ts-heavy-any <cmd> --repo <repo> --branch <ref>`. Push `git push origin HEAD:main`; rebase and retry a non-fast-forward rejection. Never force-push or delete `main`.
- CI runs on every main push; deploy only green main. If your push makes main red, fix or revert within about 30 minutes. For a red main you did not cause, wait for its owner's fix and rebase.
- Heavy builds, tests, benchmarks and stress repeats use `ts-heavy-any`, never GitHub Actions. Use mariogk-dev or beta; never run anything on or SSH to mariogk-desktop.
- Fast tests run fully parallel, finish in under 5 minutes and cover only the main features. Everything else goes to Slow; a Fast suite over 5 minutes is a bug.
- Prove flaky fixes with 5 repeats; benchmarks with 3 measured repeats in `benchmark/bench/`. For page changes, report before/after screenshots.
- StorageFormat.cs bumps and production resets belong to the lane in `.cos/lanes.md`; other lanes put `Needs format bump` in the commit message.

### Agents and decisions

- Use gpt-6.1-sol (Codex, high effort; low for work under 10 minutes) for most work. Use claude-haiku-5-5 for bounded work of at most 20 minutes; never Haiku 4.5 or the `haiku` alias. Reserve claude-opus-5-5 for engine/replication, auth/security design, billing correctness, production infrastructure or work Sol already failed.
- Decide and continue. Record `DECISION: <choice>. Reason: <why>` in commits.
- Workers never ask the user. Send the parent `NEED Q-<ID>: <question> | options: 1) <recommended> 2) ... | DECIDED: 1, continuing`. Only the COS asks the user.
- Block only for a user-only secret/login, new paid capacity, or deleting serving infrastructure or unrecoverable data. Start login device flows yourself, show URL/code, then finish after the user enters them.

### Secrets and hard gates

- Runtime secrets: OCI Vault in gru via instance principal. CI secrets: GitHub Actions. Dev secrets: `ts-dev-secret get <name> | <consumer>` or `ts-dev-secret env <name> -- <cmd>`.
- Never expose secret values in chat, arguments, history, logs, git or commits. Use stdin or a 0600 file. Credential installs are one-command handoffs the user runs.
- Ask first before new paid capacity, security permissions or credentials.
- ts-auth and ts-dashboard store data in TerraBase through ts-dotnet; keep the SDK current with TerraBase's API.
- Outside the monorepo, never download or run TerraBase binaries in tests, CI or helpers; use HTTP fakes or contract fixtures. Live ts-status API monitoring is allowed. Never publish TerraBase binaries.
- Use GitHub and `gh`; no polling loops. Never revive ts-reviewer or ts-cos.

<!-- shared-rules:end -->

# ts-orchestrator


- TerraScale's Go orchestrator replaces Kubernetes for its services. Ship one easy-to-update binary. Group related and dependent code by feature.
- Manage regional OCI resources and scale TerraBase up and down. Regional controllers embed NATS and JetStream; use NATS for orchestrator communication. Regions form their clusters automatically.
- Every feature is always on; every region serves automatically. No feature flags, enabled booleans, opt-in settings, deploy toggles or kill switches. Delete guarded paths. Values have one correct setting in code; no tuning knobs. Fakes, demo stores and skip-auth belong only in test binaries.
- Discover NetBird members, regions, placement and releases automatically; infer node identity from execution location. Keep the bootstrap gap documented in `docs/region-bootstrap.md` rather than claiming it is solved. Create and deliver each service's production credentials automatically through the platform secret integration.
- CI rejects switch-style configuration; unavoidable third-party names need a narrow allowance and one-line reason.
- Entry point: `cmd/terrascale-orchestrator`; features: `internal/`; deployment assets: `deploy/`; runbooks: `docs/`; vendored NATS: `third_party/nats-server` (go.mod replacement).
- Build: `make build` produces `dist/ts-orch`; `make release-linux` builds Linux amd64/arm64. `make release-check` validates release binaries.
- Fast pre-push: `make test-fast` (`go test -short ./...`). Full tests: `make test`; race/checks: `make verify` or `make ci-check`. `make generate-check` checks committed templ output; `make generate` regenerates it with the pinned Go tool. Use Makefile toolchain selection through mise when available.
- `make nats-identity-check` runs the separate vendored NATS regression. `make fixturetest-check` validates the fixturetest-only build. Use HTTP fakes and contract fixtures for TerraBase boundaries, per workspace rules.
