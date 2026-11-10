<!-- shared-rules:start -->

## Shared TerraScale rules

### Shipping code

- Ship every change as a pull request to `main`. Fetch `origin` first and branch from fresh `origin/main` in your own worktree or clone, outside shared checkouts. Commit small changes; no AI attribution. Ignore outside contributors' PRs unless asked.
- Record non-obvious choices in the commit message as `DECISION: <choice>. Reason: <why>`.
- Before pushing, build or type-check only the project you changed. GitHub CI on the PR is the gate. A PR squash-merges as soon as its checks are green and its review passed; rebase it when it conflicts. Never push directly to, force-push or delete `main`.
- Deploy only green main. If your merge makes main red, fix or revert within about 30 minutes. For a red main you did not cause, wait for its owner's fix and rebase.
- Never run anything on or SSH to mariogk-desktop.
- StorageFormat.cs bumps and production resets need the user's approval; otherwise put `Needs format bump` in the commit message.

### Code

- No comments: no `//`, `#`, `/* */`, `///` doc comments or commented-out code in code, scripts or build files, including code you move or rewrite. Names and types carry the meaning; non-obvious choices go in the commit message as `DECISION:`.
- Fix the root cause. No workarounds: no retries, sleeps, longer timeouts, swallowed errors, special cases, flags or skipped or weakened journey steps that hide a symptom. If the cause is outside your task or outside our code, report it instead of patching around it.
- No legacy: no deprecated paths, compatibility shims, fallbacks, old-format readers, dead code or copies kept "for now". Replace the old path and delete it in the same change.
- No tests but the journey. The only test is the user-journey E2E suite in terrascale: it runs on every terrascale PR against a throwaway environment and after every release against production. Never add unit, integration, contract, Fast or Slow tests, test projects, fakes or fixtures in any repo; delete any you find. A behaviour that matters becomes a journey step. Production monitors (ts-orchestrator `multi-region`, `deploy-lag`, `app-canary`) are not tests; keep them. ts-orchestrator also keeps its single-host E2E (job `e2e-m1`) as its PR gate.

### CI and proof

- One PR workflow per repo (`ci.yml`); its last job is `all-green`, the one required check. Release, deploy and monitor workflows stay separate.
- CI must be as fast as it can be: no test jobs, no duplicate builds, cached toolchains, jobs in parallel.
- The shared CI-time check (`ci-time.yml` in `TerraScale/.github`) runs after every CI run. A run more than 30 s slower than the median of the last 5 successful runs of the same workflow opens or updates a `CI time regression: <workflow>` issue. It never blocks a merge; investigate the issue and fix the cause like a bug.
- UI changes: screenshot every changed page before (`origin/main`) and after (your branch), same viewport, data and theme, in every supported theme. Save the PNGs outside the repo as `~/.local/state/shots/<branch>/<page>-before.png` and `-after.png`; never commit screenshots. Show them in your T3 thread: if you have T3 tools, `html_render` a before/after grid (absolute local image paths are inlined); otherwise embed each as a Markdown image with its absolute path, e.g. `![after: /settings](/home/<user>/.local/state/shots/<branch>/settings-after.png)`, in your final reply. List the pages in the PR body.

### Secrets and hard gates

- Runtime secrets: OCI Vault in gru via instance principal. CI secrets: GitHub Actions. Ask the user for dev secrets.
- Never expose secret values in chat, arguments, history, logs, git or commits. Use stdin or a 0600 file. Credential installs are one-command handoffs the user runs.
- Ask first before new paid capacity, security permissions or credentials.
- ts-auth and ts-dashboard store data in TerraBase through ts-dotnet; keep the SDK current with TerraBase's API.
- Outside the monorepo, never download or run TerraBase binaries in CI or helpers. Live ts-status API monitoring is allowed. Never publish TerraBase binaries.
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
- Checks: `make lint` and `make release-check`. The only test is the single-host E2E (`test/e2e/m1/run.sh`, CI job `e2e-m1`); product behaviour is proven by the journey E2E in the terrascale repo.
