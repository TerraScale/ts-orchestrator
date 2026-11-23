<!-- shared-rules:start -->

## Shared TerraScale rules

### Agent rules

- **Never edit any `AGENTS.md` without the user's explicit consent.**
- **Never create `.md` files unless the user explicitly asks for them first.** Prefer updating existing documentation or answering in chat instead.

### Shipping code

- Ship every change as a pull request to `main`. Fetch `origin` first and branch from fresh `origin/main` in your own worktree or clone, outside shared checkouts. Commit small changes; no AI attribution. Ignore outside contributors' PRs unless asked.
- Record non-obvious choices in the commit message as `DECISION: <choice>. Reason: <why>`.
- Before pushing, build or type-check only the project you changed. GitHub CI on the PR is the gate. A PR squash-merges as soon as its checks are green and its review passed; rebase it when it conflicts. Never push directly to, force-push or delete `main`.
- Deploy only green `main`. If your merge makes `main` red, fix or revert within about 30 minutes. For a red `main` you did not cause, wait for its owner's fix and rebase.
- Never run anything on or SSH to `mariogk-desktop`.
- `StorageFormat.cs` bumps and production resets need the user's approval; otherwise put `Needs format bump` in the commit message.

### Code

- **No comments:** no `//`, `#`, `/* */`, `///` doc comments or commented-out code in code, scripts or build files, including code you move or rewrite. Names and types carry the meaning; non-obvious choices go in the commit message as `DECISION:`.
- **Fix the root cause:** no workarounds — no retries, sleeps, longer timeouts, swallowed errors, special cases, flags or skipped or weakened journey steps that hide a symptom. If the cause is outside your task or outside our code, report it instead of patching around it.
- **No legacy:** no deprecated paths, compatibility shims, fallbacks, old-format readers, dead code or copies kept "for now". Replace the old path and delete it in the same change.
- **No tests but the journey:** the only test is the user-journey E2E suite in `terrascale` (runs on every `terrascale` PR against a throwaway environment and after every release against production). Never add unit, integration, contract, Fast or Slow tests, test projects, fakes or fixtures in any repo; delete any you find. A behaviour that matters becomes a journey step. Never skip, weaken or retry a journey test; the only allowed way to stop a flaky test from blocking PRs is quarantine (see `terrascale/e2e/AGENTS.md` "Quarantine": an open issue titled `Flaky journey test: <test>` with label `journey-quarantine` skips it on PRs while `main` still runs and reports it; closing the issue after the real fix ends quarantine). Production monitors (`ts-orchestrator` `multi-region`, `deploy-lag`, `app-canary`) are not tests; keep them. `ts-orchestrator` also keeps its single-host E2E (job `e2e-m1`) as its PR gate.

### CI and proof

- One PR workflow per repo (`ci.yml`); its last job is `all-green`, the one required check. Release, deploy and monitor workflows stay separate.
- Keep CI fast: no test jobs, no duplicate builds, cached toolchains, jobs in parallel.
- The shared CI-time check (`ci-time.yml` in `TerraScale/.github`) runs after every CI run and compares working time (the longest chain of runner execution time, excluding queue wait). A run is slow when working time exceeds the median of the last 5 successful runs with the same jobs by more than 30 s, or a job exceeds the slowest of its own earlier runs by more than 30 s. An issue opens when the same slow signal repeats on the previous run with the same jobs; it never blocks a merge — investigate and fix it like a bug.
- **UI changes:** screenshot every changed page before (`origin/main`) and after (your branch), using the same viewport, data and theme, in every supported theme. Save PNGs outside the repo as `~/.local/state/shots/<branch>/<page>-before.png` and `-after.png`; never commit screenshots. Embed each as a Markdown image with its absolute path (e.g. `![after: /settings](/home/<user>/.local/state/shots/<branch>/settings-after.png)`) in your final reply and list the pages in the PR body.

### Secrets and hard gates

- Runtime secrets: OCI Vault in `gru` via instance principal. CI secrets: GitHub Actions. Ask the user for dev secrets.
- Never expose secret values in chat, arguments, history, logs, git or commits. Use stdin or a `0600` file. Credential installs are one-command handoffs the user runs.
- Ask first before new paid capacity, security permissions or credentials.
- `ts-auth` and `ts-dashboard` store data in TerraBase through `ts-dotnet`; keep the SDK current with TerraBase's API.
- Outside the monorepo, never download or run TerraBase binaries in CI or helpers. Live `ts-status` API monitoring is allowed. Never publish TerraBase binaries.
- Use GitHub and `gh`; no polling loops.

<!-- shared-rules:end -->

# ts-orchestrator

Go orchestrator replacing Kubernetes for TerraScale services. Ship one easy-to-update binary; group related and dependent code by feature.

## Architecture and rules

- Load the `use-modern-go` skill before editing Go code.
- Manage regional OCI resources and scale TerraBase up and down. Regional controllers embed NATS and JetStream; use NATS for orchestrator communication. Regions form their clusters automatically.
- Every feature is always on; every region serves automatically. No feature flags, enabled booleans, opt-in settings, deploy toggles or kill switches. Delete guarded paths. Values have one correct setting in code; no tuning knobs.
- CI rejects switch-style configuration; unavoidable third-party names need a narrow allowance and one-line reason.
- Discover NetBird members, regions, placement and releases automatically; infer node identity from execution location. Keep the bootstrap gap documented in `docs/region-bootstrap.md` rather than claiming it is solved. Create and deliver each service's production credentials automatically through the platform secret integration.

## Layout and checks

- Entry point: `cmd/terrascale-orchestrator`; features: `internal/`; deployment assets: `deploy/`; runbooks: `docs/`; vendored NATS: `third_party/nats-server` (`go.mod` replacement).
- Build: `make build` produces `dist/ts-orch`; `make release-linux` builds Linux amd64/arm64.
- Checks: `make lint` and `make release-check`. The only test is the node E2E (`test/e2e/m1/run.sh`, CI job `e2e-m1`); product behaviour is proven by the journey E2E in `terrascale`.
