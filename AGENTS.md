<!-- shared-rules:start -->

## Shared TerraScale rules

### Agent rules

- **Never edit any `AGENTS.md` without the user's explicit consent.**
- **Never create `.md` files unless the user explicitly asks for them first.** Prefer updating existing documentation or answering in chat instead.

### Shipping code

- Ship every change as a pull request to `main`. Fetch `origin` first and branch from fresh `origin/main` in your own worktree or clone, outside shared checkouts. Commit small changes; no AI attribution. Ignore outside contributors' PRs unless asked.
- Record non-obvious choices in the commit message as `DECISION: <choice>. Reason: <why>`.
- Before pushing, build or type-check only the project you changed, and run the pre-PR council review before opening the PR. GitHub CI on the PR is the gate. A PR squash-merges as soon as its checks are green and its review passed; rebase it when it conflicts. Never push directly to, force-push or delete `main`.
- Deploy only green `main`. If your merge makes `main` red, fix or revert within about 30 minutes. For a red `main` you did not cause, wait for its owner's fix and rebase.
- Never run anything on or SSH to `mariogk-desktop`.
- `StorageFormat.cs` bumps and production resets need the user's approval; otherwise put `Needs format bump` in the commit message.

### Code

- **No comments:** no `//`, `#`, `/* */`, `///` doc comments or commented-out code in code, scripts or build files, including code you move or rewrite. Names and types carry the meaning; non-obvious choices go in the commit message as `DECISION:`.
- **Fix the root cause:** no workarounds — no retries, sleeps, longer timeouts, swallowed errors, special cases, flags or skipped or weakened journey steps that hide a symptom. If the cause is outside your task or outside our code, report it instead of patching around it.
- **No legacy:** no deprecated paths, compatibility shims, fallbacks, old-format readers, dead code or copies kept "for now". Replace the old path and delete it in the same change.
- **No tests but the journey:** the only test is the user-journey E2E suite in `terrascale` (runs on every `terrascale` PR against a throwaway environment and after every release against production). Never add unit, integration, contract, Fast or Slow tests, test projects, fakes or fixtures in any repo; delete any you find. A behaviour that matters becomes a journey step. Never skip, weaken or retry a journey test; the only allowed way to stop a flaky test from blocking PRs is quarantine (see `terrascale/e2e/AGENTS.md` "Quarantine": an open issue titled `Flaky journey test: <test>` with label `journey-quarantine` skips it on PRs while `main` still runs and reports it; closing the issue after the real fix ends quarantine). Production monitors (`ts-orchestrator` `multi-region`, `deploy-lag`, `app-canary`) are not tests; keep them. `ts-orchestrator` keeps its single-host E2E (`e2e/run.sh`) as a local pre-PR check, not a CI job.

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

Cloudflare Worker control backplane + merged global Atlas discovery (`worker/`) paired with one framework-dependent .NET 11 / C# 15 arch-neutral IL binary (`ts-orch`) running as `ts-orch-agent` and `ts-orch-edge` on OCI nodes and as the operator CLI and MCP server. No manager quorum, no Raft and no NATS.

## Architecture and rules

- Load `workspace/skills/csharp/SKILL.md` before reading, writing or reviewing any C# or `.NET` file. Follow C# 15 specific named `readonly union` results beside each operation (no generic `Results.cs` or `Result<T, ...>` wrappers) with exhaustive `switch` expressions, zero `try`/`catch` in owned code, zero `IOptions<T>`, zero single-implementation interfaces, source-generated `System.Text.Json`, locked NuGet restores and zero warnings (`TreatWarningsAsErrors=true`).
- Keep `src/TsOrch.Protocol/` and `worker/src/protocol.ts` 1:1 in sync.
- Keep `orch.terrascale.tech` (`FleetDO` SQLite, `locationHint: "sam"`, authenticated control plane and built-in Login/Status UI) strictly isolated from `atlas.terrascale.tech` (`AtlasDO` + `ATLAS_KV`, public `/v1/*` contract matching `terrascale/sites/atlas/`). `/atlas/*` and `/auth/dev-login` exist only when `LOCAL_DEV=true` on loopback.
- Every region runs two flat pools: `stateful` (persistent `/var/lib/ts-data` OCI Block Volumes with `prevent_destroy`, auto-tuning VPUs and online auto-grow at >75% sustained 5 min) and `worker` (0..50 stateless VMs, boot-volume only, never preemptible). Runtime secrets stay in OCI Vault via Instance Principal with SHA-256 `configHash` rotation; never store secret values in DO SQLite, logs or git.
- Every feature is always on; every region serves automatically. No feature flags, enabled booleans, opt-in settings, deploy toggles or kill switches; delete guarded paths. Values have one correct setting in code; no tuning knobs.
- Regenerate `worker/src/ui-assets.ts` whenever `worker/ui/login.html` or `worker/ui/index.html` changes so embedded assets stay byte-identical to source HTML.
- Release tags for v2 are `v2-<sha>` prereleases only. Never publish `ci-*` tags from v2; live v1 nodes follow `ci-*` until each region cuts over.

## Layout and checks

- `worker/`: Cloudflare Worker (`src/` backplane + Atlas, `ui/` Login & Status UI, `wrangler.jsonc`). Local dev uses `npm run dev` (`--infer-origin-from-routes=false`).
- `src/`: `TsOrch.Protocol`, `TsOrch.Oci`, `TsOrch.Agent`, `TsOrch.Edge`, `TsOrch.Cli` (operator CLI + `ts-orch mcp`) and `TsOrch.AppHost` (.NET Aspire local stack + `oci-mock`). Single solution `TsOrch.slnx`; build invariants live in `Directory.Build.props`, `Directory.Packages.props`, `.editorconfig`, `BannedSymbols.txt`, `global.json` and `NuGet.config`.
- `deploy/`: declarative production inventory (`fleet.json`, `services/*.json`), cloud-init (`cloud-init/node-boot.sh`, `docker-daemon.json`) and systemd slices/units (`systemd/`).
- `infra/`: OpenTofu (`1.13.9`) static regional OCI foundation (`modules/region`, `modules/geodns`) driven directly by `deploy/fleet.json`.
- Local stack: `dotnet run --project src/TsOrch.AppHost`.
- PR CI is a fast build-only gate: `dotnet`, `worker` and `infra` run in parallel and feed the required `all-green`. `push: main` runs the same builds and then `release` publishes the `v2-<sha>` bundle and deploys the Worker directly, with no `e2e` job.
- Before opening a PR, run `bash e2e/run.sh` locally and get a clean pre-PR council review.
- Checks (the first three run in `.github/workflows/ci.yml` ending in required `all-green`):
  - .NET: `dotnet restore TsOrch.slnx --locked-mode && dotnet format whitespace TsOrch.slnx --verify-no-changes && dotnet build TsOrch.slnx -c Release --no-restore`
  - Worker: `cd worker && npx tsc --noEmit && npx wrangler deploy --dry-run --outdir /tmp/ts-orch-dist`
  - Infra & scripts: `tofu -chdir=infra fmt -check -recursive && tofu -chdir=infra init -backend=false -input=false -lockfile=readonly && tofu -chdir=infra validate && shellcheck -S warning deploy/cloud-init/node-boot.sh deploy/systemd/prepare-data-volume.sh e2e/run.sh scripts/bake-image.sh && systemd-analyze verify deploy/systemd/*.slice deploy/systemd/*.service deploy/systemd/*.timer`
  - E2E: `bash e2e/run.sh`, run locally before every PR (not in CI); product behaviour is proven by the journey E2E in `terrascale`.
