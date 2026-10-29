# ts-orchestrator

Shipping: follow the workspace [Shipping code section](/home/mariogk/Projects/TerraScale/AGENTS.md#shipping-code-user-2026-10-29-go-fast-break-things-fast-q-trunk-q-local-check).

- TerraScale's Go orchestrator replaces Kubernetes for its services. Ship one easy-to-update binary. Group related and dependent code by feature.
- Manage regional OCI resources and scale TerraBase up and down. Regional controllers embed NATS and JetStream; use NATS for orchestrator communication. Regions form their clusters automatically.
- Every feature is always on; every region serves automatically. No feature flags, enabled booleans, opt-in settings, deploy toggles or kill switches. Delete guarded paths. Values have one correct setting in code; no tuning knobs. Fakes, demo stores and skip-auth belong only in test binaries.
- Discover NetBird members, regions, placement and releases automatically; infer node identity from execution location. Keep the bootstrap gap documented in `docs/region-bootstrap.md` rather than claiming it is solved. Create and deliver each service's production credentials automatically through the platform secret integration.
- CI rejects switch-style configuration; unavoidable third-party names need a narrow allowance and one-line reason.
- Entry point: `cmd/terrascale-orchestrator`; features: `internal/`; deployment assets: `deploy/`; runbooks: `docs/`; vendored NATS: `third_party/nats-server` (go.mod replacement).
- Build: `make build` produces `dist/ts-orch`; `make release-linux` builds Linux amd64/arm64. `make release-check` validates release binaries.
- Fast pre-push: `make test-fast` (`go test -short ./...`). Full tests: `make test`; race/checks: `make verify` or `make ci-check`. `make generate-check` checks committed templ output; `make generate` regenerates it with the pinned Go tool. Use Makefile toolchain selection through mise when available.
- `make nats-identity-check` runs the separate vendored NATS regression. `make fixturetest-check` validates the fixturetest-only build. Use HTTP fakes and contract fixtures for TerraBase boundaries, per workspace rules.
