# Historical documentation archives

Created **2026-07-17** when `docs/` was consolidated into fewer living guides.

Nothing in these archives is discarded: every work package, handoff, audit, and retirement ledger entry that previously lived under `docs/` is recoverable at exact original relative paths.

## Contents

| Artifact | What it holds | Approx size |
|---|---|---|
| [`docs-historical-full.tar.xz`](docs-historical-full.tar.xz) | `docs/work-packages/**`, `docs/audits/**`, `docs/retirement/**` at pre-consolidation paths | ~176 KiB compressed |
| [`historical-docs-bundle.md.xz`](historical-docs-bundle.md.xz) | Same text concatenated into one searchable markdown stream (`# FILE: docs/...` markers) | ~195 KiB compressed |
| [`phase0-tools-and-pins.tar.xz`](phase0-tools-and-pins.tar.xz) | Companion Phase 0 `testlab/` pins/NATS fixtures and `tools/phase0`, `tools/mutation`, `tools/nats-l0c`, `tools/traceability` snapshots that shipped with those audits | ~26 KiB compressed |

## How to use

List archive members:

```bash
tar -tJf docs/archive/docs-historical-full.tar.xz | less
xz -dc docs/archive/historical-docs-bundle.md.xz | less
```

Restore a single historical path for review:

```bash
tar -xJf docs/archive/docs-historical-full.tar.xz \
  docs/work-packages/handoffs/phase1-delivery-core.md
```

Search the bundle without full extract:

```bash
xzgrep -n 'MutationAuthorityPermit' docs/archive/historical-docs-bundle.md.xz
```

## Living replacements

| Historical area | Living document |
|---|---|
| `docs/work-packages/*.md` + handoffs | [`../guides/phase1-contracts.md`](../guides/phase1-contracts.md), [`../guides/work-stream-catalog.md`](../guides/work-stream-catalog.md) |
| `docs/audits/**` | [`../guides/phase0-evidence.md`](../guides/phase0-evidence.md) |
| `docs/retirement/workaround-ledger.yaml` | summarized in Phase 0 guide + full YAML in the tar archive |
| Per-ADR draft bodies that already existed | still live under [`../adr/`](../adr/) |

## Integrity note

Archives were produced from the repository tree at consolidation time (git `HEAD` content of those paths). They are **historical evidence**, not machine-validated by the current tooling suite. Living validators only require `docs/adr/readiness-index.yaml` and `docs/decisions/owner-decision-packet.json`.
