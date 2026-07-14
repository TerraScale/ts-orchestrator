# Phase 1 real-NATS L0C foundation

## Boundary

- Base: `origin/chore/phase0-bootstrap` at `709347e`.
- This package defines a credential-free, non-executing conformance inventory. It does not start, contact, download, install, select, or qualify NATS, NATS CLI, JWT/NKey tooling, a VM, or any external service.
- Candidate artifact metadata is not a selected toolchain. Full L0C and every acceptance claim remain blocked.

## Allowed paths

- `tools/nats-l0c/**`
- `docs/work-packages/phase1-nats-l0c-foundation.md`
- `docs/work-packages/handoffs/phase1-nats-l0c-foundation.md`

## Deliverable

Provide a deterministic machine-readable L0C case inventory for dual-plane isolation; JWT/account/subject denial; JetStream stream and KV policy; three-region control gateways; duplicate, reorder, acknowledgement, and redelivery behavior; local R3 failure; N/N-1 compatibility; and snapshot/restore recovery.

The dependency-free validator must enforce a closed schema, technical byte/count/string bounds, safe repository-relative regular-file inputs, exact pin-manifest binding, complete category/assertion coverage, and an explicitly stale non-acceptance report. It must fail if candidate metadata is promoted to a selection or if an L0C/ARM64/production claim appears.

## Verification

```text
python3 tools/nats-l0c/validate_l0c_foundation.py
python3 -m unittest discover -s tools/nats-l0c -p 'test_*.py' -v
python3 -m json.tool tools/nats-l0c/l0c-cases.json
python3 -m json.tool tools/nats-l0c/l0c-report.json
git diff --check
```
