# Phase 1 real-NATS L0C foundation handoff

## Delivered

- A 28-case deterministic, machine-readable planned L0C inventory covering dual control/product isolation, JWT/account/subject denials, R3 stream/KV contracts, gateway partitions, duplicate/reorder/ack/redelivery, one-server/quorum loss, both client/server N/N-1 directions, N/N-1 snapshot format behavior, and signed snapshot/replay recovery.
- A dependency-free offline validator with closed object fields and catalogs, a canonical whole-inventory content digest, duplicate-key rejection, repository path containment, every-component no-symlink/regular-file checks, byte/count/string bounds, exact candidate-manifest digest binding, complete category/assertion coverage, and fail-closed candidate-state checks.
- Fifteen data-driven negative mutations—including an otherwise-valid closed-value semantic swap—plus direct duplicate-key, path, leaf/parent symlink, byte, case-count, and string-bound tests.
- An intentionally stale, zero-result report that cannot be confused with current execution or acceptance evidence.

## Pin audit and blockers

The checked candidate manifest has exact version/artifact metadata for two server candidates, two managed client candidates, and one CLI candidate. This is not an executable selected closure:

- every server, client, and CLI `selected` value is false;
- `nMinusOnePolicy` is null and the candidate pair is unexecuted;
- no JWT/NKey generation/administration toolchain is selected or pinned;
- the snapshot signing identity/key technology is unselected;
- the pinned SmolVM host observation is not a qualified hermetic L0C test-toolchain environment;
- internal mirror and independent verification receipts are absent;
- generated credential, permission, account, stream, KV, gateway, and certificate inputs do not yet exist;
- critical sync/RPO values remain owner inputs.

No NATS or JWT process was started, no binary/package was downloaded or selected, and no network, VM, cloud, credential, or production action occurred.

## Nonclaims

This package proves only that a bounded planned case contract remains structurally complete and honestly blocked. It does not prove any NATS behavior, real L0C, ARM64, N/N-1 compatibility, R3 durability, JWT authorization, gateway partition behavior, snapshot recovery, configuration correctness, or production qualification. It does not satisfy any registry acceptance layer and cannot enter pre-deployment evidence.

## Verification

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- nats-l0c
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/nats-l0c/l0c-cases.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/nats-l0c/l0c-report.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/nats-l0c/negative-cases.json
git diff --check
```
