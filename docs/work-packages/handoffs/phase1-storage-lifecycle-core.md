# Phase 1 storage lifecycle and expansion core handoff

## Delivered

- Pure, immutable storage identity, authority, intent, and numeric-trace model under `ControlPlane/Storage`.
- Restartable create/classify/format/mount and bounded single-writer reattach authorization. Recognized filesystems require identity proof and cannot enter the formatting path.
- Ordered expansion authorization with persisted checkpoints, caller-declared conflict serialization, checked arithmetic, no shrink, convergence checks, and replay protection for provider extension, guest rescan, and filesystem growth.
- Retention-aware deletion authorization. Permanent retention always holds. Elastic and explicitly disposable volumes require their distinct policy proof plus all common topology, quorum, reference, backup, retention, owner/fence, and audit-readiness proofs.
- Defensive-copy, replay, permutation, culture, wrong-authority, crash-matrix, overflow, disagreement, conflict, retention, and secret-redaction tests.

## Deletion contract interpretation

`PostDeleteAuditReady` is a pre-delete capability/readiness proof and gates the exact `Delete` intent. It is deliberately distinct from `PostDeleteAuditPassed`. Terminal completion requires both observed provider absence and the actual post-delete audit proof. A readiness proof can therefore never masquerade as deletion completion.

## Boundaries

The core contains no device paths, mount or shell commands, callbacks, provider/filesystem SDK types, clock, thresholds, defaults, or I/O. Filesystem, layout, performance/SLO values, forecast, requested growth, retention, and every observation remain explicit caller inputs. The returned intents authorize work but do not execute it.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (112/112).

## Contract gaps

None found within the assigned pure-core boundary. Provider adapters must preserve the exact typed intent scope and persist each proof checkpoint before advancing; that integration is intentionally outside this work package.
