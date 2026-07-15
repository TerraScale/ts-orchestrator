# Phase 1 authority policy completeness handoff

## Result

- Replay now rejects a non-renewal acquisition request whose expected epoch or
  KV revision is below the reducer's persisted high-water truth. Exact equality
  and independently newer truth remain valid.
- Acquire, renew, release, and read initiators reject the last completed request
  identity in an otherwise admissible state. This prevents emitting an intent
  whose observation would be swallowed by the existing duplicate-result path.
- Status admissibility remains earlier: acquisition from leader still returns
  `InvalidTransition`. Common journal/command identity validation remains
  unchanged, and malformed replay events retain structural-error precedence.

## Defect evidence

Before the production changes, a content-valid journal could record winner truth
at epoch 9/revision 20, replay a requested and confirmed acquisition at epoch
5->6/revision 10->11, and then obtain a mutation permit for 6/11. The focused
regression failed because replay returned no error.

Separately, renewal using the just-completed acquisition request ID emitted a
new compare-and-set intent. Its result would then hit `LastCompletedRequestId`
and be ignored, leaving the reducer pending after the external KV mutation. The
focused regression failed because the unexpected CAS intent was present.

## Deterministic coverage

- 1,000 epoch-only, revision-only, and combined high-water regression cases,
  with exact prior-state digest/sequence, error, and zero-output assertions;
- 1,000 exact-equality, revision-advance, and epoch-advance replay/permit cases;
- structural-malformation versus regression and active-lease versus regression
  precedence;
- 1,000 cases for each reused/fresh acquire, renew, release, and read path, with
  every fresh intent and request-event field checked;
- leader-state acquisition precedence, malformed reused payload precedence,
  closed statuses/outcomes/errors/commands/events/intents, and `en-US`, `tr-TR`,
  `ar-SA`, and `ja-JP` digest stability.

## Validation

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
All projects are up-to-date for restore.

dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore -c Release -- --no-progress --treenode-filter '/*/*/AuthorityPolicyCompletenessPropertyTests/*' --output Normal
Passed: 6, Failed: 0, Skipped: 0

dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore -c Release -- --no-progress --output Normal
Passed: 474, Failed: 0, Skipped: 0

dotnet build TerraScale.Orchestrator.slnx --no-restore -c Release -warnaserror
Build succeeded. 0 warnings, 0 errors.

All five Release test executables
Passed: 670, Failed: 0, Skipped: 0 (ControlPlane 474, Contract 24, Model 38, Protocol 65, Scheduler 69).

git diff --check
Passed with no output.
```

## Compatibility and limits

No public DTO, enum value, constructor, digest encoding, or wire surface changed.
The changes narrow only two previously unsafe/stranding inputs. This shard does
not change duplicate observation handling, choose a NATS adapter, or claim a
real lease/CAS integration result.
