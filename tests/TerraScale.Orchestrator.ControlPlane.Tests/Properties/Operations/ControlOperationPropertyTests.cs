using System.Globalization;
using System.Reflection;
using TerraScale.Orchestrator.ControlPlane.Authority;
using TerraScale.Orchestrator.ControlPlane.Operations;
using TerraScale.Orchestrator.ControlPlane.Reconciliation;
using ProviderOutcome = TerraScale.Orchestrator.ControlPlane.Operations.ProviderOutcome;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties.Operations;

public sealed class ControlOperationPropertyTests
{
    private const int Cases = 1_000;
    private const ulong AuthoritySeed = 0xA110C001UL;
    private const ulong OperationSeed = 0x0BADC002UL;
    private const ulong ReconciliationSeed = 0xC0DEC003UL;
    private const ulong CrossCoreSeed = 0xC205C004UL;
    private static readonly DateTimeOffset Start = new(2026, 7, 13, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task AuthorityPropertiesCoverMonotonicFencingSingleWriterReplayAndArithmetic()
    {
        var first = UnderCulture("tr-TR", () => RunAuthority(AuthoritySeed));
        var replay = UnderCulture("ar-SA", () => RunAuthority(AuthoritySeed));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Diversity).IsGreaterThan(500);
        await Assert.That(first.ErrorCodes).IsGreaterThanOrEqualTo(3);
    }

    [Test]
    public async Task OperationPropertiesCoverDurabilityIdentityIdempotencyDeadlineAndObservations()
    {
        var first = UnderCulture("tr-TR", () => RunOperations(OperationSeed));
        var replay = UnderCulture("ar-SA", () => RunOperations(OperationSeed));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Diversity).IsGreaterThan(900);
        await Assert.That(first.ErrorCodes).IsGreaterThanOrEqualTo(6);
    }

    [Test]
    public async Task ReconciliationPropertiesCoverExactOraclesBoundsPermutationAndClosedMutation()
    {
        var first = UnderCulture("tr-TR", () => RunReconciliation(ReconciliationSeed));
        var replay = UnderCulture("ar-SA", () => RunReconciliation(ReconciliationSeed));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Reasons).IsEqualTo(11);
        await Assert.That(first.UniqueIdentities).IsGreaterThan(900);
    }

    [Test]
    public async Task CrossCorePropertiesRequireAuthorityThenDurabilityAndPreserveExactIdentity()
    {
        var first = UnderCulture("tr-TR", () => RunCrossCore(CrossCoreSeed));
        var replay = UnderCulture("ar-SA", () => RunCrossCore(CrossCoreSeed));
        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.Cases).IsEqualTo(Cases);
        await Assert.That(first.Dispatches).IsEqualTo(Cases);
        await Assert.That(first.UniqueOperations).IsGreaterThan(900);
    }

    [Test]
    public async Task DecisionSurfaceAndAuthorityAcceptedOutputsAreConstructionClosed()
    {
        var assembly = typeof(AuthorityEngine).Assembly;
        var surfaces = assembly.GetExportedTypes().Where(type => type.Namespace is
                "TerraScale.Orchestrator.ControlPlane.Authority" or
                "TerraScale.Orchestrator.ControlPlane.Operations" or
                "TerraScale.Orchestrator.ControlPlane.Reconciliation")
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .Where(method => method.Name is "Decide" or "Replay" or "Plan")
                .Select(method => $"{type.FullName}.{method.Name}"))
            .OrderBy(static value => value, StringComparer.Ordinal).ToArray();
        await Assert.That(surfaces).IsEquivalentTo(new[]
        {
            "TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEngine.Decide",
            "TerraScale.Orchestrator.ControlPlane.Authority.AuthorityEngine.Replay",
            "TerraScale.Orchestrator.ControlPlane.Operations.OperationEngine.Decide",
            "TerraScale.Orchestrator.ControlPlane.Operations.OperationEngine.Replay",
            "TerraScale.Orchestrator.ControlPlane.Reconciliation.ReconciliationEngine.Plan",
        });
        await Assert.That(typeof(AuthorityDecision).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(MutationAuthorityPermit).GetConstructors(BindingFlags.Public | BindingFlags.Instance)).IsEmpty();
        await Assert.That(typeof(AuthorityDecision).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Any(static method => method.ReturnType == typeof(AuthorityDecision))).IsFalse();
        await Assert.That(typeof(MutationAuthorityPermit).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Any(static method => method.ReturnType == typeof(MutationAuthorityPermit))).IsFalse();
    }

    [Test]
    public async Task EmbeddedMinimalCorpusIsStrictContentAddressedAndInputDriven()
    {
        var loaded = ControlOperationCorpus.LoadEmbedded();
        await Assert.That(loaded.Code).IsEqualTo(CorpusCode.Accepted);
        await Assert.That(loaded.Entries.Count).IsEqualTo(3);
        foreach (var entry in loaded.Entries)
        {
            await Assert.That(ControlOperationCorpus.Digest(entry)).IsEqualTo(entry.Digest);
            var fingerprint = ReplayCorpus(entry);
            var changedSeed = WithDigest(entry with { Seed = entry.Seed + 1 });
            var changedDelta = WithDigest(entry with { Delta = entry.Delta + 1 });
            var seedLoad = ControlOperationCorpus.Load(CorpusJson(changedSeed));
            var deltaLoad = ControlOperationCorpus.Load(CorpusJson(changedDelta));
            await Assert.That(seedLoad.Code).IsEqualTo(CorpusCode.Accepted);
            await Assert.That(deltaLoad.Code).IsEqualTo(CorpusCode.Accepted);
            await Assert.That(ReplayCorpus(seedLoad.Entries.Single())).IsNotEqualTo(fingerprint);
            await Assert.That(ReplayCorpus(deltaLoad.Entries.Single())).IsNotEqualTo(fingerprint);
            var changedExpected = WithDigest(entry with { Expected = "InvalidInput" });
            await Assert.That(ControlOperationCorpus.Load(CorpusJson(changedExpected)).Code)
                .IsEqualTo(CorpusCode.InvalidSchema);
        }
        var left = new CorpusEntry("x", 1, "a|expected=b", 0, "c", new string('0', 64));
        var right = new CorpusEntry("x", 1, "a", 0, "b|expected=c", new string('0', 64));
        await Assert.That(ControlOperationCorpus.Canonical(left)).IsNotEqualTo(ControlOperationCorpus.Canonical(right));
        await Assert.That(ControlOperationCorpus.Load("{\"version\":2,\"entries\":[]}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load("{\"version\":1,\"entries\":[]}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load("{\"version\":1,\"unknown\":[]}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        const string validEntry = "{\"family\":\"authority\",\"seed\":17,\"mutation\":\"stale-cas-request\",\"delta\":1," +
            "\"expected\":\"StaleObservation\",\"digest\":\"474376cdb563fac9a075b6447255a53e9124ec24d5b98273cbaa7e0bda300eb0\"}";
        await Assert.That(ControlOperationCorpus.Load($"{{\"version\":1,\"entries\":[{validEntry}]}}"
            .Replace("474376", "574376", StringComparison.Ordinal)).Code).IsEqualTo(CorpusCode.InvalidDigest);
        await Assert.That(ControlOperationCorpus.Load($"{{\"version\":1,\"version\":1,\"entries\":[{validEntry}]}}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load($"{{\"version\":1,\"entries\":[{validEntry},{validEntry}]}}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load($"{{\"version\":1,\"entries\":[{string.Join(',', Enumerable.Repeat(validEntry, 65))}]}}").Code)
            .IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load("{\"version\":1,\"entries\":[[[[[[[[[0]]]]]]]]]}").Code)
            .IsEqualTo(CorpusCode.InvalidJson);
        var unbounded = WithDigest(loaded.Entries[0] with { Delta = 65 });
        await Assert.That(ControlOperationCorpus.Load(CorpusJson(unbounded)).Code).IsEqualTo(CorpusCode.InvalidSchema);
        var unknownFamily = WithDigest(loaded.Entries[0] with { Family = "scheduler" });
        await Assert.That(ControlOperationCorpus.Load(CorpusJson(unknownFamily)).Code).IsEqualTo(CorpusCode.InvalidSchema);
        await Assert.That(ControlOperationCorpus.Load(new string('x', 32_769)).Code).IsEqualTo(CorpusCode.TooLarge);
        await Assert.That(ControlOperationCorpus.Load("{").Code).IsEqualTo(CorpusCode.InvalidJson);
    }

    private static PropertySummary RunAuthority(ulong seed)
    {
        var generator = new Generator(seed); var epochs = new HashSet<long>(); var codes = new HashSet<AuthorityErrorCode>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var epoch = generator.NextInt(900_000) + 1L; var revision = generator.NextInt(900_000) + 1L;
            var candidate = $"candidate-{index}-{generator.NextInt(100_000)}"; var request = $"acquire-{index}";
            var baseline = new AuthorityObservation("regional-authority", revision, epoch, $"baseline-{index}", null);
            var health = Healthy(Start.AddSeconds(index), TimeSpan.FromSeconds(index % 240));
            var acquire = AuthorityEngine.Decide([], new AcquireAuthority("regional-authority", candidate, request,
                $"lease-{index}", baseline, health, TimeSpan.FromMinutes(5)));
            Require(acquire.Errors.Count == 0 && acquire.MutationPermit is null && acquire.Intents.Single() is CompareAndSetLeaseIntent,
                "authority-acquire", index);
            var intent = (CompareAndSetLeaseIntent)acquire.Intents.Single();
            Require(intent.ExpectedEpoch == epoch && intent.ExpectedRevision == revision &&
                intent.ProposedEpoch == checked(epoch + 1), "authority-monotonic", index);
            var history = acquire.EventsToAppend.ToList();
            var observation = new AuthorityObservation("regional-authority", revision + 1, epoch + 1,
                $"confirmed-{index}", intent.ProposedLease);
            var confirmed = AuthorityEngine.Decide(history, new ObserveAuthorityCas("regional-authority", candidate,
                request, AuthorityCasOutcome.Succeeded, observation, health));
            Require(confirmed.Errors.Count == 0 && confirmed.MutationPermit is not null &&
                confirmed.MutationPermit.CandidateId == candidate && confirmed.MutationPermit.Epoch == epoch + 1 &&
                confirmed.MutationPermit.KvRevision == revision + 1, "authority-confirm", index);
            history.AddRange(confirmed.EventsToAppend);
            var restored = AuthorityEngine.Replay(history.AsEnumerable().Reverse().Concat(history).ToArray());
            Require(restored.Errors.Count == 0 && AuthorityDigest.State(restored.State) == AuthorityDigest.State(confirmed.State),
                "authority-replay", index);

            var otherLease = new AuthorityLease($"other-{index}", $"other-lease-{index}", health.ServerTime, TimeSpan.FromMinutes(5));
            var higher = new AuthorityObservation("regional-authority", revision + 2, epoch + 2,
                $"higher-{index}", otherLease);
            var fenced = AuthorityEngine.Decide(history, new EvaluateMutationAuthority("regional-authority", candidate,
                $"evaluate-{index}", higher, health));
            Require(fenced.MutationPermit is null && fenced.State.Status == AuthorityStatus.Fenced &&
                fenced.Errors.Single().Code == AuthorityErrorCode.EpochMismatch, "authority-single-writer", index);
            codes.Add(fenced.Errors.Single().Code);

            var overflowBaseline = baseline with { Epoch = index % 2 == 0 ? long.MaxValue : epoch,
                KvRevision = index % 2 == 0 ? revision : long.MaxValue };
            var overflow = AuthorityEngine.Decide([], new AcquireAuthority("regional-authority", candidate,
                $"overflow-{index}", $"overflow-lease-{index}", overflowBaseline, health, TimeSpan.FromMinutes(5)));
            Require(overflow.MutationPermit is null && overflow.Intents.Count == 0 &&
                overflow.Errors.Single().Code == AuthorityErrorCode.ArithmeticOverflow, "authority-overflow", index);
            codes.Add(overflow.Errors.Single().Code);
            var unknown = AuthorityEngine.Decide(history, new ObserveAuthorityCas("regional-authority", candidate,
                $"stale-{index}", (AuthorityCasOutcome)99, null, health));
            Require(unknown.MutationPermit is null && unknown.Errors.Count == 1, "authority-unknown", index);
            codes.Add(unknown.Errors.Single().Code);
            Require(!unknown.Errors.Single().Message.Contains(candidate, StringComparison.Ordinal), "authority-secret", index);
            epochs.Add(epoch); digest = Mix(digest, confirmed.DecisionDigest);
        }
        return new(Cases, epochs.Count, codes.Count, digest);
    }

    private static PropertySummary RunOperations(ulong seed)
    {
        var generator = new Generator(seed); var identities = new HashSet<string>(StringComparer.Ordinal);
        var codes = new HashSet<OperationErrorCode>(); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var operation = $"operation-{index}-{generator.NextInt(1_000_000)}"; var generation = generator.NextInt(100_000) + 1L;
            var epoch = generator.NextInt(100_000) + 10L; var target = $"node-{index}";
            var desired = Desired(operation, generation, target, index); var expected = Observation(generation, target, $"expected-{index}", "rv-1");
            var prepare = new PrepareOperation(operation, epoch, Start, desired, expected, ["observe-only", "quarantine"]);
            var prepared = OperationEngine.Decide([], prepare);
            Require(prepared.Errors.Count == 0 && prepared.Intents.Count == 0 && prepared.State.Checkpoint == OperationCheckpoint.Prepared,
                "operation-durable-prepare", index);
            var duplicatePrepare = OperationEngine.Decide(prepared.EventsToAppend, prepare);
            Require(duplicatePrepare.Errors.Count == 0 && duplicatePrepare.EventsToAppend.Count == 0, "operation-prepare-idempotent", index);
            var premature = OperationEngine.Decide(prepared.EventsToAppend,
                new RecordDispatch(operation, epoch + 2, Start.AddMinutes(2), $"executor-{index}", 1));
            Require(premature.Intents.Count == 0 && premature.Errors.Single().Code == OperationErrorCode.InvalidTransition,
                "operation-durable-before-dispatch", index); codes.Add(premature.Errors.Single().Code);

            var fresh = Observation(generation, target, $"fresh-{index}", "rv-2");
            var authorize = new AuthorizeOperation(operation, epoch + 1, Start.AddMinutes(1), Evidence(fresh));
            var deniedAuthorization = OperationEngine.Decide(prepared.EventsToAppend,
                authorize with { Evidence = Evidence(fresh) with { BudgetSatisfied = false } });
            Require(deniedAuthorization.Intents.Count == 0 &&
                deniedAuthorization.Errors.Single().Code == OperationErrorCode.AuthorizationDenied,
                "operation-authorization-denied", index);
            codes.Add(deniedAuthorization.Errors.Single().Code);
            var authorizedHistory = Add(prepared.EventsToAppend, authorize);
            var dispatchCommand = new RecordDispatch(operation, epoch + 2, Start.AddMinutes(2), $"executor-{index}", 1);
            var dispatch = OperationEngine.Decide(authorizedHistory, dispatchCommand);
            var intent = dispatch.Intents.Single() as DispatchProviderIntent;
            Require(dispatch.Errors.Count == 0 && dispatch.EventsToAppend.Count == 1 && intent is not null &&
                intent.OperationId == operation && intent.TargetIdentity == target && intent.IdempotencyKey == desired.IdempotencyKey &&
                intent.AuthorizingEpoch == epoch + 1 && intent.ExecutorEpoch == epoch + 2,
                "operation-exact-dispatch", index);
            var dispatchedHistory = authorizedHistory.Concat(dispatch.EventsToAppend).ToList();
            var retry = OperationEngine.Decide(dispatchedHistory, dispatchCommand);
            Require(retry.Errors.Count == 0 && retry.EventsToAppend.Count == 0 && retry.Intents.Single() is DispatchProviderIntent,
                "operation-dispatch-idempotent", index);

            var unknownCommand = new RecordObservation(operation, epoch + 2, Start.AddMinutes(3), $"unknown-{index}", target,
                generation, "unknown", ProviderOutcome.Unknown, null);
            var unknown = OperationEngine.Decide(dispatchedHistory, unknownCommand);
            Require(unknown.Errors.Count == 0 && unknown.Intents.Single() is ReconcileProviderIntent &&
                unknown.Intents.All(static value => value is not DispatchProviderIntent), "operation-unknown", index);
            var unknownHistory = dispatchedHistory.Concat(unknown.EventsToAppend).ToList();
            var duplicateUnknown = OperationEngine.Decide(unknownHistory, unknownCommand);
            Require(duplicateUnknown.Errors.Count == 0 && duplicateUnknown.EventsToAppend.Count == 0 &&
                duplicateUnknown.Intents.Single() is ReconcileProviderIntent,
                "operation-observation-idempotent", index);
            var blindRetry = OperationEngine.Decide(unknownHistory, dispatchCommand with { Now = Start.AddMinutes(4) });
            Require(blindRetry.Intents.Count == 0 && blindRetry.Errors.Single().Code == OperationErrorCode.IdempotencyConflict,
                "operation-no-blind-retry", index); codes.Add(blindRetry.Errors.Single().Code);
            var inconsistent = OperationEngine.Decide(dispatchedHistory, new RecordObservation(operation, epoch + 2,
                Start.AddMinutes(3), $"wrong-{index}", $"other-{target}", generation + 1, "running",
                ProviderOutcome.Succeeded, $"work-{index}"));
            Require(inconsistent.Errors.Count == 0 && inconsistent.State.Observation!.Outcome == ProviderOutcome.Inconsistent &&
                inconsistent.Intents.Count == 0, "operation-stale-observation", index);

            var successfulObservation = new RecordObservation(operation, epoch + 2, Start.AddMinutes(3),
                $"success-{index}", target, generation, "running", ProviderOutcome.Succeeded, $"work-{index}");
            var observedHistory = Add(dispatchedHistory, successfulObservation);
            var terminalCommand = new RecordTerminal(operation, epoch + 2, Start.AddMinutes(4),
                ProviderOutcome.Succeeded, "running");
            var terminalHistory = Add(observedHistory, terminalCommand);
            var duplicateTerminal = OperationEngine.Decide(terminalHistory, terminalCommand);
            Require(duplicateTerminal.Errors.Count == 0 && duplicateTerminal.EventsToAppend.Count == 0 &&
                duplicateTerminal.State.Checkpoint == OperationCheckpoint.Terminal,
                "operation-terminal-idempotent", index);
            var conflictingTerminal = OperationEngine.Decide(terminalHistory,
                terminalCommand with { Outcome = ProviderOutcome.Failed });
            Require(conflictingTerminal.Intents.Count == 0 &&
                conflictingTerminal.Errors.Single().Code == OperationErrorCode.ConflictingTerminalObservation,
                "operation-terminal-closed", index);
            codes.Add(conflictingTerminal.Errors.Single().Code);

            var deadline = OperationEngine.Decide(authorizedHistory, dispatchCommand with { Now = desired.Deadline });
            Require(deadline.Intents.Count == 0 && deadline.Errors.Single().Code == OperationErrorCode.DeadlineExpired &&
                deadline.State.ResumableCheckpoint == OperationCheckpoint.Authorized, "operation-deadline", index);
            codes.Add(deadline.Errors.Single().Code);
            var invalidOutcome = OperationEngine.Decide(dispatchedHistory, new RecordObservation(operation, epoch + 2,
                Start.AddMinutes(3), $"invalid-{index}", target, generation, "running", (ProviderOutcome)99, null));
            Require(invalidOutcome.EventsToAppend.Count == 0 && invalidOutcome.Errors.Single().Code == OperationErrorCode.InvalidInput,
                "operation-unknown-enum", index); codes.Add(invalidOutcome.Errors.Single().Code);
            var replay = OperationEngine.Replay(dispatchedHistory.AsEnumerable().Reverse().Concat(dispatchedHistory).ToArray());
            Require(replay.Errors.Count == 0 && OperationDigest.State(replay.State) == OperationDigest.State(dispatch.State) &&
                replay.State.PermittedCompensations.SequenceEqual(["observe-only", "quarantine"], StringComparer.Ordinal),
                "operation-replay", index);
            var conflict = OperationEngine.Decide(dispatchedHistory, dispatchCommand with { Attempt = 2 });
            Require(conflict.Errors.Single().Code == OperationErrorCode.IdempotencyConflict, "operation-conflict", index);
            codes.Add(conflict.Errors.Single().Code);
            var staleWriter = OperationEngine.Decide(dispatchedHistory, dispatchCommand with { WriterEpoch = epoch });
            Require(staleWriter.Errors.Single().Code == OperationErrorCode.StaleWriterEpoch, "operation-stale-writer", index);
            codes.Add(staleWriter.Errors.Single().Code);
            Require(!staleWriter.Errors.Single().Message.Contains(operation, StringComparison.Ordinal), "operation-secret", index);
            identities.Add(operation); digest = Mix(digest, dispatch.DecisionDigest);
        }
        return new(Cases, identities.Count, codes.Count, digest);
    }

    private static ReconciliationSummary RunReconciliation(ulong seed)
    {
        var generator = new Generator(seed); var identities = new HashSet<string>(StringComparer.Ordinal);
        var reasons = new HashSet<string>(StringComparer.Ordinal); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var prefix = $"r{index}-{generator.NextInt(1_000_000)}"; identities.Add(prefix);
            var a = DesiredResourceOf($"{prefix}-a"); var b = DesiredResourceOf($"{prefix}-b", a.Identity.Value);
            var c = DesiredResourceOf($"{prefix}-c", b.Identity.Value); var desired = new[] { c, a, b };
            var observed = desired.Select(Exact).ToArray(); var mode = index % 11; ReconciliationPlan plan;
            switch (mode)
            {
                case 0: plan = Plan(desired, observed); Require(plan.Steps.All(static step => step.Output is ConvergedResource), "reconcile-exact", index); reasons.Add("exact"); break;
                case 1: observed[1] = Exact(a) with { Generation = 1, Digest = "old" }; plan = Plan(desired, observed);
                    Require(plan.Steps.Single(step => step.Desired.Identity == a.Identity).Output is ReconcileResourceIntent &&
                        plan.Steps.Where(step => step.Desired.Identity != a.Identity).All(static step => step.Output is HoldResource), "reconcile-drift", index); reasons.Add("drift"); break;
                case 2: plan = Plan(desired, observed.Where(value => value.Identity != a.Identity)); Require(plan.Steps.Single(step => step.Desired.Identity == a.Identity).Output is ObserveResourceIntent, "reconcile-missing", index); reasons.Add("missing"); break;
                case 3: observed[1] = Exact(a) with { FreshnessSequence = 9 }; plan = Plan(desired, observed); Require(plan.Steps.Single(step => step.Desired.Identity == a.Identity).Output is ObserveResourceIntent, "reconcile-stale", index); reasons.Add("stale"); break;
                case 4: observed[1] = Exact(a) with { Generation = 3, Digest = "future" }; plan = Plan(desired, observed); Require(Hold(plan, a).Reason == ReconciliationReasonCode.FutureObservation, "reconcile-future", index); reasons.Add("future"); break;
                case 5: observed[1] = Exact(a) with { Digest = "conflict" }; plan = Plan(desired, observed); Require(Hold(plan, a).Reason == ReconciliationReasonCode.ConflictingObservation, "reconcile-conflict", index); reasons.Add("conflict"); break;
                case 6: observed[1] = Exact(a) with { Condition = ObservedCondition.Failed }; plan = Plan(desired, observed); Require(Hold(plan, a).Reason == ReconciliationReasonCode.FailedObservation, "reconcile-failed", index); reasons.Add("failed"); break;
                case 7: observed[1] = Exact(a) with { Condition = ObservedCondition.Held }; plan = Plan(desired, observed); Require(Hold(plan, a).Reason == ReconciliationReasonCode.HeldObservation, "reconcile-held", index); reasons.Add("held"); break;
                case 8: var x = DesiredResourceOf($"{prefix}-x", $"{prefix}-y"); var y = DesiredResourceOf($"{prefix}-y", $"{prefix}-x"); plan = Plan([x, y], [Exact(x), Exact(y)]); Require(plan.Steps.All(static step => step.Output is HoldResource), "reconcile-cycle", index); reasons.Add("cycle"); break;
                case 9: var missing = DesiredResourceOf($"{prefix}-m", "absent"); plan = Plan([missing], [Exact(missing)]); Require(plan.Steps.Single().Output is HoldResource, "reconcile-missing-dependency", index); reasons.Add("missing-dependency"); break;
                default: plan = Plan([a, a], []); Require(plan.Steps.Count == 0 && plan.Errors.Any(static error => error.Code == ReconciliationErrorCode.DuplicateResource), "reconcile-duplicate", index); reasons.Add("duplicate"); break;
            }
            var permutedObserved = mode == 2
                ? observed.Where(value => value.Identity != a.Identity)
                : observed;
            var permuted = mode <= 7 ? Plan(desired.Reverse(), permutedObserved.Reverse()) : plan;
            if (mode <= 7) Require(Signature(plan) == Signature(permuted), "reconcile-permutation", index);
            if (mode <= 7) Require(plan.Steps.All(step => step.Output.Identity == step.Desired.Identity &&
                step.Output.Generation == step.Desired.Generation && step.Output.Digest == step.Desired.Digest), "reconcile-identity", index);
            var bound = ReconciliationEngine.Plan(new ReconciliationRequest(desired, observed, Policy(maximumResources: 2)));
            Require(bound.Steps.Count == 0 && bound.Errors.Any(static error => error.Code == ReconciliationErrorCode.ResourceLimitExceeded), "reconcile-bound", index);
            digest = Mix(digest, Signature(plan));
        }
        return new(Cases, identities.Count, reasons.Count, digest);
    }

    private static CrossSummary RunCrossCore(ulong seed)
    {
        var generator = new Generator(seed); var operations = new HashSet<string>(StringComparer.Ordinal); ulong digest = 0;
        for (var index = 0; index < Cases; index++)
        {
            var operation = $"cross-{index}-{generator.NextInt(1_000_000)}"; operations.Add(operation);
            var baseline = new AuthorityObservation("regional-authority", index + 1, index + 1, $"baseline-{index}", null);
            var health = Healthy(Start.AddSeconds(index), TimeSpan.FromSeconds(index % 240));
            var pending = AuthorityEngine.Decide([], new AcquireAuthority("regional-authority", $"candidate-{index}",
                $"acquire-{index}", $"lease-{index}", baseline, health, TimeSpan.FromMinutes(5)));
            Require(pending.MutationPermit is null, "cross-pending", index);
            var cas = (CompareAndSetLeaseIntent)pending.Intents.Single();
            var confirmed = AuthorityEngine.Decide(pending.EventsToAppend, new ObserveAuthorityCas("regional-authority",
                $"candidate-{index}", $"acquire-{index}", AuthorityCasOutcome.Succeeded,
                new AuthorityObservation("regional-authority", baseline.KvRevision + 1, cas.ProposedEpoch,
                    $"confirmed-{index}", cas.ProposedLease), health));
            var permit = confirmed.MutationPermit; Require(permit is not null, "cross-permit", index);
            var target = $"node-{index}"; var generation = index + 2L;
            var desired = Desired(operation, generation, target, index);
            var expected = Observation(generation, target, $"expected-{index}", "rv-1");
            var prepared = OperationEngine.Decide([], new PrepareOperation(operation, permit!.Epoch, Start,
                desired, expected, ["observe-only"]));
            var denied = OperationEngine.Decide(prepared.EventsToAppend,
                new RecordDispatch(operation, permit.Epoch, Start.AddMinutes(1), $"executor-{index}", 1));
            Require(denied.Intents.Count == 0, "cross-no-dispatch-before-auth", index);
            var authorized = Add(prepared.EventsToAppend, new AuthorizeOperation(operation, permit.Epoch,
                Start.AddMinutes(1), Evidence(Observation(generation, target, $"fresh-{index}", "rv-2"))));
            var dispatched = OperationEngine.Decide(authorized, new RecordDispatch(operation, permit.Epoch + 1,
                Start.AddMinutes(2), $"executor-{index}", 1));
            var dispatch = (DispatchProviderIntent)dispatched.Intents.Single();
            Require(dispatch.OperationId == operation && dispatch.TargetIdentity == target &&
                dispatch.AuthorizingEpoch == permit.Epoch, "cross-exact-dispatch", index);
            var resource = new DesiredResource(new(target), "node", generation, desired.PayloadDigest, []);
            var plan = ReconciliationEngine.Plan(new ReconciliationRequest([resource],
                [new(resource.Identity, resource.Kind, 1, "old", $"observation-{index}", 10, ObservedCondition.Ready)],
                Policy(["node"])));
            var intent = plan.Steps.Single().Output as ReconcileResourceIntent;
            Require(intent is not null && intent.Identity.Value == dispatch.TargetIdentity &&
                intent.Generation == desired.Generation && intent.Digest == dispatch.PayloadDigest,
                "cross-reconciliation-binding", index);
            digest = Mix(digest, dispatched.DecisionDigest);
        }
        return new(Cases, Cases, operations.Count, digest);
    }

    private static string ReplayCorpus(CorpusEntry entry)
    {
        var repetitions = (int)(entry.Seed % 5) + 2;
        string? fingerprint = null;
        for (var replay = 0; replay < repetitions; replay++)
        {
            string observed;
            switch (entry.Family, entry.Mutation)
            {
                case ("authority", "stale-cas-request"):
                    var health = Healthy(Start, TimeSpan.Zero);
                    var baseline = new AuthorityObservation("regional-authority", entry.Seed + entry.Delta,
                        entry.Seed, $"baseline-{entry.Seed}", null);
                    var pending = AuthorityEngine.Decide([], new AcquireAuthority("regional-authority",
                        $"candidate-{entry.Seed}", $"request-{entry.Seed}", $"lease-{entry.Seed}", baseline,
                        health, TimeSpan.FromMinutes(5)));
                    Require(pending.Errors.Count == 0, "corpus-authority-setup", entry.Seed);
                    var authority = AuthorityEngine.Decide(pending.EventsToAppend, new ObserveAuthorityCas(
                        "regional-authority", $"candidate-{entry.Seed}", $"request-{entry.Seed + entry.Delta}",
                        AuthorityCasOutcome.Succeeded, null, health));
                    observed = authority.Errors.Single().Code.ToString();
                    Require(observed == entry.Expected, "corpus-authority", entry.Seed);
                    observed = $"{observed}|{pending.State.JournalDigest}|{baseline.Epoch}|{baseline.KvRevision}";
                    break;
                case ("operations", "dispatch-before-authorization"):
                    var operationId = $"operation-{entry.Seed}"; var target = $"node-{entry.Seed}";
                    var prepared = OperationEngine.Decide([], new PrepareOperation(operationId, entry.Seed, Start,
                        Desired(operationId, entry.Delta, target, checked((int)entry.Seed)),
                        Observation(entry.Delta, target, $"expected-{entry.Seed}", "rv-1"), ["observe-only"]));
                    Require(prepared.Errors.Count == 0, "corpus-operation-setup", entry.Seed);
                    var operation = OperationEngine.Decide(prepared.EventsToAppend, new RecordDispatch(operationId,
                        entry.Seed + entry.Delta, Start.AddMinutes(1), $"executor-{entry.Seed}", 1));
                    observed = operation.Errors.Single().Code.ToString();
                    Require(observed == entry.Expected, "corpus-operation", entry.Seed);
                    observed = $"{observed}|{prepared.State.JournalDigest}|{entry.Seed}|{entry.Delta}";
                    break;
                case ("reconciliation", "future-observation"):
                    var desired = new DesiredResource(new($"resource-{entry.Seed}"), "service", entry.Seed,
                        $"digest-{entry.Seed}", []);
                    var future = Exact(desired) with { Generation = desired.Generation + entry.Delta,
                        Digest = "future" };
                    var plan = Plan([desired], [future]);
                    observed = ((HoldResource)plan.Steps.Single().Output).Reason.ToString();
                    Require(observed == entry.Expected, "corpus-reconciliation", entry.Seed);
                    observed = $"{observed}|{desired.Identity.Value}|{desired.Generation}|{future.Generation}";
                    break;
                default: throw new InvalidOperationException("Unknown bounded corpus mutation.");
            }
            fingerprint ??= observed;
            Require(fingerprint == observed, "corpus-replay", entry.Seed);
        }
        return fingerprint!;
    }

    private static CorpusEntry WithDigest(CorpusEntry entry) => entry with { Digest = ControlOperationCorpus.Digest(entry) };
    private static string CorpusJson(CorpusEntry entry) =>
        $"{{\"version\":1,\"entries\":[{{\"family\":\"{entry.Family}\",\"seed\":{entry.Seed.ToString(CultureInfo.InvariantCulture)}," +
        $"\"mutation\":\"{entry.Mutation}\",\"delta\":{entry.Delta.ToString(CultureInfo.InvariantCulture)}," +
        $"\"expected\":\"{entry.Expected}\",\"digest\":\"{entry.Digest}\"}}]}}";

    private static AuthorityHealth Healthy(DateTimeOffset time, TimeSpan elapsed) => new(time, elapsed, true, true);
    private static DesiredOperation Desired(string operation, long generation, string target, int index) => new(
        $"aggregate-{index}", generation, $"desired-rv-{generation}", "create-node", target, "running",
        $"payload-{operation}", $"idempotency-{operation}", Start.AddMinutes(10));
    private static ObservedResource Observation(long generation, string target, string observation, string version) => new(
        target.Replace("node", "aggregate", StringComparison.Ordinal), generation, version, observation, target, "absent", true);
    private static AuthorizationEvidence Evidence(ObservedResource observation) => new(observation,
        "approval-digest", "evidence-digest", true, true, true, true);
    private static List<OperationEvent> Add(IEnumerable<OperationEvent> history, OperationCommand command)
    {
        var result = history.ToList(); var decision = OperationEngine.Decide(result, command);
        Require(decision.Errors.Count == 0, "operation-add", result.Count); result.AddRange(decision.EventsToAppend); return result;
    }
    private static DesiredResource DesiredResourceOf(string identity, params string[] dependencies) => new(
        new(identity), "service", 2, $"digest-{identity}", dependencies.Select(static value => new ResourceIdentity(value)));
    private static ObservedResourceState Exact(DesiredResource resource) => new(resource.Identity, resource.Kind,
        resource.Generation, resource.Digest, $"observation-{resource.Identity.Value}", 10, ObservedCondition.Ready);
    private static ReconciliationPolicy Policy(IEnumerable<string>? kinds = null, int maximumResources = 8) => new(
        kinds ?? ["service"], new Dictionary<ResourceIdentity, long>(), maximumResources, 96, 32, 128, 96, 8, 10);
    private static ReconciliationPlan Plan(IEnumerable<DesiredResource> desired, IEnumerable<ObservedResourceState> observed) =>
        ReconciliationEngine.Plan(new ReconciliationRequest(desired, observed, Policy()));
    private static HoldResource Hold(ReconciliationPlan plan, DesiredResource resource) =>
        (HoldResource)plan.Steps.Single(step => step.Desired.Identity == resource.Identity).Output;
    private static string Signature(ReconciliationPlan plan) => string.Join('|', plan.Steps.Select(step =>
    {
        var proofs = step.Output is ReconcileResourceIntent intent
            ? string.Join(',', intent.DependencyProofs.Select(proof =>
                $"{proof.Identity.Value}:{proof.Kind}:{proof.Generation}:{proof.Digest}:{proof.ObservationId}:{proof.FreshnessSequence}:{proof.Condition}"))
            : string.Empty;
        return $"{step.Order}:{step.Desired.Identity.Value}:{step.Output.GetType().Name}:{step.Trace.Single().Reason}:{proofs}";
    }));
    private static ulong Mix(ulong digest, string value)
    {
        foreach (var character in value) digest = unchecked((digest ^ character) * 1099511628211UL);
        return digest;
    }
    private static T UnderCulture<T>(string cultureName, Func<T> action)
    {
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(cultureName);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(cultureName);
            return action();
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }
    private static void Require(bool condition, string property, long seed)
    { if (!condition) throw new InvalidOperationException($"Property failed: {property}, seed {seed.ToString(CultureInfo.InvariantCulture)}."); }

    private sealed record PropertySummary(int Cases, int Diversity, int ErrorCodes, ulong Digest);
    private sealed record ReconciliationSummary(int Cases, int UniqueIdentities, int Reasons, ulong Digest);
    private sealed record CrossSummary(int Cases, int Dispatches, int UniqueOperations, ulong Digest);
    private sealed class Generator(ulong state)
    {
        public ulong Next() { state += 0x9E3779B97F4A7C15UL; var value = state;
            value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9UL;
            value = (value ^ (value >> 27)) * 0x94D049BB133111EBUL; return value ^ (value >> 31); }
        public int NextInt(int maximum) => (int)(Next() % (uint)maximum);
    }
}
