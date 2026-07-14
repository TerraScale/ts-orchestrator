using System.Collections.ObjectModel;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

public static class ProviderOwnershipEngine
{
    public static ProviderAuthorizationDecision Authorize(ProviderAuthorizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var context = request.Context;
        var ownershipGroups = request.OwnershipRecords.GroupBy(x => x.ResourceId.Value, StringComparer.Ordinal).ToArray();
        var observationGroups = request.Observations.GroupBy(x => x.ResourceId.Value, StringComparer.Ordinal).ToArray();
        var createObservationGroups = request.CreateObservations.GroupBy(x => x.CreateKey.Value, StringComparer.Ordinal).ToArray();
        var tagGroups = request.Tags.GroupBy(x => x.ResourceId.Value, StringComparer.Ordinal).ToArray();
        var duplicateCount = CheckedDuplicates(ownershipGroups.Select(x => x.Count())
            .Concat(observationGroups.Select(x => x.Count())).Concat(createObservationGroups.Select(x => x.Count()))
            .Concat(tagGroups.Select(x => x.Count())));
        var conflictCount = ownershipGroups.Count(HasOwnershipConflict) + observationGroups.Count(HasObservationConflict) +
                            createObservationGroups.Count(HasCreateObservationConflict) + tagGroups.Count(HasTagConflict);
        var trace = new List<ProviderDecisionReason>(13)
        {
            Hold(ProviderDecisionCode.EvidenceComplete, request.ObservationCompleteness == ProviderObservationCompleteness.Complete, request.ObservationCompleteness == ProviderObservationCompleteness.Complete ? 1UL : 0UL, 1),
            Hold(ProviderDecisionCode.EvidenceUnique, duplicateCount == 0, checked((ulong)duplicateCount), 0),
            Hold(ProviderDecisionCode.EvidenceConsistent, conflictCount == 0, checked((ulong)conflictCount), 0),
            Hold(ProviderDecisionCode.AuthorityPresent, request.Authority is not null, request.Authority is null ? 0UL : 1UL, 1),
        };
        var ambiguous = trace.Any(x => x.Outcome == ProviderDecisionOutcome.Held);
        if (ambiguous)
        {
            foreach (var code in OperationDecisionCodes)
                trace.Add(new(code, ProviderDecisionOutcome.Held, 0, 0));
            return Decision(trace, [], null);
        }

        var authority = request.Authority!;
        var scopeMatches = authority.CellId == context.CellId && authority.CompartmentId == context.CompartmentId;
        trace.Add(Reject(ProviderDecisionCode.ScopeMatches, scopeMatches, scopeMatches ? 1UL : 0UL, 1));

        var priorExact = request.PriorAuthorization is not null && request.PriorAuthorization.Fingerprint == context.Fingerprint;
        var durableResume = priorExact && request.PriorAuthorization!.Irreversible && context.ControllerEpoch.Value < authority.CurrentEpoch.Value;
        var epochMatches = context.ControllerEpoch.Value == authority.CurrentEpoch.Value || durableResume;
        trace.Add(Reject(ProviderDecisionCode.EpochCurrentOrDurablyResumable, epochMatches, context.ControllerEpoch.Value, authority.CurrentEpoch.Value));

        var ownershipMatches = true;
        var generationMatches = true;
        if (context.Target is ExistingProviderResource target)
        {
            var records = request.OwnershipRecords.Where(x => x.ResourceId == target.Id).ToArray();
            var observations = request.Observations.Where(x => x.ResourceId == target.Id).ToArray();
            ownershipMatches = records.Length == 1 && records[0].CellId == context.CellId && records[0].CompartmentId == context.CompartmentId;
            generationMatches = records.Length == 1 && observations.Length == 1 &&
                                records[0].Generation == context.ExpectedGeneration &&
                                observations[0].Generation == context.ExpectedGeneration &&
                                observations[0].State == context.ExpectedObservedState;
        }
        else if (context.Target is IdempotentProviderCreate create)
        {
            var observations = request.CreateObservations.Where(x => x.CreateKey == create.Key).ToArray();
            ownershipMatches = request.OwnershipRecords.Count == 0;
            generationMatches = observations is [var observation] &&
                                observation.Generation == context.ExpectedGeneration &&
                                observation.State == context.ExpectedObservedState;
        }
        trace.Add(Reject(ProviderDecisionCode.OwnershipMatches, ownershipMatches, ownershipMatches ? 1UL : 0UL, 1));
        trace.Add(Reject(ProviderDecisionCode.GenerationMatches, generationMatches, generationMatches ? context.ExpectedGeneration.Value : 0UL, context.ExpectedGeneration.Value));

        trace.Add(context.DeadlineEvidence.Status switch
        {
            DeadlineEvidenceStatus.Valid => new(ProviderDecisionCode.DeadlineValid, ProviderDecisionOutcome.Passed, 1, 1),
            DeadlineEvidenceStatus.Expired => new(ProviderDecisionCode.DeadlineValid, ProviderDecisionOutcome.Rejected, 0, 1),
            _ => new(ProviderDecisionCode.DeadlineValid, ProviderDecisionOutcome.Held, 0, 1),
        });
        var approvals = request.RequiredApprovals.All(context.Approvals.Contains);
        trace.Add(Reject(ProviderDecisionCode.ApprovalsComplete, approvals,
            checked((ulong)request.RequiredApprovals.Count(x => context.Approvals.Contains(x))), checked((ulong)request.RequiredApprovals.Count)));

        var callEvidenceMatches = request.CallEvidence.Context.Fingerprint == context.Fingerprint;
        trace.Add(Reject(ProviderDecisionCode.CallEvidenceMatches, callEvidenceMatches, callEvidenceMatches ? 1UL : 0UL, 1));

        var priorCompatible = request.PriorAuthorization is null || priorExact;
        trace.Add(Reject(ProviderDecisionCode.PriorAuthorizationCompatible, priorCompatible, priorCompatible ? 1UL : 0UL, 1));
        var compatible = Compatible(context);
        trace.Add(Reject(ProviderDecisionCode.ActionResourceCompatible, compatible, compatible ? 1UL : 0UL, 1));
        var tagsConsistent = TagsConsistent(request);
        trace.Add(Reject(ProviderDecisionCode.TagsConsistent, tagsConsistent, tagsConsistent ? 1UL : 0UL, 1));
        trace.Add(new(ProviderDecisionCode.TagsNotAuthority, ProviderDecisionOutcome.NotApplicable, checked((ulong)request.Tags.Count), 0));

        if (trace.Any(x => x.Outcome is ProviderDecisionOutcome.Rejected or ProviderDecisionOutcome.Held)) return Decision(trace, [], null);
        var durablyAccepted = request.Context.Action != ProviderAction.Observe
            && request.CallEvidence.Status is ProviderCallStatus.Accepted or ProviderCallStatus.ResponseLost or ProviderCallStatus.Completed
            ? request.Context : null;
        return Decision(trace, [NextIntent(request)], durablyAccepted);
    }

    public static HandoffDecision EvaluateHandoff(HandoffRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var inventory = request.Inventory;
        var evidence = request.Evidence;
        var all = new[] { inventory.Expected, inventory.Pulumi, inventory.Regional };
        var duplicates = all.Aggregate(0, (count, items) => checked(count +
            items.Count - items.Select(x => x.ResourceId.Value).Distinct(StringComparer.Ordinal).Count()));
        var expected = Projection(inventory.Expected);
        var exact = expected == Projection(inventory.Pulumi) && expected == Projection(inventory.Regional);
        var scopeMatchesInventory = request.ExpectedScope.InventoryFingerprint == HandoffInventoryFingerprint.Compute(inventory.Expected);
        var generationNotRollback = request.ExpectedScope.BootstrapGeneration.Value >=
                                    request.CurrentAcceptedBootstrapGeneration.Value;
        var trace = new List<ProviderDecisionReason>
        {
            Hold(ProviderDecisionCode.HandoffInventoryUnique, duplicates == 0, checked((ulong)duplicates), 0),
            Reject(ProviderDecisionCode.HandoffInventoryExact, exact, exact ? 1UL : 0UL, 1),
            Reject(ProviderDecisionCode.HandoffScopeMatches, scopeMatchesInventory, scopeMatchesInventory ? 1UL : 0UL, 1),
            Reject(ProviderDecisionCode.HandoffGenerationNotRollback, generationNotRollback,
                request.ExpectedScope.BootstrapGeneration.Value, request.CurrentAcceptedBootstrapGeneration.Value),
            Evidence(ProviderDecisionCode.HandoffRetainUnmanage, evidence.RetainUnmanage, request.ExpectedScope),
            Evidence(ProviderDecisionCode.HandoffJournalReceipt, evidence.RegionalJournalReceipt, request.ExpectedScope),
            Evidence(ProviderDecisionCode.HandoffProviderReady, evidence.ProviderReady, request.ExpectedScope),
            Evidence(ProviderDecisionCode.HandoffTrustReady, evidence.TrustReady, request.ExpectedScope),
            Evidence(ProviderDecisionCode.HandoffBackupReady, evidence.BackupReady, request.ExpectedScope),
            Evidence(ProviderDecisionCode.HandoffFenceActivated, evidence.RegionalFenceActivated, request.ExpectedScope),
        };
        var ready = trace.All(x => x.Outcome == ProviderDecisionOutcome.Passed);
        return new(ready, new ReadOnlyCollection<ProviderDecisionReason>(trace),
            ready ? new(inventory, request.ExpectedScope, request.CurrentAcceptedBootstrapGeneration) : null);
    }

    private static ProviderIntent NextIntent(ProviderAuthorizationRequest request)
    {
        if (request.CallEvidence.Status is ProviderCallStatus.Accepted or ProviderCallStatus.ResponseLost && request.CallEvidence.WorkRequestId is not null)
            return new ReadProviderWorkRequestIntent(request.Context, request.CallEvidence.WorkRequestId);
        if (request.CallEvidence.Status is ProviderCallStatus.Accepted or ProviderCallStatus.ResponseLost or ProviderCallStatus.Completed)
            return new ObserveProviderResourceIntent(request.Context);
        if (request.Context.Target is IdempotentProviderCreate create)
        {
            var observation = request.CreateObservations.Single(x => x.CreateKey == create.Key);
            if (observation.ResolvedResourceId is not null)
                return new ObserveResolvedProviderCreateIntent(request.Context, observation);
        }
        return request.Context.Action switch
        {
            ProviderAction.CreateNode => new CreateNodeProviderIntent(request.Context),
            ProviderAction.StartNode => new StartNodeProviderIntent(request.Context),
            ProviderAction.StopNode => new StopNodeProviderIntent(request.Context),
            ProviderAction.TerminateNode => new TerminateNodeProviderIntent(request.Context),
            ProviderAction.CreateVolume => new CreateVolumeProviderIntent(request.Context),
            ProviderAction.ExpandVolume => new ExpandVolumeProviderIntent(request.Context),
            ProviderAction.ChangeVolumePerformance => new ChangeVolumePerformanceProviderIntent(request.Context),
            ProviderAction.AttachVolume => new AttachVolumeProviderIntent(request.Context),
            ProviderAction.DetachVolume => new DetachVolumeProviderIntent(request.Context),
            ProviderAction.RegisterBackend => new RegisterBackendProviderIntent(request.Context),
            ProviderAction.DeregisterBackend => new DeregisterBackendProviderIntent(request.Context),
            ProviderAction.Observe => new ObserveProviderResourceIntent(request.Context),
            _ => throw new ArgumentOutOfRangeException(),
        };
    }

    private static bool Compatible(ProviderOperationContext context) =>
        (context.ResourceKind, context.Action, context.DesiredTerminalState, context.ActionParameters) switch
    {
        (ProviderResourceKind.Node, ProviderAction.CreateNode, ProviderTerminalState.Present, CreateNodeProviderParameters) => true,
        (ProviderResourceKind.Node, ProviderAction.StartNode, ProviderTerminalState.Running, StartNodeProviderParameters) => true,
        (ProviderResourceKind.Node, ProviderAction.StopNode, ProviderTerminalState.Stopped, StopNodeProviderParameters) => true,
        (ProviderResourceKind.Node, ProviderAction.TerminateNode, ProviderTerminalState.Terminated, TerminateNodeProviderParameters) => true,
        (ProviderResourceKind.Node or ProviderResourceKind.Volume or ProviderResourceKind.Attachment or ProviderResourceKind.Backend, ProviderAction.Observe, _, ObserveProviderParameters) => true,
        (ProviderResourceKind.Volume, ProviderAction.CreateVolume, ProviderTerminalState.Present, CreateVolumeProviderParameters) => true,
        (ProviderResourceKind.Volume, ProviderAction.ExpandVolume, ProviderTerminalState.Expanded, ExpandVolumeProviderParameters) => true,
        (ProviderResourceKind.Volume, ProviderAction.ChangeVolumePerformance, ProviderTerminalState.PerformanceChanged, ChangeVolumePerformanceProviderParameters) => true,
        (ProviderResourceKind.Attachment, ProviderAction.AttachVolume, ProviderTerminalState.Attached, AttachVolumeProviderParameters) => true,
        (ProviderResourceKind.Attachment, ProviderAction.DetachVolume, ProviderTerminalState.Detached, DetachVolumeProviderParameters) => true,
        (ProviderResourceKind.Backend, ProviderAction.RegisterBackend, ProviderTerminalState.Registered, RegisterBackendProviderParameters) => true,
        (ProviderResourceKind.Backend, ProviderAction.DeregisterBackend, ProviderTerminalState.Deregistered, DeregisterBackendProviderParameters) => true,
        _ => false,
    };

    private static int CheckedDuplicates(IEnumerable<int> counts) => counts.Aggregate(0, (sum, count) => checked(sum + Math.Max(0, count - 1)));
    private static readonly ProviderDecisionCode[] OperationDecisionCodes =
    [
        ProviderDecisionCode.ScopeMatches,
        ProviderDecisionCode.EpochCurrentOrDurablyResumable,
        ProviderDecisionCode.OwnershipMatches,
        ProviderDecisionCode.GenerationMatches,
        ProviderDecisionCode.DeadlineValid,
        ProviderDecisionCode.ApprovalsComplete,
        ProviderDecisionCode.CallEvidenceMatches,
        ProviderDecisionCode.PriorAuthorizationCompatible,
        ProviderDecisionCode.ActionResourceCompatible,
        ProviderDecisionCode.TagsConsistent,
        ProviderDecisionCode.TagsNotAuthority,
    ];
    private static bool HasOwnershipConflict(IGrouping<string, ProviderOwnershipRecord> g) => g
        .Select(x => string.Join('|', x.CellId.Value, x.CompartmentId.Value, Invariant(x.Generation.Value)))
        .Distinct(StringComparer.Ordinal).Skip(1).Any();
    private static bool HasObservationConflict(IGrouping<string, ProviderResourceObservation> g) => g
        .Select(x => string.Join('|', Invariant(x.Generation.Value), x.State))
        .Distinct(StringComparer.Ordinal).Skip(1).Any();
    private static bool HasCreateObservationConflict(IGrouping<string, ProviderCreateObservation> g) => g
        .Select(x => string.Join('|', Invariant(x.Generation.Value), x.State, x.ResolvedResourceId?.Value ?? "-"))
        .Distinct(StringComparer.Ordinal).Skip(1).Any();
    private static bool HasTagConflict(IGrouping<string, ProviderInventoryTagEvidence> g) => g
        .Select(x => string.Join('|', x.CellId.Value, x.CompartmentId.Value, x.OperationId.Value, Invariant(x.Generation.Value)))
        .Distinct(StringComparer.Ordinal).Skip(1).Any();
    private static bool TagsConsistent(ProviderAuthorizationRequest request)
    {
        if (request.Context.Target is not ExistingProviderResource target) return request.Tags.Count == 0;
        var tags = request.Tags.Where(x => x.ResourceId == target.Id).ToArray();
        return tags.Length == 0 || tags is [var tag] &&
            tag.CellId == request.Context.CellId &&
            tag.CompartmentId == request.Context.CompartmentId &&
            tag.OperationId == request.Context.OperationId &&
            tag.Generation == request.Context.ExpectedGeneration;
    }
    private static string Projection(IEnumerable<HandoffInventoryItem> items) => string.Join(';', items
        .OrderBy(x => x.ResourceId.Value, StringComparer.Ordinal).ThenBy(x => x.Kind).ThenBy(x => x.Generation.Value)
        .Select(x => string.Join('|', x.ResourceId.Value, x.Kind, Invariant(x.Generation.Value))));
    private static string Invariant(ulong value) => value.ToString(CultureInfo.InvariantCulture);
    private static ProviderDecisionReason Hold(ProviderDecisionCode c, bool pass, ulong o, ulong r) => new(c, pass ? ProviderDecisionOutcome.Passed : ProviderDecisionOutcome.Held, o, r);
    private static ProviderDecisionReason Reject(ProviderDecisionCode c, bool pass, ulong o, ulong r) => new(c, pass ? ProviderDecisionOutcome.Passed : ProviderDecisionOutcome.Rejected, o, r);
    private static ProviderDecisionReason Evidence(ProviderDecisionCode c, HandoffProof proof, HandoffScope expectedScope)
    {
        if (proof.Scope != expectedScope) return new(c, ProviderDecisionOutcome.Rejected, 0, 1);
        return proof.Status switch
        {
            HandoffEvidenceStatus.Verified => new(c, ProviderDecisionOutcome.Passed, 1, 1),
            HandoffEvidenceStatus.Missing => new(c, ProviderDecisionOutcome.Held, 0, 1),
            _ => new(c, ProviderDecisionOutcome.Rejected, 0, 1),
        };
    }
    private static ProviderAuthorizationDecision Decision(List<ProviderDecisionReason> trace, IReadOnlyList<ProviderIntent> intents,
        ProviderOperationContext? durablyAcceptedContext) => new(intents.Count > 0, new ReadOnlyCollection<ProviderDecisionReason>(trace),
        new ReadOnlyCollection<ProviderIntent>(intents.ToArray()), durablyAcceptedContext);
}
