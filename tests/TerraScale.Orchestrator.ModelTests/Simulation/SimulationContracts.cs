using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

public enum FailureKind { Unspecified, Loss, Duplicate, Reorder, Delay, Crash, Restart, LeaderChange, Partition, Heal }
public enum ModelEventKind { Unspecified, AuthorizeOperation, RequestCreate, ProviderOutcomeUnknown, ProviderLateCompletion, MutationSucceeded, RequestTermination, Delivery }
public enum ModelNodeRole { Unspecified, Critical, Elastic }
public enum SimulationFailureCode { Unspecified, Completed, InvalidEvent, Overflow, StepBoundExhausted, ScheduleBoundExhausted, NonConvergent, InvariantViolation }
public enum SafetyInvariant { Unspecified, SingleAcceptedWriter, NoStaleSuccessfulMutation, NoUnauthorizedAction, NoUnsafeTermination, QuorumFloorPreserved, NoSecondCreateAfterUnknown, SnapshotReplayDigestEqual, TerminalMutationUnique }
public enum ProviderOutcome { Unspecified, Absent, OutcomeUnknown, Completed }
public enum AcceptedActionKind { Unspecified, Authorization, Create, Mutation, Termination }

public sealed record SimulationBounds(int MaximumSteps, int MaximumSchedules, int MaximumDepth)
{
    public static SimulationBounds SmokeShard { get; } = new(2_048, 2_048, 5);
    public static SimulationBounds FeatureMinimum { get; } = new(10_000, 10_000, 8);
    public static SimulationBounds FullMinimum { get; } = new(1_000_000, 1_000_000, 12);
    public bool IsValid => MaximumSteps > 0 && MaximumSchedules > 0 && MaximumDepth >= 0;
}

public sealed record VirtualClock(long Tick)
{
    public ClockAdvance Advance(long delta)
    {
        if (delta < 0) return new(this, SimulationFailureCode.InvalidEvent);
        try { return new(new(checked(Tick + delta)), SimulationFailureCode.Completed); }
        catch (OverflowException) { return new(this, SimulationFailureCode.Overflow); }
    }
}
public sealed record ClockAdvance(VirtualClock Clock, SimulationFailureCode Code);

public sealed record DeterministicIdentitySource(long NextValue)
{
    public IdentityAdvance Next()
    {
        if (NextValue <= 0) return new(this, null, SimulationFailureCode.InvalidEvent);
        try { return new(new(checked(NextValue + 1)), $"sim-{NextValue.ToString(CultureInfo.InvariantCulture)}", SimulationFailureCode.Completed); }
        catch (OverflowException) { return new(this, null, SimulationFailureCode.Overflow); }
    }
}
public sealed record IdentityAdvance(DeterministicIdentitySource Source, string? Identity, SimulationFailureCode Code);

public sealed record ModelNode(string Id, ModelNodeRole Role, bool Crashed, bool Partitioned, long AcceptedWriterEpoch);
public sealed record ModelOperation(string Operation, long Generation, long Epoch, string IdempotencyKey,
    string Resource, bool Authorized, int CreateCount, ProviderOutcome ProviderOutcome);

public sealed record ModelEvent(long Sequence, long DueTick, string EventId, ModelEventKind Kind, string Node,
    string Operation, long Generation, long Epoch, string IdempotencyKey, string Resource, long ObservationSequence);
public sealed record FailureDirective(FailureKind Kind, string Node, long DelayTicks);
public sealed record AcceptedActionEvidence(AcceptedActionKind Kind, string Operation, string Node,
    long Generation, string IdempotencyKey, string Resource, long EventEpoch, long AuthorityEpoch,
    string LeaderAtAcceptance, long NodeAcceptedEpoch, bool NodeCrashed, bool NodePartitioned,
    bool Authorized, ModelNodeRole NodeRole, int Ordinal, int CriticalNodesAfter);

public sealed record FakeProviderObservation(string Operation, long Generation, long Epoch, string IdempotencyKey,
    string Resource, long ObservationSequence, ProviderOutcome Outcome);
public sealed record FakeDeliveryObservation(string Operation, long Generation, long Epoch, string IdempotencyKey,
    string Resource, long ObservationSequence, bool Duplicate);

public sealed class ImmutableEventQueue
{
    private readonly ReadOnlyCollection<QueueEntry> entries;
    public ImmutableEventQueue(IEnumerable<ModelEvent> events)
    {
        var copy = (events ?? throw new ArgumentNullException(nameof(events))).Take(ModelValidation.MaximumModelEvents + 1).ToArray();
        if (copy.Length > ModelValidation.MaximumModelEvents) throw new ArgumentException("Event bound exceeded.", nameof(events));
        ModelValidation.Events(copy, requireUniqueIds: false);
        var ordered = copy.OrderBy(static item => item.DueTick).ThenBy(static item => item.Sequence)
            .ThenBy(static item => item.EventId, StringComparer.Ordinal).ToArray();
        entries = new(ordered.Select((item, index) => new QueueEntry(item, item.DueTick, index + 1L)).ToArray());
    }
    private ImmutableEventQueue(IEnumerable<QueueEntry> values)
    {
        entries = new(values.OrderBy(static item => item.AvailableTick).ThenBy(static item => item.DeliveryOrdinal)
            .ThenBy(static item => item.Event.Sequence).ThenBy(static item => item.Event.EventId, StringComparer.Ordinal).ToArray());
    }
    public IReadOnlyList<ModelEvent> Events => new ReadOnlyCollection<ModelEvent>(entries.Select(static item => item.Event).ToArray());
    internal IReadOnlyList<QueueEntry> Entries => entries;
    internal long FirstAvailableTick => entries.Count == 0 ? 0 : entries[0].AvailableTick;
    public int Count => entries.Count;
    public ImmutableEventQueue DuplicateFirst()
    {
        if (entries.Count == 0) return this;
        var ordinal = checked(entries.Max(static item => item.DeliveryOrdinal) + 1);
        return new(entries.Append(new(entries[0].Event, entries[0].AvailableTick, ordinal)));
    }
    public ImmutableEventQueue ReorderFirstTwo()
    {
        if (entries.Count < 2) return this;
        var values = entries.ToArray();
        (values[0], values[1]) = (values[0] with { AvailableTick = values[1].AvailableTick,
                DeliveryOrdinal = values[1].DeliveryOrdinal },
            values[1] with { AvailableTick = values[0].AvailableTick,
                DeliveryOrdinal = values[0].DeliveryOrdinal });
        return new(values);
    }
    public ImmutableEventQueue DelayFirst(long dueTick) => entries.Count == 0 ? this :
        new([entries[0] with { AvailableTick = dueTick }, .. entries.Skip(1)]);
    public ImmutableEventQueue RemoveFirst() => entries.Count == 0 ? this : new(entries.Skip(1));
}
internal sealed record QueueEntry(ModelEvent Event, long AvailableTick, long DeliveryOrdinal);

public sealed class ModelState
{
    public ModelState(VirtualClock clock, DeterministicIdentitySource identities, long currentEpoch,
        string leader, IEnumerable<ModelNode> nodes, IEnumerable<ModelOperation> operations,
        ImmutableEventQueue queue, IEnumerable<string> deliveredEventIds, int acceptedMutations,
        int rejectedMutations, int terminations, IEnumerable<string>? completedMutationOperations = null,
        IEnumerable<AcceptedActionEvidence>? acceptedActions = null)
    {
        ArgumentNullException.ThrowIfNull(clock); ArgumentNullException.ThrowIfNull(identities);
        ArgumentNullException.ThrowIfNull(queue);
        if (clock.Tick < 0 || identities.NextValue <= 0 || currentEpoch <= 0 || !ModelValidation.Identity(leader))
            throw new ArgumentException("Invalid model state scalar.");
        var nodeValues = (nodes ?? throw new ArgumentNullException(nameof(nodes))).Take(4).ToArray();
        var operationValues = (operations ?? throw new ArgumentNullException(nameof(operations)))
            .Take(ModelValidation.MaximumModelOperations + 1).ToArray();
        var deliveredValues = (deliveredEventIds ?? throw new ArgumentNullException(nameof(deliveredEventIds)))
            .Take(ModelValidation.MaximumModelEvents + 1).ToArray();
        var completedValues = (completedMutationOperations ?? []).Take(ModelValidation.MaximumModelOperations + 1).ToArray();
        var actionValues = (acceptedActions ?? []).Take(ModelValidation.MaximumModelEvents + 1).ToArray();
        if (nodeValues.Length is < 1 or > 3 || nodeValues.Any(static node => node is null ||
                !ModelValidation.Identity(node.Id) || !Enum.IsDefined(node.Role) || node.Role == ModelNodeRole.Unspecified ||
                node.AcceptedWriterEpoch < 0) ||
            nodeValues.Select(static node => node.Id).Distinct(StringComparer.Ordinal).Count() != nodeValues.Length)
            throw new ArgumentException("Invalid nodes.", nameof(nodes));
        if (!nodeValues.Any(node => node.Id == leader)) throw new ArgumentException("Leader is not a node.", nameof(leader));
        if (operationValues.Length > ModelValidation.MaximumModelOperations || operationValues.Any(static operation => operation is null || !ModelValidation.Identity(operation.Operation) ||
                !ModelValidation.Identity(operation.IdempotencyKey) || !ModelValidation.Identity(operation.Resource) ||
                operation.Generation <= 0 || operation.Epoch <= 0 || operation.CreateCount is < 0 or > 1 ||
                !Enum.IsDefined(operation.ProviderOutcome) || operation.ProviderOutcome == ProviderOutcome.Unspecified) ||
            operationValues.Select(static operation => operation.Operation).Distinct(StringComparer.Ordinal).Count() != operationValues.Length)
            throw new ArgumentException("Invalid operations.", nameof(operations));
        if (deliveredValues.Length > ModelValidation.MaximumModelEvents || deliveredValues.Any(static id => !ModelValidation.Identity(id)) ||
            deliveredValues.Distinct(StringComparer.Ordinal).Count() != deliveredValues.Length ||
            completedValues.Length > ModelValidation.MaximumModelOperations ||
            completedValues.Any(static id => !ModelValidation.Identity(id)) ||
            completedValues.Distinct(StringComparer.Ordinal).Count() != completedValues.Length ||
            actionValues.Length > ModelValidation.MaximumModelEvents || actionValues.Any(static action => action is null ||
                !Enum.IsDefined(action.Kind) || action.Kind == AcceptedActionKind.Unspecified ||
                !ModelValidation.Identity(action.Operation) || !ModelValidation.Identity(action.Node) || action.Generation <= 0 ||
                !ModelValidation.Identity(action.IdempotencyKey) || !ModelValidation.Identity(action.Resource) ||
                !ModelValidation.Identity(action.LeaderAtAcceptance) || action.EventEpoch <= 0 ||
                action.AuthorityEpoch <= 0 || action.NodeAcceptedEpoch < 0 || !Enum.IsDefined(action.NodeRole) ||
                action.NodeRole == ModelNodeRole.Unspecified || action.Ordinal <= 0 || action.CriticalNodesAfter is < 0 or > 3) ||
            acceptedMutations < 0 || rejectedMutations < 0 || terminations < 0)
            throw new ArgumentException("Invalid model counters or delivered identifiers.");
        Clock = clock; Identities = identities; CurrentEpoch = currentEpoch; Leader = leader;
        Nodes = new ReadOnlyCollection<ModelNode>(nodeValues.OrderBy(static item => item.Id, StringComparer.Ordinal).ToArray());
        Operations = new ReadOnlyCollection<ModelOperation>(operationValues.OrderBy(static item => item.Operation, StringComparer.Ordinal).ToArray());
        Queue = queue; DeliveredEventIds = new ReadOnlyCollection<string>(deliveredValues.OrderBy(static item => item, StringComparer.Ordinal).ToArray());
        AcceptedMutations = acceptedMutations; RejectedMutations = rejectedMutations; Terminations = terminations;
        CompletedMutationOperations = new ReadOnlyCollection<string>(completedValues.OrderBy(static item => item, StringComparer.Ordinal).ToArray());
        AcceptedActions = new ReadOnlyCollection<AcceptedActionEvidence>(actionValues.ToArray());
    }
    public VirtualClock Clock { get; }
    public DeterministicIdentitySource Identities { get; }
    public long CurrentEpoch { get; }
    public string Leader { get; }
    public IReadOnlyList<ModelNode> Nodes { get; }
    public IReadOnlyList<ModelOperation> Operations { get; }
    public ImmutableEventQueue Queue { get; }
    public IReadOnlyList<string> DeliveredEventIds { get; }
    public int AcceptedMutations { get; }
    public int RejectedMutations { get; }
    public int Terminations { get; }
    public IReadOnlyList<string> CompletedMutationOperations { get; }
    public IReadOnlyList<AcceptedActionEvidence> AcceptedActions { get; }

    public static ModelState Create(IEnumerable<ModelEvent> events)
    {
        var values = (events ?? throw new ArgumentNullException(nameof(events))).Take(ModelValidation.MaximumModelEvents + 1).ToArray();
        if (values.Length > ModelValidation.MaximumModelEvents) throw new ArgumentException("Event bound exceeded.", nameof(events));
        ModelValidation.Events(values, requireUniqueIds: true);
        return new(new(0), new(1), 1, "n1",
            [new("n1", ModelNodeRole.Critical, false, false, 1), new("n2", ModelNodeRole.Critical, false, false, 0),
             new("n3", ModelNodeRole.Critical, false, false, 0)], [], new(values), [], 0, 0, 0);
    }

    public string Canonical()
    {
        var builder = new StringBuilder();
        builder.Append("v2|tick=").Append(Clock.Tick.ToString(CultureInfo.InvariantCulture))
            .Append("|next=").Append(Identities.NextValue.ToString(CultureInfo.InvariantCulture))
            .Append("|epoch=").Append(CurrentEpoch.ToString(CultureInfo.InvariantCulture));
        AppendString(builder, "leader", Leader);
        builder
            .Append("|accepted=").Append(AcceptedMutations.ToString(CultureInfo.InvariantCulture))
            .Append("|rejected=").Append(RejectedMutations.ToString(CultureInfo.InvariantCulture))
            .Append("|terminated=").Append(Terminations.ToString(CultureInfo.InvariantCulture));
        foreach (var node in Nodes) { AppendString(builder, "node", node.Id); builder.Append(':').Append((int)node.Role).Append(':')
            .Append(node.Crashed ? 1 : 0).Append(':').Append(node.Partitioned ? 1 : 0).Append(':')
            .Append(node.AcceptedWriterEpoch.ToString(CultureInfo.InvariantCulture));
        }
        foreach (var operation in Operations) { AppendString(builder, "operation", operation.Operation); builder.Append(':')
            .Append(operation.Generation.ToString(CultureInfo.InvariantCulture)).Append(':')
            .Append(operation.Epoch.ToString(CultureInfo.InvariantCulture)); AppendString(builder, "key", operation.IdempotencyKey);
            AppendString(builder, "resource", operation.Resource); builder.Append(':').Append(operation.Authorized ? 1 : 0).Append(':')
            .Append(operation.CreateCount.ToString(CultureInfo.InvariantCulture))
            .Append(':').Append((int)operation.ProviderOutcome);
        }
        foreach (var item in Queue.Entries) { builder.Append("|qordinal=")
            .Append(item.DeliveryOrdinal.ToString(CultureInfo.InvariantCulture)).Append("|available=")
            .Append(item.AvailableTick.ToString(CultureInfo.InvariantCulture)).Append('{')
            .Append(EventCanonical(item.Event)).Append('}'); }
        foreach (var id in DeliveredEventIds) AppendString(builder, "delivered", id);
        foreach (var id in CompletedMutationOperations) AppendString(builder, "completed-operation", id);
        foreach (var action in AcceptedActions) { builder.Append("|action=").Append((int)action.Kind); AppendString(builder, "operation", action.Operation);
            AppendString(builder, "node", action.Node); AppendString(builder, "key", action.IdempotencyKey);
            AppendString(builder, "resource", action.Resource); AppendString(builder, "accepted-leader", action.LeaderAtAcceptance);
            builder.Append("|generation=").Append(action.Generation.ToString(CultureInfo.InvariantCulture))
                .Append("|event-epoch=").Append(action.EventEpoch.ToString(CultureInfo.InvariantCulture))
                .Append("|authority-epoch=").Append(action.AuthorityEpoch.ToString(CultureInfo.InvariantCulture))
                .Append("|node-epoch=").Append(action.NodeAcceptedEpoch.ToString(CultureInfo.InvariantCulture))
                .Append("|node-crashed=").Append(action.NodeCrashed ? 1 : 0)
                .Append("|node-partitioned=").Append(action.NodePartitioned ? 1 : 0)
                .Append("|authorized=").Append(action.Authorized ? 1 : 0).Append("|role=").Append((int)action.NodeRole)
                .Append("|ordinal=").Append(action.Ordinal.ToString(CultureInfo.InvariantCulture))
                .Append("|critical-after=").Append(action.CriticalNodesAfter.ToString(CultureInfo.InvariantCulture)); }
        return builder.ToString();
    }
    public string Digest() => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical()))).ToLowerInvariant();
    public static string EventCanonical(ModelEvent item)
    {
        var builder = new StringBuilder().Append("seq=").Append(item.Sequence.ToString(CultureInfo.InvariantCulture))
            .Append("|due=").Append(item.DueTick.ToString(CultureInfo.InvariantCulture)).Append("|kind=")
            .Append(((int)item.Kind).ToString(CultureInfo.InvariantCulture)).Append("|generation=")
            .Append(item.Generation.ToString(CultureInfo.InvariantCulture)).Append("|epoch=")
            .Append(item.Epoch.ToString(CultureInfo.InvariantCulture)).Append("|observation=")
            .Append(item.ObservationSequence.ToString(CultureInfo.InvariantCulture));
        AppendString(builder, "event", item.EventId); AppendString(builder, "node", item.Node);
        AppendString(builder, "operation", item.Operation); AppendString(builder, "key", item.IdempotencyKey);
        AppendString(builder, "resource", item.Resource);
        return builder.ToString();
    }
    private static void AppendString(StringBuilder builder, string tag, string value) => builder.Append('|').Append(tag)
        .Append('=').Append(value.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(value);
}

public sealed class SimulationResult
{
    public SimulationResult(ModelState state, SimulationFailureCode code, SafetyInvariant invariant, int steps,
        int schedules, string digest, IEnumerable<FailureDirective> schedule)
    {
        State = state; Code = code; Invariant = invariant; Steps = steps; Schedules = schedules; Digest = digest;
        Schedule = new ReadOnlyCollection<FailureDirective>((schedule ?? throw new ArgumentNullException(nameof(schedule))).ToArray());
    }
    public ModelState State { get; }
    public SimulationFailureCode Code { get; }
    public SafetyInvariant Invariant { get; }
    public int Steps { get; }
    public int Schedules { get; }
    public string Digest { get; }
    public IReadOnlyList<FailureDirective> Schedule { get; }
}
public sealed record ShrinkResult(SimulationFailureCode Code, IReadOnlyList<FailureDirective> Schedule);

internal static class ModelValidation
{
    internal const int MaximumModelEvents = 2048;
    internal const int MaximumModelOperations = 2048;
    internal static bool Identity(string? value) => value is { Length: > 0 and <= 80 } &&
        value.All(static character => character is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or >= '0' and <= '9' or '.' or '_' or '-');
    internal static void Events(IReadOnlyList<ModelEvent> events, bool requireUniqueIds)
    {
        if (events.Any(static item => item is null || item.Sequence <= 0 || item.DueTick < 0 ||
                item.ObservationSequence <= 0 || item.Generation <= 0 || item.Epoch <= 0 ||
                !Identity(item.EventId) || !Identity(item.Node) || !Identity(item.Operation) ||
                item.Node is not ("n1" or "n2" or "n3") ||
                !Identity(item.IdempotencyKey) || !Identity(item.Resource) || !Enum.IsDefined(item.Kind) ||
                item.Kind == ModelEventKind.Unspecified) || (requireUniqueIds &&
            events.Select(static item => item.EventId).Distinct(StringComparer.Ordinal).Count() != events.Count))
            throw new ArgumentException("Invalid events.", nameof(events));
    }
}

public static class FailureScheduleCatalog
{
    public static IReadOnlyList<FailureKind> Ordered { get; } = new ReadOnlyCollection<FailureKind>(
        [FailureKind.Loss, FailureKind.Duplicate, FailureKind.Reorder, FailureKind.Delay, FailureKind.Crash,
         FailureKind.Restart, FailureKind.LeaderChange, FailureKind.Partition, FailureKind.Heal]);
}
