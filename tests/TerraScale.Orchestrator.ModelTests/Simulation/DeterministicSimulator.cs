using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ModelTests.Simulation;

public static class DeterministicSimulator
{
    public static SimulationResult Replay(IEnumerable<ModelEvent> events, IEnumerable<FailureDirective> schedule,
        SimulationBounds bounds)
    {
        if (!bounds.IsValid) return Failure(ModelState.Create([]), SimulationFailureCode.InvalidEvent, 0, 0, []);
        var scheduleMaterialization = TryMaterialize(schedule ?? [], Math.Min(Math.Min(bounds.MaximumSteps, bounds.MaximumSchedules),
                ModelValidation.MaximumModelEvents), out var orderedSchedule);
        if (scheduleMaterialization != MaterializationCode.Completed)
            return Failure(ModelState.Create([]), scheduleMaterialization == MaterializationCode.BoundExceeded ?
                SimulationFailureCode.ScheduleBoundExhausted : SimulationFailureCode.InvalidEvent, 0, 0, []);
        if (orderedSchedule.Any(static item => item is null || !Enum.IsDefined(item.Kind) || item.Kind == FailureKind.Unspecified ||
                item.DelayTicks < 0 || item.Node is not ("n1" or "n2" or "n3")))
            return Failure(ModelState.Create([]), SimulationFailureCode.InvalidEvent, 0, 0, orderedSchedule);
        var eventMaterialization = TryMaterialize(events ?? [], Math.Min(bounds.MaximumSteps, ModelValidation.MaximumModelEvents), out var eventValues);
        if (eventMaterialization != MaterializationCode.Completed)
            return Failure(ModelState.Create([]), eventMaterialization == MaterializationCode.BoundExceeded ?
                SimulationFailureCode.StepBoundExhausted : SimulationFailureCode.InvalidEvent, 0, 0, orderedSchedule);
        ModelState state;
        try { state = ModelState.Create(eventValues); }
        catch (ArgumentException) { return Failure(ModelState.Create([]), SimulationFailureCode.InvalidEvent, 0, 0, orderedSchedule); }
        var steps = 0;
        foreach (var directive in orderedSchedule)
        {
            if (steps >= bounds.MaximumSteps) return Failure(state, SimulationFailureCode.StepBoundExhausted, steps, 1, orderedSchedule);
            var transition = ApplyDirectiveAndStep(state, directive);
            if (transition.Code != SimulationFailureCode.Completed)
                return Failure(transition.State, transition.Code, steps + 1, 1, orderedSchedule);
            state = transition.State; steps++;
            var invariant = FirstViolation(state);
            if (invariant != SafetyInvariant.Unspecified)
                return Failure(state, SimulationFailureCode.InvariantViolation, steps, 1, orderedSchedule, invariant);
        }
        while (state.Queue.Count > 0)
        {
            if (steps >= bounds.MaximumSteps) return Failure(state, SimulationFailureCode.StepBoundExhausted, steps, 1, orderedSchedule);
            var transition = ProcessNext(state);
            if (transition.Code != SimulationFailureCode.Completed)
                return Failure(transition.State, transition.Code, steps + 1, 1, orderedSchedule);
            state = transition.State; steps++;
            var invariant = FirstViolation(state);
            if (invariant != SafetyInvariant.Unspecified)
                return Failure(state, SimulationFailureCode.InvariantViolation, steps, 1, orderedSchedule, invariant);
        }
        return new(state, SimulationFailureCode.Completed, SafetyInvariant.Unspecified, steps, 1, state.Digest(),
            new ReadOnlyCollection<FailureDirective>(orderedSchedule));
    }

    public static SimulationResult Explore(IEnumerable<ModelEvent> events, SimulationBounds bounds)
    {
        var empty = ModelState.Create([]);
        if (!bounds.IsValid) return Failure(empty, SimulationFailureCode.InvalidEvent, 0, 0, []);
        var eventMaterialization = TryMaterialize(events ?? [], Math.Min(bounds.MaximumSteps, ModelValidation.MaximumModelEvents), out var eventValues);
        if (eventMaterialization != MaterializationCode.Completed)
            return Failure(empty, eventMaterialization == MaterializationCode.BoundExceeded ?
                SimulationFailureCode.StepBoundExhausted : SimulationFailureCode.InvalidEvent, 0, 0, []);
        ModelState initial;
        try { initial = ModelState.Create(eventValues); }
        catch (ArgumentException) { return Failure(empty, SimulationFailureCode.InvalidEvent, 0, 0, []); }
        var frontier = new Queue<(ModelState State, int Depth, FailureDirective[] Schedule)>();
        frontier.Enqueue((initial, 0, []));
        var visited = new HashSet<string>(StringComparer.Ordinal) { initial.Digest() };
        var schedules = 0; var steps = 0; var last = initial; var prunedPendingState = false;
        while (frontier.Count > 0)
        {
            var current = frontier.Dequeue(); last = current.State;
            if (current.State.Queue.Count == 0) continue;
            if (current.Depth >= bounds.MaximumDepth) { prunedPendingState = true; continue; }
            foreach (var branch in Branches(current.State))
            {
                if (schedules >= bounds.MaximumSchedules)
                    return Failure(last, SimulationFailureCode.ScheduleBoundExhausted, steps, schedules, current.Schedule);
                if (steps >= bounds.MaximumSteps)
                    return Failure(last, SimulationFailureCode.StepBoundExhausted, steps, schedules, current.Schedule);
                var transition = branch is null ? ProcessNext(current.State) : ApplyDirectiveAndStep(current.State, branch);
                schedules++; steps++;
                if (transition.Code != SimulationFailureCode.Completed)
                    return Failure(transition.State, transition.Code, steps, schedules,
                        branch is null ? current.Schedule : current.Schedule.Append(branch).ToArray());
                var invariant = FirstViolation(transition.State);
                if (invariant != SafetyInvariant.Unspecified)
                    return Failure(transition.State, SimulationFailureCode.InvariantViolation, steps, schedules,
                        branch is null ? current.Schedule : current.Schedule.Append(branch).ToArray(), invariant);
                var digest = transition.State.Digest();
                if (!visited.Add(digest)) continue;
                frontier.Enqueue((transition.State, current.Depth + 1,
                    branch is null ? current.Schedule : current.Schedule.Append(branch).ToArray()));
            }
        }
        return new(last, prunedPendingState ? SimulationFailureCode.NonConvergent : SimulationFailureCode.Completed,
            SafetyInvariant.Unspecified, steps, schedules, last.Digest(), []);
    }

    public static ShrinkResult Shrink(IEnumerable<ModelEvent> events,
        IReadOnlyList<FailureDirective> schedule, SimulationBounds bounds, SimulationFailureCode expectedCode,
        SafetyInvariant expectedInvariant = SafetyInvariant.Unspecified, string? expectedDigest = null)
    {
        if (events is null || schedule is null || !bounds.IsValid) return new(SimulationFailureCode.InvalidEvent, []);
        var materialized = TryMaterialize(events, Math.Min(bounds.MaximumSteps, ModelValidation.MaximumModelEvents), out var eventValues);
        if (materialized != MaterializationCode.Completed) return new(materialized == MaterializationCode.BoundExceeded ?
            SimulationFailureCode.StepBoundExhausted : SimulationFailureCode.InvalidEvent, []);
        FailureDirective[] scheduleValues;
        try
        {
            if (schedule.Count > Math.Min(bounds.MaximumSchedules, ModelValidation.MaximumModelEvents))
                return new(SimulationFailureCode.ScheduleBoundExhausted, []);
            scheduleValues = schedule.Take(schedule.Count).ToArray();
        }
        catch (Exception) { return new(SimulationFailureCode.InvalidEvent, []); }
        var result = scheduleValues.ToList();
        for (var index = 0; index < result.Count;)
        {
            var candidate = result.Where((_, position) => position != index).ToArray();
            var replay = Replay(eventValues, candidate, bounds);
            if (replay.Code == expectedCode && replay.Invariant == expectedInvariant &&
                (expectedDigest is null || string.Equals(replay.Digest, expectedDigest, StringComparison.Ordinal)))
                result = candidate.ToList();
            else index++;
        }
        return new(SimulationFailureCode.Completed, new ReadOnlyCollection<FailureDirective>(result));
    }

    private static Transition ApplyDirectiveAndStep(ModelState state, FailureDirective directive)
    {
        if (!Enum.IsDefined(directive.Kind) || directive.Kind == FailureKind.Unspecified || directive.DelayTicks < 0)
            return new(state, SimulationFailureCode.InvalidEvent);
        var queue = state.Queue;
        var nodes = state.Nodes.ToArray();
        var epoch = state.CurrentEpoch; var leader = state.Leader;
        switch (directive.Kind)
        {
            case FailureKind.Loss:
                queue = queue.RemoveFirst();
                break;
            case FailureKind.Duplicate:
                if (queue.Count >= ModelValidation.MaximumModelEvents)
                    return new(state, SimulationFailureCode.StepBoundExhausted);
                try { queue = queue.DuplicateFirst(); }
                catch (OverflowException) { return new(state, SimulationFailureCode.Overflow); }
                break;
            case FailureKind.Reorder:
                queue = queue.ReorderFirstTwo();
                break;
            case FailureKind.Delay:
                if (queue.Count > 0)
                {
                    long due;
                    try { due = checked(queue.FirstAvailableTick + directive.DelayTicks); }
                    catch (OverflowException) { return new(state, SimulationFailureCode.Overflow); }
                    queue = queue.DelayFirst(due);
                }
                break;
            case FailureKind.Crash:
                if (!UpdateNode(nodes, directive.Node, crashed: true)) return new(state, SimulationFailureCode.InvalidEvent);
                break;
            case FailureKind.Restart:
                if (!UpdateNode(nodes, directive.Node, crashed: false)) return new(state, SimulationFailureCode.InvalidEvent);
                break;
            case FailureKind.LeaderChange:
                try { epoch = checked(epoch + 1); }
                catch (OverflowException) { return new(state, SimulationFailureCode.Overflow); }
                if (!UpdateNode(nodes, directive.Node, acceptedEpoch: epoch)) return new(state, SimulationFailureCode.InvalidEvent);
                for (var index = 0; index < nodes.Length; index++)
                    if (nodes[index].Id != directive.Node) nodes[index] = nodes[index] with { AcceptedWriterEpoch = 0 };
                leader = directive.Node;
                break;
            case FailureKind.Partition:
                if (!UpdateNode(nodes, directive.Node, partitioned: true)) return new(state, SimulationFailureCode.InvalidEvent);
                break;
            case FailureKind.Heal:
                if (!UpdateNode(nodes, directive.Node, partitioned: false)) return new(state, SimulationFailureCode.InvalidEvent);
                break;
        }
        var updated = CopyState(state, queue: queue, nodes: nodes, epoch: epoch, leader: leader);
        return updated.Queue.Count == 0 ? new(updated, SimulationFailureCode.Completed) : ProcessNext(updated);
    }

    private static Transition ProcessNext(ModelState state)
    {
        if (state.Queue.Count == 0) return new(state, SimulationFailureCode.Completed);
        var item = state.Queue.Events[0];
        if (!Valid(item)) return new(state, SimulationFailureCode.InvalidEvent);
        var clock = state.Clock.Tick < state.Queue.FirstAvailableTick ? new VirtualClock(state.Queue.FirstAvailableTick) : state.Clock;
        var queue = state.Queue.RemoveFirst();
        if (state.DeliveredEventIds.Contains(item.EventId, StringComparer.Ordinal))
            return new(CopyState(state, clock: clock, queue: queue), SimulationFailureCode.Completed);
        var delivered = state.DeliveredEventIds.Append(item.EventId).ToArray();
        var operations = state.Operations.ToList();
        var completedOperations = state.CompletedMutationOperations.ToList();
        var acceptedActions = state.AcceptedActions.ToList();
        var accepted = state.AcceptedMutations; var rejected = state.RejectedMutations; var terminations = state.Terminations;
        var existing = operations.FindIndex(value => value.Operation == item.Operation);
        switch (item.Kind)
        {
            case ModelEventKind.AuthorizeOperation:
                if (existing < 0 && CurrentAuthority(state, item))
                {
                    operations.Add(new(item.Operation, item.Generation, item.Epoch, item.IdempotencyKey,
                        item.Resource, true, 0, ProviderOutcome.Absent));
                    acceptedActions.Add(Evidence(AcceptedActionKind.Authorization, item, state, true,
                        state.Nodes.Single(node => node.Id == item.Node).Role, 1));
                }
                else rejected++;
                break;
            case ModelEventKind.RequestCreate:
                if (existing >= 0 && Exact(operations[existing], item) && operations[existing].Authorized &&
                    operations[existing].CreateCount == 0 && CurrentAuthority(state, item))
                {
                    operations[existing] = operations[existing] with { CreateCount = 1 };
                    acceptedActions.Add(Evidence(AcceptedActionKind.Create, item, state, operations[existing].Authorized,
                        state.Nodes.Single(node => node.Id == item.Node).Role, operations[existing].CreateCount));
                }
                else rejected++;
                break;
            case ModelEventKind.ProviderOutcomeUnknown:
                if (existing < 0 || !Exact(operations[existing], item) || operations[existing].CreateCount != 1) rejected++;
                else operations[existing] = operations[existing] with { ProviderOutcome = ProviderOutcome.OutcomeUnknown };
                break;
            case ModelEventKind.ProviderLateCompletion:
                if (existing < 0 || !Exact(operations[existing], item) ||
                    operations[existing].CreateCount != 1 ||
                    operations[existing].ProviderOutcome != ProviderOutcome.OutcomeUnknown) rejected++;
                else operations[existing] = operations[existing] with { ProviderOutcome = ProviderOutcome.Completed };
                break;
            case ModelEventKind.MutationSucceeded:
                var node = state.Nodes.SingleOrDefault(value => value.Id == item.Node);
                if (node is not null && existing >= 0 && Exact(operations[existing], item) && operations[existing].Authorized &&
                    node.Id == state.Leader && node.AcceptedWriterEpoch == state.CurrentEpoch && item.Epoch == state.CurrentEpoch &&
                    !node.Crashed && !node.Partitioned && !completedOperations.Contains(item.Operation, StringComparer.Ordinal))
                { accepted++; completedOperations.Add(item.Operation);
                    acceptedActions.Add(Evidence(AcceptedActionKind.Mutation, item, state,
                        operations[existing].Authorized, node.Role, 1)); }
                else rejected++;
                break;
            case ModelEventKind.RequestTermination:
                var target = state.Nodes.SingleOrDefault(value => value.Id == item.Node);
                if (target?.Role == ModelNodeRole.Elastic)
                { terminations++; acceptedActions.Add(Evidence(AcceptedActionKind.Termination, item, state, true, target.Role, 1)); }
                else rejected++;
                break;
            case ModelEventKind.Delivery:
                break;
            default:
                return new(state, SimulationFailureCode.InvalidEvent);
        }
        return new(new(clock, state.Identities, state.CurrentEpoch, state.Leader, state.Nodes, operations, queue,
            delivered, accepted, rejected, terminations, completedOperations, acceptedActions), SimulationFailureCode.Completed);
    }

    private static SafetyInvariant FirstViolation(ModelState state)
    {
        if (state.Nodes.Count(node => node.AcceptedWriterEpoch == state.CurrentEpoch) > 1) return SafetyInvariant.SingleAcceptedWriter;
        if (!InvariantHolds(state, SafetyInvariant.NoStaleSuccessfulMutation)) return SafetyInvariant.NoStaleSuccessfulMutation;
        if (!InvariantHolds(state, SafetyInvariant.NoUnauthorizedAction)) return SafetyInvariant.NoUnauthorizedAction;
        if (!InvariantHolds(state, SafetyInvariant.NoUnsafeTermination)) return SafetyInvariant.NoUnsafeTermination;
        if (!InvariantHolds(state, SafetyInvariant.NoSecondCreateAfterUnknown)) return SafetyInvariant.NoSecondCreateAfterUnknown;
        if (!InvariantHolds(state, SafetyInvariant.QuorumFloorPreserved)) return SafetyInvariant.QuorumFloorPreserved;
        if (!InvariantHolds(state, SafetyInvariant.TerminalMutationUnique)) return SafetyInvariant.TerminalMutationUnique;
        return SafetyInvariant.Unspecified;
    }

    public static bool InvariantHolds(ModelState state, SafetyInvariant invariant, string? replayDigest = null) => invariant switch
    {
        SafetyInvariant.SingleAcceptedWriter => state.Nodes.Count(node => node.AcceptedWriterEpoch == state.CurrentEpoch) <= 1,
        SafetyInvariant.NoStaleSuccessfulMutation => state.AcceptedActions.Where(static action =>
            action.Kind is AcceptedActionKind.Authorization or AcceptedActionKind.Create or AcceptedActionKind.Mutation)
                .All(static action => action.EventEpoch == action.AuthorityEpoch &&
                    action.NodeAcceptedEpoch == action.AuthorityEpoch),
        SafetyInvariant.NoUnauthorizedAction => state.AcceptedActions.Where(static action =>
            action.Kind is AcceptedActionKind.Authorization or AcceptedActionKind.Create or AcceptedActionKind.Mutation)
                .All(action => FullAuthority(action) && ExactAcceptedIdentity(state, action)),
        SafetyInvariant.NoUnsafeTermination => state.AcceptedActions.Where(static action =>
            action.Kind == AcceptedActionKind.Termination).All(static action => action.NodeRole == ModelNodeRole.Elastic),
        SafetyInvariant.QuorumFloorPreserved => state.AcceptedActions.Where(static action =>
            action.Kind == AcceptedActionKind.Termination).All(static action => action.CriticalNodesAfter >= 3),
        SafetyInvariant.NoSecondCreateAfterUnknown => state.Operations.All(static operation => operation.CreateCount <= 1) &&
            state.AcceptedActions.Where(static action => action.Kind == AcceptedActionKind.Create)
                .GroupBy(static action => action.Operation, StringComparer.Ordinal).All(static group => group.Count() <= 1 &&
                    group.All(static action => action.Ordinal == 1)),
        SafetyInvariant.SnapshotReplayDigestEqual => string.Equals(state.Digest(), replayDigest, StringComparison.Ordinal),
        SafetyInvariant.TerminalMutationUnique => state.AcceptedActions.Where(static action =>
            action.Kind == AcceptedActionKind.Mutation).GroupBy(static action =>
                (action.Operation, action.Generation, action.IdempotencyKey, action.Resource))
                .All(static group => group.Count() <= 1),
        _ => false,
    };

    private static bool FullAuthority(AcceptedActionEvidence action) => action.Authorized &&
        action.Node == action.LeaderAtAcceptance && action.EventEpoch == action.AuthorityEpoch &&
        action.NodeAcceptedEpoch == action.AuthorityEpoch && !action.NodeCrashed && !action.NodePartitioned;
    private static bool ExactAcceptedIdentity(ModelState state, AcceptedActionEvidence action) => state.Operations.Any(operation =>
        operation.Operation == action.Operation && operation.Generation == action.Generation && operation.Epoch == action.EventEpoch &&
        operation.IdempotencyKey == action.IdempotencyKey && operation.Resource == action.Resource && operation.Authorized);

    private static bool Exact(ModelOperation operation, ModelEvent item) => operation.Operation == item.Operation &&
        operation.Generation == item.Generation && operation.Epoch == item.Epoch &&
        operation.IdempotencyKey == item.IdempotencyKey && operation.Resource == item.Resource;
    private static bool CurrentAuthority(ModelState state, ModelEvent item)
    {
        var node = state.Nodes.SingleOrDefault(value => value.Id == item.Node);
        return node is not null && node.Id == state.Leader && node.AcceptedWriterEpoch == state.CurrentEpoch &&
            item.Epoch == state.CurrentEpoch && !node.Crashed && !node.Partitioned;
    }
    private static AcceptedActionEvidence Evidence(AcceptedActionKind kind, ModelEvent item, ModelState state,
        bool authorized, ModelNodeRole role, int ordinal)
    {
        var node = state.Nodes.Single(value => value.Id == item.Node);
        return new(kind, item.Operation, item.Node, item.Generation, item.IdempotencyKey, item.Resource, item.Epoch,
            state.CurrentEpoch, state.Leader, node.AcceptedWriterEpoch, node.Crashed, node.Partitioned,
            authorized, role, ordinal, state.Nodes.Count(static value => value.Role == ModelNodeRole.Critical));
    }
    private static bool Valid(ModelEvent item) => item.Sequence > 0 && item.DueTick >= 0 && item.ObservationSequence > 0 &&
        item.Generation > 0 && item.Epoch > 0 && ModelValidation.Identity(item.EventId) && ModelValidation.Identity(item.Node) &&
        item.Node is "n1" or "n2" or "n3" &&
        ModelValidation.Identity(item.Operation) && ModelValidation.Identity(item.IdempotencyKey) &&
        ModelValidation.Identity(item.Resource) && Enum.IsDefined(item.Kind) && item.Kind != ModelEventKind.Unspecified;
    private static bool UpdateNode(ModelNode[] nodes, string id, bool? crashed = null, bool? partitioned = null,
        long? acceptedEpoch = null)
    {
        var index = Array.FindIndex(nodes, node => node.Id == id);
        if (index < 0) return false;
        nodes[index] = nodes[index] with { Crashed = crashed ?? nodes[index].Crashed,
            Partitioned = partitioned ?? nodes[index].Partitioned,
            AcceptedWriterEpoch = acceptedEpoch ?? nodes[index].AcceptedWriterEpoch };
        return true;
    }
    private static IEnumerable<FailureDirective?> Branches(ModelState state)
    {
        yield return null;
        yield return new(FailureKind.Loss, "n1", 0);
        yield return new(FailureKind.Duplicate, "n1", 0);
        yield return new(FailureKind.Reorder, "n1", 0);
        yield return new(FailureKind.Delay, "n1", 1);
        foreach (var node in state.Nodes)
        {
            if (!node.Crashed) yield return new(FailureKind.Crash, node.Id, 0);
            else yield return new(FailureKind.Restart, node.Id, 0);
            if (node.Id != state.Leader && !node.Crashed && !node.Partitioned)
                yield return new(FailureKind.LeaderChange, node.Id, 0);
            if (!node.Partitioned) yield return new(FailureKind.Partition, node.Id, 0);
            else yield return new(FailureKind.Heal, node.Id, 0);
        }
    }
    private static ModelState CopyState(ModelState state, VirtualClock? clock = null, ImmutableEventQueue? queue = null,
        ModelNode[]? nodes = null, long? epoch = null, string? leader = null) => new(clock ?? state.Clock,
        state.Identities, epoch ?? state.CurrentEpoch, leader ?? state.Leader, nodes ?? state.Nodes,
        state.Operations, queue ?? state.Queue, state.DeliveredEventIds, state.AcceptedMutations,
        state.RejectedMutations, state.Terminations, state.CompletedMutationOperations, state.AcceptedActions);
    private static SimulationResult Failure(ModelState state, SimulationFailureCode code, int steps, int schedules,
        IEnumerable<FailureDirective> schedule, SafetyInvariant invariant = SafetyInvariant.Unspecified) => new(state,
        code, invariant, steps, schedules, state.Digest(), new ReadOnlyCollection<FailureDirective>(schedule.ToArray()));
    private static MaterializationCode TryMaterialize<T>(IEnumerable<T> source, int maximum, out T[] values)
    {
        try
        {
            values = source.Take(maximum + 1).ToArray();
            if (values.Length <= maximum) return MaterializationCode.Completed;
            values = [];
            return MaterializationCode.BoundExceeded;
        }
        catch (Exception) { values = []; return MaterializationCode.Invalid; }
    }
    private enum MaterializationCode { Completed, BoundExceeded, Invalid }
    private sealed record Transition(ModelState State, SimulationFailureCode Code);
}
