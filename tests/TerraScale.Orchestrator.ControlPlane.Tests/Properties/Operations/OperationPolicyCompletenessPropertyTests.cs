using TerraScale.Orchestrator.ControlPlane.Operations;

namespace TerraScale.Orchestrator.ControlPlane.Tests.Properties.Operations;

public sealed class OperationPolicyCompletenessPropertyTests
{
    private const int Cases = 1_000;
    private static readonly DateTimeOffset Start = new(2026, 7, 14, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task CrashReplayReemitsOnlyExactFrozenMutationOrReadOnlyRecoveryFor1000Cases()
    {
        var completed = 0;
        for (var index = 0; index < Cases; index++)
        {
            var subject = Subject(index);
            var compensations = new[] { $"observe-{index}", $"quarantine-{index}" };
            var prepared = OperationEngine.Decide([], new PrepareOperation(subject.OperationId,
                subject.Epoch, Start, subject.Desired, subject.Expected, compensations));
            compensations[0] = "caller-mutated";
            var history = prepared.EventsToAppend.ToList();
            history.AddRange(OperationEngine.Decide(history, new AuthorizeOperation(subject.OperationId,
                subject.Epoch + 1, Start.AddMinutes(1), subject.Evidence)).EventsToAppend);
            var dispatchCommand = new RecordDispatch(subject.OperationId, subject.Epoch + 2,
                Start.AddMinutes(2), $"executor-{index}", 1);
            var dispatch = OperationEngine.Decide(history, dispatchCommand);
            var mutation = (DispatchProviderIntent)dispatch.Intents.Single();
            RequireDispatch(mutation, subject, index);
            history.AddRange(dispatch.EventsToAppend);

            var beforeDeadline = (DispatchProviderIntent)OperationEngine.Decide(history, dispatchCommand).Intents.Single();
            RequireDispatch(beforeDeadline, subject, index);
            var expired = OperationEngine.Decide(history, dispatchCommand with { Now = subject.Desired.Deadline });
            RequireReconcile(expired, subject, null);

            var outcome = index % 2 == 0 ? ProviderOutcome.Unknown : ProviderOutcome.InProgress;
            var workRequest = index % 3 == 0 ? null : $"work-{index}";
            var observation = new RecordObservation(subject.OperationId, subject.Epoch + 2,
                Start.AddMinutes(3), $"observation-{index}", subject.Desired.TargetIdentity,
                subject.Desired.Generation, "pending", outcome, workRequest);
            var observed = OperationEngine.Decide(history, observation);
            RequireReconcile(observed, subject, workRequest);
            history.AddRange(observed.EventsToAppend);
            var replayed = OperationEngine.Decide(history, observation);
            RequireReconcile(replayed, subject, workRequest);
            if (replayed.EventsToAppend.Count != 0)
                throw new InvalidOperationException($"duplicate observation appended at case {index}");

            var conflict = OperationEngine.Decide(history, observation with
            {
                Now = Start.AddMinutes(4),
                TerminalState = "running",
                Outcome = ProviderOutcome.Succeeded,
            });
            if (conflict.EventsToAppend.Count != 0 || conflict.Intents.Count != 0 ||
                conflict.Errors.Single().Code != OperationErrorCode.ConflictingTerminalObservation)
                throw new InvalidOperationException($"observation identity rebound at case {index}");
            completed++;
        }

        await Assert.That(completed).IsEqualTo(Cases);
    }

    [Test]
    public async Task DeadlineHoldIsIrreversibleInCommandsAndReplayFor1000Cases()
    {
        var completed = 0;
        for (var index = 0; index < Cases; index++)
        {
            var subject = Subject(index);
            var prepared = OperationEngine.Decide([], new PrepareOperation(subject.OperationId,
                subject.Epoch, Start, subject.Desired, subject.Expected,
                [$"observe-{index}", $"quarantine-{index}"]));
            var history = prepared.EventsToAppend.ToList();
            var deadlineTime = subject.Desired.Deadline.AddTicks(index % 2);
            var held = OperationEngine.Decide(history, new AuthorizeOperation(subject.OperationId,
                subject.Epoch + 1, deadlineTime, subject.Evidence));
            history.AddRange(held.EventsToAppend);
            var heldState = OperationEngine.Replay(history).State;

            var rewound = OperationEngine.Decide(history, new AuthorizeOperation(subject.OperationId,
                subject.Epoch + 2, subject.Desired.Deadline.AddTicks(-1), subject.Evidence));
            RequireDeadlineHold(rewound, heldState, index);

            var sequence = heldState.LastSequence + 1;
            var authorizationDigest = OperationDigest.Authorization(sequence, heldState.JournalDigest,
                subject.OperationId, subject.Epoch + 2, subject.Desired, subject.Evidence,
                heldState.PermittedCompensations);
            var body = new OperationAuthorized(sequence, heldState.JournalDigest, string.Empty,
                subject.OperationId, subject.Epoch + 2, subject.Desired.Deadline.AddTicks(-1),
                subject.Evidence, authorizationDigest);
            var forged = body with { EventDigest = OperationDigest.Event(body) };
            var replay = OperationEngine.Replay(history.Append(forged).ToArray());
            if (replay.Errors.Single().Code != OperationErrorCode.InvalidJournal || replay.Intents.Count != 0 ||
                OperationDigest.State(replay.State) != OperationDigest.State(heldState))
                throw new InvalidOperationException($"forged deadline recovery replayed at case {index}");

            var authorizedHistory = prepared.EventsToAppend.ToList();
            authorizedHistory.AddRange(OperationEngine.Decide(authorizedHistory,
                new AuthorizeOperation(subject.OperationId, subject.Epoch + 1,
                    Start.AddMinutes(1), subject.Evidence)).EventsToAppend);
            var dispatchHold = OperationEngine.Decide(authorizedHistory,
                new RecordDispatch(subject.OperationId, subject.Epoch + 2, deadlineTime,
                    $"executor-{index}", 1));
            authorizedHistory.AddRange(dispatchHold.EventsToAppend);
            var dispatchHeldState = OperationEngine.Replay(authorizedHistory).State;
            var dispatchRewind = OperationEngine.Decide(authorizedHistory,
                new RecordDispatch(subject.OperationId, subject.Epoch + 3,
                    subject.Desired.Deadline.AddTicks(-1), $"executor-new-{index}", 1));
            RequireDeadlineHold(dispatchRewind, dispatchHeldState, index);
            var dispatchBody = new OperationDispatchRecorded(dispatchHeldState.LastSequence + 1,
                dispatchHeldState.JournalDigest, string.Empty, subject.OperationId, subject.Epoch + 3,
                subject.Desired.Deadline.AddTicks(-1), $"executor-new-{index}", 1);
            var forgedDispatch = dispatchBody with { EventDigest = OperationDigest.Event(dispatchBody) };
            var dispatchReplay = OperationEngine.Replay(authorizedHistory.Append(forgedDispatch).ToArray());
            if (dispatchReplay.Errors.Single().Code != OperationErrorCode.InvalidJournal ||
                dispatchReplay.Intents.Count != 0 ||
                OperationDigest.State(dispatchReplay.State) != OperationDigest.State(dispatchHeldState))
                throw new InvalidOperationException($"forged dispatch deadline recovery replayed at case {index}");
            completed++;
        }

        await Assert.That(completed).IsEqualTo(Cases);
    }

    private static void RequireDispatch(DispatchProviderIntent intent, OperationSubject subject, int index)
    {
        var expectedCompensations = new[] { $"observe-{index}", $"quarantine-{index}" };
        if (intent.OperationId != subject.OperationId || intent.OperationKind != subject.Desired.OperationKind ||
            intent.AggregateId != subject.Desired.AggregateId ||
            intent.DesiredGeneration != subject.Desired.Generation ||
            intent.DesiredResourceVersion != subject.Desired.ResourceVersion ||
            intent.TargetIdentity != subject.Desired.TargetIdentity ||
            intent.DesiredTerminalState != subject.Desired.DesiredTerminalState ||
            intent.PayloadDigest != subject.Desired.PayloadDigest ||
            intent.IdempotencyKey != subject.Desired.IdempotencyKey ||
            intent.AuthorizedObservationId != subject.Evidence.Observation.ObservationId ||
            intent.AuthorizedResourceVersion != subject.Evidence.Observation.ResourceVersion ||
            !intent.PermittedCompensations.SequenceEqual(expectedCompensations, StringComparer.Ordinal) ||
            intent.AuthorizationSequence != 2 || string.IsNullOrWhiteSpace(intent.AuthorizationDigest) ||
            intent.AuthorizingEpoch != subject.Epoch + 1 || intent.ExecutorEpoch != subject.Epoch + 2 ||
            intent.ExecutorId != $"executor-{index}" || intent.DispatchAttempt != 1 ||
            intent.Deadline != subject.Desired.Deadline)
            throw new InvalidOperationException($"dispatch subject mismatch at case {index}");
    }

    private static void RequireReconcile(OperationDecision decision, OperationSubject subject, string? workRequest)
    {
        if (decision.Errors.Count != 0 || decision.Intents.Count != 1 ||
            decision.Intents.Single() is not ReconcileProviderIntent intent ||
            intent.OperationId != subject.OperationId || intent.TargetIdentity != subject.Desired.TargetIdentity ||
            intent.DesiredGeneration != subject.Desired.Generation ||
            intent.IdempotencyKey != subject.Desired.IdempotencyKey ||
            intent.ProviderWorkRequestId != workRequest || intent.AuthorizationSequence != 2 ||
            string.IsNullOrWhiteSpace(intent.AuthorizationDigest))
            throw new InvalidOperationException($"reconcile subject mismatch for {subject.OperationId}");
    }

    private static void RequireDeadlineHold(OperationDecision decision, OperationState expected, int index)
    {
        if (decision.EventsToAppend.Count != 0 || decision.Intents.Count != 0 ||
            decision.Errors.Single().Code != OperationErrorCode.DeadlineExpired ||
            OperationDigest.State(decision.State) != OperationDigest.State(expected))
            throw new InvalidOperationException($"deadline hold changed at case {index}");
    }

    private static OperationSubject Subject(int index)
    {
        var generation = index + 1L;
        var epoch = 100L + index;
        var operation = $"operation-{index}";
        var aggregate = $"aggregate-{index}";
        var target = $"node-{index}";
        var desired = new DesiredOperation(aggregate, generation, $"desired-rv-{index}",
            index % 2 == 0 ? "create-node" : "terminate-node", target,
            index % 2 == 0 ? "running" : "terminated", $"sha256:payload-{index}",
            $"idempotency-{index}", Start.AddMinutes(10).AddSeconds(index));
        var expected = new ObservedResource(aggregate, generation, $"expected-rv-{index}",
            $"expected-{index}", target, "absent", true);
        var evidence = new AuthorizationEvidence(new ObservedResource(aggregate, generation,
            $"authorized-rv-{index}", $"authorized-{index}", target, "absent", true),
            $"sha256:approval-{index}", $"sha256:evidence-{index}", true, true, true, true);
        return new(operation, epoch, desired, expected, evidence);
    }

    private sealed record OperationSubject(string OperationId, long Epoch, DesiredOperation Desired,
        ObservedResource Expected, AuthorizationEvidence Evidence);
}
