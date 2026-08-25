using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class RuntimeLifecycleCoordinatorTests
{
    [Test]
    public async Task CanonicalIdentityIsStableAndEveryBoundInputFencesTheExistingCheckpoint()
    {
        var exact = Request();
        var repeat = Request();
        await Assert.That(exact.OperationKey).IsEqualTo(repeat.OperationKey);
        await Assert.That(exact.PlanFingerprint).IsEqualTo(repeat.PlanFingerprint);

        var checkpoint = RuntimeLifecycleCheckpoint.Proposed(exact);
        foreach (var tampered in new[]
                 {
                     checkpoint with { SchemaVersion = 2 },
                     checkpoint with { WorkloadGeneration = new RuntimeGeneration(8) },
                     checkpoint with { WriterEpoch = new RuntimeEpoch(8) },
                     checkpoint with { PlanFingerprint = new RuntimeLifecyclePlanFingerprint(Digest("other-plan")) },
                     checkpoint with { CompensationPolicy = RuntimeLifecycleCompensationPolicy.AuthorizedCleanup },
                     checkpoint with { Phase = (RuntimeLifecyclePhase)99 },
                     checkpoint with { EventDigest = new RuntimeDigest(Digest("tampered-event")) }
                 })
        {
            var journal = new Journal();
            journal.Put(exact.OperationKey, tampered);
            var result = await new RuntimeLifecycleCoordinator(journal, new Authority(), new Executor()).ExecuteAsync(exact, CancellationToken.None);
            await Assert.That(result.ErrorCode is RuntimeLifecycleErrorCode.IdentityMismatch or RuntimeLifecycleErrorCode.InvalidCheckpoint).IsTrue();
            await Assert.That(journal.Checkpoint).IsEqualTo(tampered);
        }
    }

    [Test]
    public async Task DispatchIsPersistedBeforeItsSingleMutationAndExactRetriesRecoverWithoutDuplication()
    {
        var journal = new Journal();
        var executor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.Completed) };
        executor.BeforeExecute = () => executor.SeenDispatchPersisted = journal.Checkpoint?.Phase == RuntimeLifecyclePhase.InFlight;
        var coordinator = new RuntimeLifecycleCoordinator(journal, new Authority(), executor);
        var request = Request();

        var first = await coordinator.ExecuteAsync(request, CancellationToken.None);
        await Assert.That(first.RequiresReconciliation).IsTrue();
        await Assert.That(executor.Calls).IsEqualTo(1);
        await Assert.That(executor.SeenDispatchPersisted).IsTrue();

        executor.Observation = Observation(request, RuntimeLifecycleObservationStatus.Converged, 1);
        var second = await coordinator.ExecuteAsync(request, CancellationToken.None);
        var third = await coordinator.ExecuteAsync(request, CancellationToken.None);
        var fourth = await coordinator.ExecuteAsync(request, CancellationToken.None);
        await Assert.That(second.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.None);
        await Assert.That(third.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.Converged);
        await Assert.That(fourth.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.Converged);
        await Assert.That(executor.Calls).IsEqualTo(1);
        await Assert.That(executor.Observations).IsEqualTo(1);
    }

    [Test]
    public async Task PersistedOrInflightRecoveryObservesBeforeAnyPossibleRepeat()
    {
        var request = Request();
        var journal = new Journal();
        var originalExecutor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.ResponseLost) };
        var first = await new RuntimeLifecycleCoordinator(journal, new Authority(), originalExecutor).ExecuteAsync(request, CancellationToken.None);
        await Assert.That(first.RequiresReconciliation).IsTrue();
        await Assert.That(originalExecutor.Calls).IsEqualTo(1);

        var persistedCheckpoint = journal.Checkpoint
            ?? throw new InvalidOperationException("The first lifecycle execution must persist a checkpoint.");
        var persisted = persistedCheckpoint with
        {
            LastObservationFingerprint = new RuntimeLifecycleHostObservationFingerprint(Digest("persisted-observation")),
            LastObservationWatermark = 41
        };
        journal.Put(request.OperationKey, persisted with { EventDigest = RuntimeLifecycleFingerprint.Event(persisted) });
        var restartedExecutor = new Executor { Observation = Observation(request, RuntimeLifecycleObservationStatus.Converged, 42) };
        var recovery = new RuntimeLifecycleCoordinator(journal, new Authority(), restartedExecutor);
        _ = await recovery.ExecuteAsync(request, CancellationToken.None);
        var terminal = await recovery.ExecuteAsync(request, CancellationToken.None);
        await Assert.That(terminal.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.Converged);
        await Assert.That(restartedExecutor.Calls).IsEqualTo(0);
        await Assert.That(restartedExecutor.Observations).IsEqualTo(1);
        var observationRequest = restartedExecutor.LastObservationRequest
            ?? throw new InvalidOperationException("Recovery must record its observation request.");
        await Assert.That(observationRequest.Plan).IsSameReferenceAs(request.Plan);
        await Assert.That(observationRequest.Action).IsEqualTo(request.Action);
        await Assert.That(observationRequest.PlanFingerprint).IsEqualTo(request.PlanFingerprint);
        await Assert.That(observationRequest.PreviousObservationWatermark).IsEqualTo(41UL);
        await Assert.That(observationRequest.WriterEpoch).IsEqualTo(request.WriterEpoch);
    }

    [Test]
    public async Task AuthorityLossAndCancellationAfterDispatchAreUncertainNeverSafeRetries()
    {
        var request = Request();
        var journal = new Journal();
        var authority = new Authority { AfterExecute = new(RuntimeLifecycleAuthorityStatus.Follower, new RuntimeEpoch(7)) };
        var executor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.Completed) };
        var result = await new RuntimeLifecycleCoordinator(journal, authority, executor).ExecuteAsync(request, CancellationToken.None);
        await Assert.That(result.RequiresReconciliation).IsTrue();
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.AuthorityFenced);
        await Assert.That(executor.Calls).IsEqualTo(1);

        var cancelledJournal = new Journal();
        var cancelledExecutor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.Completed) };
        var cancelledCoordinator = new RuntimeLifecycleCoordinator(cancelledJournal, new Authority(), cancelledExecutor);
        var source = new CancellationTokenSource();
        cancelledExecutor.BeforeExecute = source.Cancel;
        var cancelled = await cancelledCoordinator.ExecuteAsync(request, source.Token);
        await Assert.That(cancelled.RequiresReconciliation).IsTrue();
        await Assert.That(cancelled.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.CancelledAfterDispatch);
        await Assert.That(cancelledExecutor.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task CancellationBeforeDurableDispatchPropagatesWithoutHostCall()
    {
        var executor = new Executor();
        var source = new CancellationTokenSource();
        source.Cancel();
        await Assert.That(async () => await new RuntimeLifecycleCoordinator(new Journal(), new Authority(), executor).ExecuteAsync(Request(), source.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(executor.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task ForeignWrongActionAndNullObservationsAreFencedAndCleanupCannotBeRequested()
    {
        var request = Request();
        var journal = new Journal();
        var executor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.ResponseLost) };
        _ = await new RuntimeLifecycleCoordinator(journal, new Authority(), executor).ExecuteAsync(request, CancellationToken.None);
        executor.Observation = Observation(request, RuntimeLifecycleObservationStatus.Converged, 1) with { AllocationId = "foreign" };
        var result = await new RuntimeLifecycleCoordinator(journal, new Authority(), executor).ExecuteAsync(request, CancellationToken.None);
        await Assert.That(result.RequiresReconciliation).IsTrue();
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.ObservationMismatch);

        var wrongActionJournal = new Journal();
        var wrongActionExecutor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.ResponseLost) };
        _ = await new RuntimeLifecycleCoordinator(wrongActionJournal, new Authority(), wrongActionExecutor).ExecuteAsync(request, CancellationToken.None);
        wrongActionExecutor.Observation = Observation(request, RuntimeLifecycleObservationStatus.Converged, 1) with { Action = LifecycleAction.Stop };
        var wrongAction = await new RuntimeLifecycleCoordinator(wrongActionJournal, new Authority(), wrongActionExecutor).ExecuteAsync(request, CancellationToken.None);
        await Assert.That(wrongAction.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.ObservationMismatch);

        var nullObservationJournal = new Journal();
        var nullObservationExecutor = new Executor { Response = new(RuntimeLifecycleExecutorStatus.ResponseLost), ReturnNullObservation = true };
        _ = await new RuntimeLifecycleCoordinator(nullObservationJournal, new Authority(), nullObservationExecutor).ExecuteAsync(request, CancellationToken.None);
        var nullObservation = await new RuntimeLifecycleCoordinator(nullObservationJournal, new Authority(), nullObservationExecutor).ExecuteAsync(request, CancellationToken.None);
        await Assert.That(nullObservation.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.ObservationMismatch);
        await Assert.That(() => Request(compensation: RuntimeLifecycleCompensationPolicy.AuthorizedCleanup)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => new RuntimeLifecycleOperationRequest(new("gru"), new("node-a"), new(7), new(Digest("convergence")), Request().Plan, LifecycleAction.Cleanup, new(7), new(Digest("authorization")), new(new(Digest("deadline")), 9))).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task CasConflictsAreBoundedAndDoNotCallTheExecutor()
    {
        var journal = new Journal { ConflictWrites = RuntimeLifecycleContract.MaximumCoordinatorSteps + 2 };
        var executor = new Executor();
        var result = await new RuntimeLifecycleCoordinator(journal, new Authority(), executor).ExecuteAsync(Request(), CancellationToken.None);
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.CasExhausted);
        await Assert.That(executor.Calls).IsEqualTo(0);
        await Assert.That(journal.Writes).IsLessThanOrEqualTo(RuntimeLifecycleContract.MaximumCoordinatorSteps);
    }

    [Test]
    public async Task NullExecutorResponseFailsClosedAfterDurableDispatch()
    {
        var executor = new Executor { Response = null };
        var result = await new RuntimeLifecycleCoordinator(new Journal(), new Authority(), executor).ExecuteAsync(Request(), CancellationToken.None);
        await Assert.That(result.RequiresReconciliation).IsTrue();
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.ExecutorFailed);
        await Assert.That(executor.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task PlanFingerprintReplayCasesRemainCanonicalWithoutRetainingRawExecutionMaterial()
    {
        for (var value = 1; value <= 32; value++)
        {
            var request = Request(digest: Digest($"artifact-{value}"));
            var checkpoint = RuntimeLifecycleCheckpoint.Proposed(request);
            await Assert.That(checkpoint.OperationKey).IsEqualTo(request.OperationKey);
            await Assert.That(checkpoint.ToString()).DoesNotContain("Environment=");
            await Assert.That(checkpoint.ToString()).DoesNotContain("--config");
        }
    }

    private static RuntimeLifecycleOperationRequest Request(string? digest = null, RuntimeLifecycleCompensationPolicy compensation = RuntimeLifecycleCompensationPolicy.None)
    {
        var plan = HostRuntimePlan.Create(HostRole.Platform, HostRuntimeDriver.OciContainer,
            new TerraScale.Orchestrator.Runtime.RuntimeAllocationId("platform-a"), new TerraScale.Orchestrator.Runtime.ArtifactDigest(digest ?? Digest("artifact")), HostArchitecture.Arm64);
        return new(new("gru"), new("node-a"), new(7), new(Digest("convergence")), plan, LifecycleAction.Converge, new(7), new(Digest("authorization")), new(new(Digest("deadline")), 9), compensation);
    }

    private static RuntimeLifecycleObservation Observation(RuntimeLifecycleOperationRequest request, RuntimeLifecycleObservationStatus status, ulong watermark) =>
        new(request.OperationKey, request.Plan.AllocationId.Value, request.PlanFingerprint, request.Action, new(Digest($"observation-{watermark}")), watermark, status);

    private static string Digest(string input) => RuntimeLifecycleFingerprint.Hash(input);

    private sealed class Journal : IRuntimeLifecycleJournal
    {
        private readonly Dictionary<string, RuntimeLifecycleCheckpoint> _values = [];
        public int ConflictWrites { get; set; }
        public int Writes { get; private set; }
        public RuntimeLifecycleCheckpoint? Checkpoint => _values.Values.SingleOrDefault();
        public void Put(RuntimeLifecycleOperationKey key, RuntimeLifecycleCheckpoint checkpoint) => _values[key.Value] = checkpoint;
        public ValueTask<RuntimeLifecycleJournalRead> ReadAsync(RuntimeLifecycleOperationKey operationKey, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_values.TryGetValue(operationKey.Value, out var checkpoint)
                ? new RuntimeLifecycleJournalRead(RuntimeLifecycleJournalReadStatus.Found, checkpoint)
                : new RuntimeLifecycleJournalRead(RuntimeLifecycleJournalReadStatus.Missing, null));
        public ValueTask<RuntimeLifecycleJournalWrite> CompareExchangeAsync(RuntimeLifecycleOperationKey operationKey, ulong? expectedRevision, RuntimeLifecycleCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            Writes++;
            if (ConflictWrites-- > 0) return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Conflict, null));
            if (_values.TryGetValue(operationKey.Value, out var current))
            {
                if (expectedRevision != current.JournalRevision) return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Conflict, current));
            }
            else if (expectedRevision is not null) return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Missing, null));
            _values[operationKey.Value] = checkpoint;
            return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Applied, checkpoint));
        }
    }

    private sealed class Authority : IRuntimeLifecycleAuthorityGate
    {
        private int _reads;
        public RuntimeLifecycleAuthority? AfterExecute { get; set; }
        public ValueTask<RuntimeLifecycleAuthority> ReadAsync(RuntimeLifecycleCellId cell, CancellationToken cancellationToken) =>
            ValueTask.FromResult(++_reads > 3 && AfterExecute is not null ? AfterExecute : new RuntimeLifecycleAuthority(RuntimeLifecycleAuthorityStatus.ReadyLeader, new RuntimeEpoch(7)));
    }

    private sealed class Executor : IRuntimeLifecycleHostExecutor
    {
        public int Calls { get; private set; }
        public int Observations { get; private set; }
        public bool SeenDispatchPersisted { get; set; }
        public Action? BeforeExecute { get; set; }
        public RuntimeLifecycleExecutorResponse? Response { get; set; } = new(RuntimeLifecycleExecutorStatus.ResponseLost);
        public RuntimeLifecycleObservation? Observation { get; set; }
        public RuntimeLifecycleObservationRequest? LastObservationRequest { get; private set; }
        public bool ReturnNullObservation { get; set; }
        public ValueTask<RuntimeLifecycleExecutorResponse?> ExecuteAsync(RuntimeLifecycleExecutionRequest request, CancellationToken cancellationToken)
        {
            Calls++; BeforeExecute?.Invoke(); return ValueTask.FromResult(Response);
        }
        public ValueTask<RuntimeLifecycleObservation?> ObserveAsync(RuntimeLifecycleObservationRequest request, CancellationToken cancellationToken)
        {
            Observations++; LastObservationRequest = request;
            return ValueTask.FromResult(ReturnNullObservation ? null : Observation ?? new(request.OperationKey, "unknown", new RuntimeLifecyclePlanFingerprint(Digest("unknown")), LifecycleAction.Converge, new RuntimeLifecycleHostObservationFingerprint(Digest("unknown-observation")), 1, RuntimeLifecycleObservationStatus.Unknown));
        }
    }
}
