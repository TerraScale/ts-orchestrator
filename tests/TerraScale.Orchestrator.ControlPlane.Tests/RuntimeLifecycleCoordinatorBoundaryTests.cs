using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class RuntimeLifecycleCoordinatorBoundaryTests
{
    [Test]
    public async Task AmbiguousJournalReadFailsClosedBeforeAuthorityOrHostAccess()
    {
        var journal = new Journal
        {
            ReadResult = new(RuntimeLifecycleJournalReadStatus.Ambiguous, null)
        };
        var authority = new Authority();
        var executor = new Executor();

        var result = await new RuntimeLifecycleCoordinator(journal, authority, executor)
            .ExecuteAsync(Request(), CancellationToken.None);

        await Assert.That(result.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.Failed);
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.JournalAmbiguous);
        await Assert.That(authority.Reads).IsEqualTo(0);
        await Assert.That(executor.ExecuteCalls).IsEqualTo(0);
        await Assert.That(executor.ObserveCalls).IsEqualTo(0);
        await Assert.That(journal.Writes).IsEqualTo(0);
    }

    [Test]
    public async Task FencedAuthorityStopsBeforeTheFirstHostMutation()
    {
        var journal = new Journal();
        var authority = new Authority
        {
            Value = new(RuntimeLifecycleAuthorityStatus.Follower, new RuntimeEpoch(7))
        };
        var executor = new Executor();

        var result = await new RuntimeLifecycleCoordinator(journal, authority, executor)
            .ExecuteAsync(Request(), CancellationToken.None);

        await Assert.That(result.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.Failed);
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.AuthorityFenced);
        await Assert.That(result.Checkpoint?.Phase).IsEqualTo(RuntimeLifecyclePhase.Proposed);
        await Assert.That(executor.ExecuteCalls).IsEqualTo(0);
        await Assert.That(executor.ObserveCalls).IsEqualTo(0);
    }

    [Test]
    public async Task ObservationMustMatchOperationAndAdvanceWatermark()
    {
        var request = Request();
        var journal = new Journal();
        var executor = new Executor
        {
            Response = new(RuntimeLifecycleExecutorStatus.ResponseLost)
        };
        _ = await new RuntimeLifecycleCoordinator(journal, new Authority(), executor)
            .ExecuteAsync(request, CancellationToken.None);

        executor.Observation = new(
            request.OperationKey,
            request.Plan.AllocationId.Value,
            request.PlanFingerprint,
            request.Action,
            new(RuntimeLifecycleFingerprint.Hash("observation")),
            0,
            RuntimeLifecycleObservationStatus.Converged);

        var result = await new RuntimeLifecycleCoordinator(journal, new Authority(), executor)
            .ExecuteAsync(request, CancellationToken.None);

        await Assert.That(result.Status).IsEqualTo(RuntimeLifecycleTerminalStatus.ReconciliationRequired);
        await Assert.That(result.ErrorCode).IsEqualTo(RuntimeLifecycleErrorCode.ObservationMismatch);
        await Assert.That(executor.ExecuteCalls).IsEqualTo(1);
        await Assert.That(executor.ObserveCalls).IsEqualTo(1);
    }

    private static RuntimeLifecycleOperationRequest Request()
    {
        var plan = HostRuntimePlan.Create(
            HostRole.CustomerDashboard,
            HostRuntimeDriver.OciContainer,
            new TerraScale.Orchestrator.Runtime.RuntimeAllocationId("platform-a"),
            new TerraScale.Orchestrator.Runtime.ArtifactDigest(RuntimeLifecycleFingerprint.Hash("artifact")),
            HostArchitecture.Arm64);
        return new(
            new("gru"),
            new("node-a"),
            new(7),
            new(RuntimeLifecycleFingerprint.Hash("convergence")),
            plan,
            LifecycleAction.Converge,
            new(7),
            new(RuntimeLifecycleFingerprint.Hash("authorization")),
            new(new(RuntimeLifecycleFingerprint.Hash("deadline")), 9));
    }

    private sealed class Journal : IRuntimeLifecycleJournal
    {
        private readonly Dictionary<string, RuntimeLifecycleCheckpoint> _values = [];

        public RuntimeLifecycleJournalRead ReadResult { get; set; } = new(RuntimeLifecycleJournalReadStatus.Missing, null);
        public int Writes { get; private set; }

        public ValueTask<RuntimeLifecycleJournalRead> ReadAsync(
            RuntimeLifecycleOperationKey operationKey,
            CancellationToken cancellationToken) =>
            _values.TryGetValue(operationKey.Value, out var checkpoint)
                ? ValueTask.FromResult(new RuntimeLifecycleJournalRead(RuntimeLifecycleJournalReadStatus.Found, checkpoint))
                : ValueTask.FromResult(ReadResult);

        public ValueTask<RuntimeLifecycleJournalWrite> CompareExchangeAsync(
            RuntimeLifecycleOperationKey operationKey,
            ulong? expectedRevision,
            RuntimeLifecycleCheckpoint checkpoint,
            CancellationToken cancellationToken)
        {
            Writes++;
            if (expectedRevision is not null || _values.ContainsKey(operationKey.Value))
            {
                return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Conflict, null));
            }

            _values[operationKey.Value] = checkpoint;
            return ValueTask.FromResult(new RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus.Applied, checkpoint));
        }
    }

    private sealed class Authority : IRuntimeLifecycleAuthorityGate
    {
        public RuntimeLifecycleAuthority Value { get; set; } = new(RuntimeLifecycleAuthorityStatus.ReadyLeader, new RuntimeEpoch(7));
        public int Reads { get; private set; }

        public ValueTask<RuntimeLifecycleAuthority> ReadAsync(
            RuntimeLifecycleCellId cell,
            CancellationToken cancellationToken)
        {
            Reads++;
            return ValueTask.FromResult(Value);
        }
    }

    private sealed class Executor : IRuntimeLifecycleHostExecutor
    {
        public RuntimeLifecycleExecutorResponse? Response { get; set; } = new(RuntimeLifecycleExecutorStatus.ResponseLost);
        public RuntimeLifecycleObservation? Observation { get; set; }
        public int ExecuteCalls { get; private set; }
        public int ObserveCalls { get; private set; }

        public ValueTask<RuntimeLifecycleExecutorResponse?> ExecuteAsync(
            RuntimeLifecycleExecutionRequest request,
            CancellationToken cancellationToken)
        {
            ExecuteCalls++;
            return ValueTask.FromResult(Response);
        }

        public ValueTask<RuntimeLifecycleObservation?> ObserveAsync(
            RuntimeLifecycleObservationRequest request,
            CancellationToken cancellationToken)
        {
            ObserveCalls++;
            return ValueTask.FromResult(Observation);
        }
    }
}
