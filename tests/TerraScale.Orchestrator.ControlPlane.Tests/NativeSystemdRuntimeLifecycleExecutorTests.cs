using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;
using SystemdAllocationObservation = TerraScale.Orchestrator.Runtime.SystemdAllocationObservation;
using SystemdAllocationState = TerraScale.Orchestrator.Runtime.SystemdAllocationState;
using TerraScale.Orchestrator.ControlPlane.Runtime;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class NativeSystemdRuntimeLifecycleExecutorTests
{
    [Test]
    public async Task ExecuteDispatchesExactlyOneCanonicalActionAndRequiresObservation()
    {
        foreach (var action in new[] { LifecycleAction.Converge, LifecycleAction.Drain, LifecycleAction.Stop })
        {
            var admission = new Admission();
            var executor = new NativeSystemdRuntimeLifecycleExecutor(new Factory(admission));

            var response = RequireResponse(await executor.ExecuteAsync(Execution(action), CancellationToken.None));

            await Assert.That(response.Status).IsEqualTo(RuntimeLifecycleExecutorStatus.Completed);
            await Assert.That(admission.ConvergeCalls).IsEqualTo(action == LifecycleAction.Converge ? 1 : 0);
            await Assert.That(admission.StopCalls).IsEqualTo(action == LifecycleAction.Converge ? 0 : 1);
            await Assert.That(admission.ObserveCalls).IsEqualTo(0);
        }
    }

    [Test]
    public async Task ObserveMapsOnlySafeSystemdStatesAndBindsTheExactRequest()
    {
        var cases = new[]
        {
            (LifecycleAction.Converge, SystemdAllocationState.Running, RuntimeLifecycleObservationStatus.Converged),
            (LifecycleAction.Converge, SystemdAllocationState.Starting, RuntimeLifecycleObservationStatus.NotObserved),
            (LifecycleAction.Stop, SystemdAllocationState.Stopped, RuntimeLifecycleObservationStatus.Stopped),
            (LifecycleAction.Drain, SystemdAllocationState.Absent, RuntimeLifecycleObservationStatus.Stopped),
            (LifecycleAction.Stop, SystemdAllocationState.Stopping, RuntimeLifecycleObservationStatus.NotObserved),
            (LifecycleAction.Stop, SystemdAllocationState.Failed, RuntimeLifecycleObservationStatus.Unknown),
            (LifecycleAction.Stop, SystemdAllocationState.Running, RuntimeLifecycleObservationStatus.Unknown)
        };

        foreach (var (action, state, expected) in cases)
        {
            var admission = new Admission { Observation = Observation(state) };
            var executor = new NativeSystemdRuntimeLifecycleExecutor(new Factory(admission));
            var request = ObservationRequest(action, previousWatermark: 41);

            var observed = RequireObservation(await executor.ObserveAsync(request, CancellationToken.None));

            await Assert.That(observed.Status).IsEqualTo(expected);
            await Assert.That(observed.OperationKey).IsEqualTo(request.OperationKey);
            await Assert.That(observed.AllocationId).IsEqualTo(request.Plan.AllocationId.Value);
            await Assert.That(observed.PlanFingerprint).IsEqualTo(request.PlanFingerprint);
            await Assert.That(observed.Action).IsEqualTo(request.Action);
            await Assert.That(observed.Watermark).IsEqualTo(42UL);
            await Assert.That(observed.Fingerprint.Value).Length().IsEqualTo(64);
            await Assert.That(admission.ObserveCalls).IsEqualTo(1);
        }
    }

    [Test]
    public async Task ObserveMapsAdmissionAndOwnershipAdapterFailuresToUnknownWithoutHostMaterial()
    {
        var rawUnit = "terrascale-secret-unit.service";
        var rawResult = "host-private-result";
        var admission = new Admission { ObserveException = new InvalidOperationException($"{rawUnit}:{rawResult}:4312") };
        var executor = new NativeSystemdRuntimeLifecycleExecutor(new Factory(admission));
        var observed = RequireObservation(await executor.ObserveAsync(ObservationRequest(LifecycleAction.Stop), CancellationToken.None));

        await Assert.That(observed.Status).IsEqualTo(RuntimeLifecycleObservationStatus.Unknown);
        await Assert.That(observed.ToString()).DoesNotContain(rawUnit);
        await Assert.That(observed.ToString()).DoesNotContain(rawResult);
        await Assert.That(observed.ToString()).DoesNotContain("4312");

        var admissionFailure = new Factory(new Admission()) { AdmissionException = new InvalidOperationException($"{rawUnit}:{rawResult}") };
        var admissionObserved = RequireObservation(await new NativeSystemdRuntimeLifecycleExecutor(admissionFailure)
            .ObserveAsync(ObservationRequest(LifecycleAction.Stop), CancellationToken.None));
        await Assert.That(admissionObserved.Status).IsEqualTo(RuntimeLifecycleObservationStatus.Unknown);
        await Assert.That(admissionObserved.ToString()).DoesNotContain(rawUnit);
        await Assert.That(admissionObserved.ToString()).DoesNotContain(rawResult);
    }

    [Test]
    public async Task InvalidDriverFingerprintAndCleanupAreRejectedBeforeAdmission()
    {
        var admission = new Admission();
        var factory = new Factory(admission);
        var executor = new NativeSystemdRuntimeLifecycleExecutor(factory);
        var valid = ObservationRequest(LifecycleAction.Converge);
        var ociPlan = HostRuntimePlan.Create(HostRole.Platform, HostRuntimeDriver.OciContainer,
            new("platform-a"), new(Digest("oci")), HostArchitecture.Arm64);

        await Assert.That(async () => await executor.ObserveAsync(valid with { Plan = ociPlan }, CancellationToken.None))
            .Throws<ArgumentException>();
        await Assert.That(async () => await executor.ObserveAsync(valid with { PlanFingerprint = new(Digest("wrong-plan")) }, CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await executor.ExecuteAsync(Execution(LifecycleAction.Cleanup), CancellationToken.None))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(factory.Admissions).IsEqualTo(0);
    }

    [Test]
    public async Task ObservationWatermarkOverflowFailsBeforeAdmission()
    {
        var admission = new Admission();
        var factory = new Factory(admission);
        var executor = new NativeSystemdRuntimeLifecycleExecutor(factory);

        await Assert.That(async () => await executor.ObserveAsync(
                ObservationRequest(LifecycleAction.Converge, ulong.MaxValue), CancellationToken.None))
            .Throws<OverflowException>();
        await Assert.That(factory.Admissions).IsEqualTo(0);
    }

    [Test]
    public async Task CallerCancellationAndExecutionAdmissionFailuresPropagateWithoutRetries()
    {
        var cancelled = new Admission { ConvergeCancellation = true };
        var cancellationFactory = new Factory(cancelled);
        var executor = new NativeSystemdRuntimeLifecycleExecutor(cancellationFactory);
        using var source = new CancellationTokenSource();
        source.Cancel();

        await Assert.That(async () => await executor.ExecuteAsync(Execution(LifecycleAction.Converge), source.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(cancelled.ConvergeCalls).IsEqualTo(1);
        await Assert.That(cancellationFactory.Admissions).IsEqualTo(1);

        var failedFactory = new Factory(new Admission()) { AdmissionException = new InvalidOperationException("admission-failed") };
        var failedExecutor = new NativeSystemdRuntimeLifecycleExecutor(failedFactory);
        await Assert.That(async () => await failedExecutor.ExecuteAsync(Execution(LifecycleAction.Converge), CancellationToken.None))
            .Throws<InvalidOperationException>();
        await Assert.That(failedFactory.Admissions).IsEqualTo(1);
    }

    [Test]
    public async Task FingerprintsAreCanonicalAndDoNotContainRawSystemdMaterial()
    {
        var rawUnit = "terrascale-private.service";
        var rawResult = "private-result";
        var admission = new Admission { Observation = new(rawUnit, SystemdAllocationState.Running, 9123, rawResult) };
        var executor = new NativeSystemdRuntimeLifecycleExecutor(new Factory(admission));
        var request = ObservationRequest(LifecycleAction.Converge);

        var first = RequireObservation(await executor.ObserveAsync(request, CancellationToken.None));
        var second = RequireObservation(await executor.ObserveAsync(request, CancellationToken.None));

        await Assert.That(first.Fingerprint).IsEqualTo(second.Fingerprint);
        await Assert.That(first.ToString()).DoesNotContain(rawUnit);
        await Assert.That(first.ToString()).DoesNotContain(rawResult);
        await Assert.That(first.ToString()).DoesNotContain("9123");
        var executable = request.Plan.Systemd?.Executable
            ?? throw new InvalidOperationException("The test plan must contain a native systemd execution plan.");
        await Assert.That(first.ToString()).DoesNotContain(executable);
        await Assert.That(first.ToString()).DoesNotContain("TS_ORCH_CONFIG");

        var checkpoint = RuntimeLifecycleCheckpoint.Proposed(OperationRequest()) with
        {
            LastObservationFingerprint = first.Fingerprint,
            LastObservationWatermark = first.Watermark
        };
        await Assert.That(checkpoint.ToString()).DoesNotContain(rawUnit);
        await Assert.That(checkpoint.ToString()).DoesNotContain(rawResult);
        await Assert.That(checkpoint.ToString()).DoesNotContain("9123");
        await Assert.That(checkpoint.ToString()).DoesNotContain(executable);
    }

    private static RuntimeLifecycleExecutionRequest Execution(LifecycleAction action)
    {
        var plan = Plan();
        return new(new(Digest("operation")), new(Digest("dispatch")), plan, action, new(7));
    }

    private static RuntimeLifecycleObservationRequest ObservationRequest(
        LifecycleAction action,
        ulong previousWatermark = 0)
    {
        var plan = Plan();
        return new(new(Digest("operation")), plan, action, RuntimeLifecycleFingerprint.Plan(plan), previousWatermark,
            new(7), new(Digest("dispatch")));
    }

    private static RuntimeLifecycleOperationRequest OperationRequest()
    {
        var plan = Plan();
        return new(new("gru"), new("node-a"), new(7), new(Digest("convergence")), plan,
            LifecycleAction.Converge, new(7), new(Digest("authorization")), new(new(Digest("deadline")), 9));
    }

    private static HostRuntimePlan Plan() => HostRuntimePlan.Create(HostRole.TerraBaseMember,
        HostRuntimeDriver.NativeSystemd, new("terrabase-a"), new(Digest("artifact")), HostArchitecture.Arm64);

    private static SystemdAllocationObservation Observation(SystemdAllocationState state) =>
        new("terrascale-terrabase-a.service", state, 9123, "private-result");

    private static string Digest(string input) => RuntimeLifecycleFingerprint.Hash(input);

    private static RuntimeLifecycleExecutorResponse RequireResponse(RuntimeLifecycleExecutorResponse? response) =>
        response ?? throw new InvalidOperationException("The executor must return a response for this test.");

    private static RuntimeLifecycleObservation RequireObservation(RuntimeLifecycleObservation? observation) =>
        observation ?? throw new InvalidOperationException("The executor must return an observation for this test.");

    private sealed class Factory(Admission admission) : INativeSystemdRuntimeLifecycleAdmissionFactory
    {
        private readonly Admission admission = admission;
        public int Admissions { get; private set; }
        public Exception? AdmissionException { get; init; }

        public INativeSystemdRuntimeLifecycleAdmission Admit(HostRuntimePlan plan)
        {
            Admissions++;
            if (AdmissionException is not null) throw AdmissionException;
            return admission;
        }
    }

    private sealed class Admission : INativeSystemdRuntimeLifecycleAdmission
    {
        public int ConvergeCalls { get; private set; }
        public int StopCalls { get; private set; }
        public int ObserveCalls { get; private set; }
        public bool ConvergeCancellation { get; init; }
        public Exception? ObserveException { get; init; }
        public SystemdAllocationObservation? Observation { get; init; }

        public Task ConvergeAsync(CancellationToken cancellationToken)
        {
            ConvergeCalls++;
            cancellationToken.ThrowIfCancellationRequested();
            return ConvergeCancellation ? Task.FromCanceled(cancellationToken) : Task.CompletedTask;
        }

        public Task<SystemdAllocationObservation> ObserveAsync(CancellationToken cancellationToken)
        {
            ObserveCalls++;
            cancellationToken.ThrowIfCancellationRequested();
            if (ObserveException is not null) throw ObserveException;
            return Task.FromResult(Observation ?? new SystemdAllocationObservation("unit", SystemdAllocationState.Absent, null, "not-found"));
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            StopCalls++;
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}
