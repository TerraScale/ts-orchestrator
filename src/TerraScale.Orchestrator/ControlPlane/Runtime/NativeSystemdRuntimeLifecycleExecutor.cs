using System.Globalization;
using System.Text;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using SystemdAllocationObservation = TerraScale.Orchestrator.Runtime.SystemdAllocationObservation;
using SystemdAllocationState = TerraScale.Orchestrator.Runtime.SystemdAllocationState;
using NativeSystemdRuntimeAdmission = TerraScale.Orchestrator.Runtime.NativeSystemdRuntimeAdmission;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>
/// Narrow test seam around the already fail-closed native-systemd admission boundary.
/// Production construction retains its Linux/PID-1/cgroup-v2/fixed-binary checks.
/// </summary>
internal interface INativeSystemdRuntimeLifecycleAdmission
{
    Task ConvergeAsync(CancellationToken cancellationToken);
    Task<SystemdAllocationObservation> ObserveAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

internal interface INativeSystemdRuntimeLifecycleAdmissionFactory
{
    INativeSystemdRuntimeLifecycleAdmission Admit(HostRuntimePlan plan);
}

internal sealed class NativeSystemdRuntimeLifecycleAdmissionFactory : INativeSystemdRuntimeLifecycleAdmissionFactory
{
    public INativeSystemdRuntimeLifecycleAdmission Admit(HostRuntimePlan plan) =>
        new NativeSystemdRuntimeLifecycleAdmissionAdapter(NativeSystemdRuntimeAdmission.Create(plan));
}

internal sealed class NativeSystemdRuntimeLifecycleAdmissionAdapter(
    NativeSystemdRuntimeAdmission admission) : INativeSystemdRuntimeLifecycleAdmission
{
    private readonly NativeSystemdRuntimeAdmission admission = admission ?? throw new ArgumentNullException(nameof(admission));

    public Task ConvergeAsync(CancellationToken cancellationToken) => admission.ConvergeAsync(cancellationToken);
    public Task<SystemdAllocationObservation> ObserveAsync(CancellationToken cancellationToken) => admission.ObserveAsync(cancellationToken);
    public Task StopAsync(CancellationToken cancellationToken) => admission.StopAsync(cancellationToken);
}

/// <summary>
/// Native-systemd implementation of the persisted lifecycle executor contract.
/// It performs exactly one admitted host action per durable dispatch and always leaves
/// completion to a separate, read-only observation; it is intentionally not composed
/// into a production lifecycle route yet.
/// </summary>
public sealed class NativeSystemdRuntimeLifecycleExecutor : IRuntimeLifecycleHostExecutor
{
    private const string ObservationFingerprintDomain = "native-systemd-runtime-lifecycle-observation-v1";
    private readonly INativeSystemdRuntimeLifecycleAdmissionFactory admissionFactory;

    public NativeSystemdRuntimeLifecycleExecutor()
        : this(new NativeSystemdRuntimeLifecycleAdmissionFactory())
    {
    }

    internal NativeSystemdRuntimeLifecycleExecutor(
        INativeSystemdRuntimeLifecycleAdmissionFactory admissionFactory)
    {
        this.admissionFactory = admissionFactory ?? throw new ArgumentNullException(nameof(admissionFactory));
    }

    public async ValueTask<RuntimeLifecycleExecutorResponse?> ExecuteAsync(
        RuntimeLifecycleExecutionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        Validate(request.Plan, request.Action, RuntimeLifecycleFingerprint.Plan(request.Plan));

        var admission = admissionFactory.Admit(request.Plan);
        switch (request.Action)
        {
            case LifecycleAction.Converge:
                await admission.ConvergeAsync(cancellationToken).ConfigureAwait(false);
                break;
            case LifecycleAction.Drain:
            case LifecycleAction.Stop:
                await admission.StopAsync(cancellationToken).ConfigureAwait(false);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(request), "The lifecycle action is not supported by native systemd.");
        }

        // A completed systemd command is not convergence evidence. The coordinator
        // must persist and invoke ObserveAsync before reporting a terminal outcome.
        return new(RuntimeLifecycleExecutorStatus.Completed);
    }

    public async ValueTask<RuntimeLifecycleObservation?> ObserveAsync(
        RuntimeLifecycleObservationRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        Validate(request.Plan, request.Action, request.PlanFingerprint);
        var watermark = checked(request.PreviousObservationWatermark + 1);

        SystemdAllocationState? state = null;
        RuntimeLifecycleObservationStatus status;
        try
        {
            var admission = admissionFactory.Admit(request.Plan);
            var observation = await admission.ObserveAsync(cancellationToken).ConfigureAwait(false);
            state = observation?.State;
            status = observation is null
                ? RuntimeLifecycleObservationStatus.Unknown
                : MapObservation(request.Action, observation.State);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            // Admission and ownership/adapter failures have no safe positive claim.
            // Deliberately avoid carrying exception or host material into the durable
            // observation contract.
            status = RuntimeLifecycleObservationStatus.Unknown;
        }

        return new(
            request.OperationKey,
            request.Plan.AllocationId.Value,
            request.PlanFingerprint,
            request.Action,
            new RuntimeLifecycleHostObservationFingerprint(
                ObservationFingerprint(request, status, state)),
            watermark,
            status);
    }

    private static void Validate(
        HostRuntimePlan plan,
        LifecycleAction action,
        RuntimeLifecyclePlanFingerprint expectedPlanFingerprint)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(expectedPlanFingerprint);
        if (!Enum.IsDefined(action) || action == LifecycleAction.Cleanup)
        {
            throw new ArgumentOutOfRangeException(nameof(action), "Destructive cleanup is not supported by native systemd lifecycle execution.");
        }
        if (plan.Driver != HostRuntimeDriver.NativeSystemd)
        {
            throw new ArgumentException("Native systemd lifecycle execution requires a native systemd plan.", nameof(plan));
        }
        if (RuntimeLifecycleFingerprint.Plan(plan) != expectedPlanFingerprint)
        {
            throw new InvalidOperationException("The lifecycle request plan fingerprint does not bind the supplied plan.");
        }
    }

    private static RuntimeLifecycleObservationStatus MapObservation(
        LifecycleAction action,
        SystemdAllocationState state) => action switch
        {
            LifecycleAction.Converge when state == SystemdAllocationState.Running => RuntimeLifecycleObservationStatus.Converged,
            LifecycleAction.Drain or LifecycleAction.Stop when state is SystemdAllocationState.Absent or SystemdAllocationState.Stopped => RuntimeLifecycleObservationStatus.Stopped,
            LifecycleAction.Converge or LifecycleAction.Drain or LifecycleAction.Stop
                when state is SystemdAllocationState.Starting or SystemdAllocationState.Stopping => RuntimeLifecycleObservationStatus.NotObserved,
            _ => RuntimeLifecycleObservationStatus.Unknown
        };

    private static string ObservationFingerprint(
        RuntimeLifecycleObservationRequest request,
        RuntimeLifecycleObservationStatus status,
        SystemdAllocationState? state)
    {
        // The canonical input uses only already-hashed bindings and finite enum
        // values. Raw unit names, PIDs, systemd Result values, plans, and arguments
        // are intentionally absent from both the fingerprint and returned contract.
        var values = new[]
        {
            ObservationFingerprintDomain,
            request.OperationKey.Value,
            request.PlanFingerprint.Value,
            ((int)HostRuntimeDriver.NativeSystemd).ToString(CultureInfo.InvariantCulture),
            ((int)request.Action).ToString(CultureInfo.InvariantCulture),
            ((int)status).ToString(CultureInfo.InvariantCulture),
            state is null ? "unknown" : ((int)state.Value).ToString(CultureInfo.InvariantCulture)
        };
        var canonical = new StringBuilder();
        foreach (var value in values)
        {
            canonical.Append(value.Length).Append(':').Append(value).Append(';');
        }
        return RuntimeLifecycleFingerprint.Hash(canonical.ToString());
    }
}

