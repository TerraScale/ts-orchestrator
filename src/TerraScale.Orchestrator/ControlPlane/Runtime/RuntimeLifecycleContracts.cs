using System.Security.Cryptography;
using System.Text;
using HostArchitecture = TerraScale.Orchestrator.Runtime.HostArchitecture;
using HostRuntimeDriver = TerraScale.Orchestrator.Runtime.RuntimeDriver;
using HostRuntimePlan = TerraScale.Orchestrator.Runtime.HostRuntimePlan;
using HostRole = TerraScale.Orchestrator.Runtime.AdmittedRole;

namespace TerraScale.Orchestrator.ControlPlane.Runtime;

/// <summary>Versioned, persistence-safe lifecycle contract. It intentionally contains fingerprints, never host execution material.</summary>
public static class RuntimeLifecycleContract
{
    public const int SchemaVersion = 1;
    public const int MaximumCasAttempts = 3;
    public const int MaximumCoordinatorSteps = 12;
}

public enum RuntimeLifecyclePhase
{
    Proposed = 1,
    Authorized = 2,
    DispatchPersisted = 3,
    InFlight = 4,
    ObservedConverged = 5,
    ObservedStopped = 6,
    Uncertain = 7,
    Failed = 8,
    Terminal = 9
}

public enum RuntimeLifecycleCallStatus { NotCalled = 1, DispatchPersisted = 2, InFlight = 3, ResponseLost = 4, ObservationRequired = 5, Observed = 6 }
public enum RuntimeLifecycleCompensationPolicy { None = 1, AuthorizedCleanup = 2 }
public enum RuntimeLifecycleTerminalStatus { None = 1, Converged = 2, Stopped = 3, ReconciliationRequired = 4, Failed = 5 }
public enum RuntimeLifecycleErrorCode { None = 1, AuthorityUnavailable = 2, AuthorityFenced = 3, IdentityMismatch = 4, JournalUnavailable = 5, JournalAmbiguous = 6, CasExhausted = 7, InvalidCheckpoint = 8, ObservationMismatch = 9, ExecutorResponseLost = 10, ExecutorFailed = 11, CancelledAfterDispatch = 12, UnsupportedCleanup = 13 }
public enum RuntimeLifecycleAuthorityStatus { ReadyLeader = 1, NotReady = 2, Follower = 3, Unavailable = 4 }
public enum RuntimeLifecycleJournalReadStatus { Found = 1, Missing = 2, Ambiguous = 3, Unavailable = 4 }
public enum RuntimeLifecycleJournalWriteStatus { Applied = 1, Conflict = 2, Missing = 3, Ambiguous = 4, Unavailable = 5 }
public enum RuntimeLifecycleExecutorStatus { Accepted = 1, Completed = 2, ResponseLost = 3, Failed = 4 }
public enum RuntimeLifecycleObservationStatus { Converged = 1, Stopped = 2, NotObserved = 3, Unknown = 4 }

public sealed record RuntimeLifecycleCellId : RuntimeToken { public RuntimeLifecycleCellId(string value) : base(value, nameof(value)) { } }
public sealed record RuntimeLifecycleOperationKey { public RuntimeLifecycleOperationKey(string value) => Value = RuntimeIdentity.Digest(value, nameof(value)); public string Value { get; } }
public sealed record RuntimeLifecyclePlanFingerprint { public RuntimeLifecyclePlanFingerprint(string value) => Value = RuntimeIdentity.Digest(value, nameof(value)); public string Value { get; } }
public sealed record RuntimeLifecycleHostObservationFingerprint { public RuntimeLifecycleHostObservationFingerprint(string value) => Value = RuntimeIdentity.Digest(value, nameof(value)); public string Value { get; } }

public sealed record RuntimeLifecycleDeadlineEvidence
{
    public RuntimeLifecycleDeadlineEvidence(RuntimeDigest digest, ulong watermark)
    {
        Digest = digest ?? throw new ArgumentNullException(nameof(digest));
        Watermark = watermark > 0 ? watermark : throw new ArgumentOutOfRangeException(nameof(watermark));
    }
    public RuntimeDigest Digest { get; }
    public ulong Watermark { get; }
}

public sealed record RuntimeLifecycleAuthority
{
    public RuntimeLifecycleAuthority(RuntimeLifecycleAuthorityStatus status, RuntimeEpoch epoch)
    {
        Status = RuntimeEnums.Defined(status, nameof(status));
        Epoch = epoch ?? throw new ArgumentNullException(nameof(epoch));
    }
    public RuntimeLifecycleAuthorityStatus Status { get; }
    public RuntimeEpoch Epoch { get; }
    public bool IsExactLeader(RuntimeEpoch expectedEpoch) => Status == RuntimeLifecycleAuthorityStatus.ReadyLeader && Epoch == expectedEpoch;
}

public sealed record RuntimeLifecycleOperationRequest
{
    public RuntimeLifecycleOperationRequest(
        RuntimeLifecycleCellId cell,
        RuntimeNodeId node,
        RuntimeGeneration workloadGeneration,
        RuntimeDigest acceptedConvergenceDigest,
        HostRuntimePlan plan,
        LifecycleAction action,
        RuntimeEpoch writerEpoch,
        RuntimeDigest authorizationEvidenceDigest,
        RuntimeLifecycleDeadlineEvidence deadlineEvidence,
        RuntimeLifecycleCompensationPolicy compensationPolicy = RuntimeLifecycleCompensationPolicy.None)
    {
        Cell = cell ?? throw new ArgumentNullException(nameof(cell));
        Node = node ?? throw new ArgumentNullException(nameof(node));
        WorkloadGeneration = workloadGeneration ?? throw new ArgumentNullException(nameof(workloadGeneration));
        AcceptedConvergenceDigest = acceptedConvergenceDigest ?? throw new ArgumentNullException(nameof(acceptedConvergenceDigest));
        Plan = plan ?? throw new ArgumentNullException(nameof(plan));
        Action = RuntimeEnums.Defined(action, nameof(action));
        if (Action == LifecycleAction.Cleanup)
            throw new ArgumentOutOfRangeException(nameof(action), "Destructive cleanup is not enabled by this lifecycle contract.");
        WriterEpoch = writerEpoch ?? throw new ArgumentNullException(nameof(writerEpoch));
        AuthorizationEvidenceDigest = authorizationEvidenceDigest ?? throw new ArgumentNullException(nameof(authorizationEvidenceDigest));
        DeadlineEvidence = deadlineEvidence ?? throw new ArgumentNullException(nameof(deadlineEvidence));
        CompensationPolicy = RuntimeEnums.Defined(compensationPolicy, nameof(compensationPolicy));
        if (CompensationPolicy != RuntimeLifecycleCompensationPolicy.None)
            throw new ArgumentOutOfRangeException(nameof(compensationPolicy), "Destructive cleanup is not enabled by this lifecycle contract.");
        PlanFingerprint = RuntimeLifecycleFingerprint.Plan(Plan);
        OperationKey = RuntimeLifecycleFingerprint.Operation(this);
    }

    public RuntimeLifecycleCellId Cell { get; }
    public RuntimeNodeId Node { get; }
    public RuntimeGeneration WorkloadGeneration { get; }
    public RuntimeDigest AcceptedConvergenceDigest { get; }
    public HostRuntimePlan Plan { get; }
    public LifecycleAction Action { get; }
    public RuntimeEpoch WriterEpoch { get; }
    public RuntimeDigest AuthorizationEvidenceDigest { get; }
    public RuntimeLifecycleDeadlineEvidence DeadlineEvidence { get; }
    public RuntimeLifecycleCompensationPolicy CompensationPolicy { get; }
    public RuntimeLifecyclePlanFingerprint PlanFingerprint { get; }
    public RuntimeLifecycleOperationKey OperationKey { get; }
}

public sealed record RuntimeLifecycleCheckpoint(
    int SchemaVersion,
    RuntimeLifecycleOperationKey OperationKey,
    RuntimeLifecycleCellId Cell,
    RuntimeNodeId Node,
    string AllocationId,
    RuntimeGeneration WorkloadGeneration,
    RuntimeDigest AcceptedConvergenceDigest,
    RuntimeLifecyclePlanFingerprint PlanFingerprint,
    HostRuntimeDriver Driver,
    HostRole Role,
    LifecycleAction Action,
    RuntimeLifecyclePhase Phase,
    RuntimeEpoch WriterEpoch,
    RuntimeDigest AuthorizationEvidenceDigest,
    RuntimeAttempt ExecutorAttempt,
    RuntimeDigest DispatchToken,
    RuntimeLifecycleCallStatus CallStatus,
    RuntimeLifecycleHostObservationFingerprint? LastObservationFingerprint,
    ulong LastObservationWatermark,
    RuntimeLifecycleDeadlineEvidence DeadlineEvidence,
    RuntimeLifecycleCompensationPolicy CompensationPolicy,
    ulong JournalRevision,
    RuntimeDigest PreviousEventDigest,
    RuntimeDigest EventDigest,
    RuntimeLifecycleTerminalStatus TerminalStatus,
    RuntimeLifecycleErrorCode ErrorCode)
{
    public static RuntimeLifecycleCheckpoint Proposed(RuntimeLifecycleOperationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var genesis = new RuntimeDigest(RuntimeLifecycleFingerprint.Hash("runtime-lifecycle-genesis-v1"));
        var checkpoint = new RuntimeLifecycleCheckpoint(
            RuntimeLifecycleContract.SchemaVersion, request.OperationKey, request.Cell, request.Node, request.Plan.AllocationId.Value,
            request.WorkloadGeneration, request.AcceptedConvergenceDigest, request.PlanFingerprint, request.Plan.Driver, request.Plan.Role,
            request.Action, RuntimeLifecyclePhase.Proposed, request.WriterEpoch, request.AuthorizationEvidenceDigest, new RuntimeAttempt(1),
            new RuntimeDigest(RuntimeLifecycleFingerprint.DispatchToken(request)), RuntimeLifecycleCallStatus.NotCalled, null, 0,
            request.DeadlineEvidence, request.CompensationPolicy, 0, genesis, genesis, RuntimeLifecycleTerminalStatus.None, RuntimeLifecycleErrorCode.None);
        return checkpoint with { EventDigest = RuntimeLifecycleFingerprint.Event(checkpoint) };
    }

    public bool Matches(RuntimeLifecycleOperationRequest request) =>
        SchemaVersion == RuntimeLifecycleContract.SchemaVersion && OperationKey == request.OperationKey && Cell == request.Cell && Node == request.Node &&
        AllocationId == request.Plan.AllocationId.Value && WorkloadGeneration == request.WorkloadGeneration && AcceptedConvergenceDigest == request.AcceptedConvergenceDigest &&
        PlanFingerprint == request.PlanFingerprint && Driver == request.Plan.Driver && Role == request.Plan.Role && Action == request.Action &&
        WriterEpoch == request.WriterEpoch && AuthorizationEvidenceDigest == request.AuthorizationEvidenceDigest && DeadlineEvidence == request.DeadlineEvidence &&
        CompensationPolicy == RuntimeLifecycleCompensationPolicy.None;
}

public sealed record RuntimeLifecycleJournalRead(RuntimeLifecycleJournalReadStatus Status, RuntimeLifecycleCheckpoint? Checkpoint);
public sealed record RuntimeLifecycleJournalWrite(RuntimeLifecycleJournalWriteStatus Status, RuntimeLifecycleCheckpoint? Checkpoint);

public interface IRuntimeLifecycleJournal
{
    ValueTask<RuntimeLifecycleJournalRead> ReadAsync(RuntimeLifecycleOperationKey operationKey, CancellationToken cancellationToken);
    ValueTask<RuntimeLifecycleJournalWrite> CompareExchangeAsync(RuntimeLifecycleOperationKey operationKey, ulong? expectedRevision, RuntimeLifecycleCheckpoint checkpoint, CancellationToken cancellationToken);
}

public interface IRuntimeLifecycleAuthorityGate
{
    ValueTask<RuntimeLifecycleAuthority> ReadAsync(RuntimeLifecycleCellId cell, CancellationToken cancellationToken);
}

public sealed record RuntimeLifecycleExecutionRequest(RuntimeLifecycleOperationKey OperationKey, RuntimeDigest DispatchToken, HostRuntimePlan Plan, LifecycleAction Action, RuntimeEpoch WriterEpoch);
public sealed record RuntimeLifecycleExecutorResponse(RuntimeLifecycleExecutorStatus Status);
/// <summary>Transient recovery context. The plan is supplied by the exact caller, never retained in the checkpoint.</summary>
public sealed record RuntimeLifecycleObservationRequest(
    RuntimeLifecycleOperationKey OperationKey,
    HostRuntimePlan Plan,
    LifecycleAction Action,
    RuntimeLifecyclePlanFingerprint PlanFingerprint,
    ulong PreviousObservationWatermark,
    RuntimeEpoch WriterEpoch,
    RuntimeDigest DispatchToken);
public sealed record RuntimeLifecycleObservation(
    RuntimeLifecycleOperationKey OperationKey,
    string AllocationId,
    RuntimeLifecyclePlanFingerprint PlanFingerprint,
    LifecycleAction Action,
    RuntimeLifecycleHostObservationFingerprint Fingerprint,
    ulong Watermark,
    RuntimeLifecycleObservationStatus Status);

public interface IRuntimeLifecycleHostExecutor
{
    ValueTask<RuntimeLifecycleExecutorResponse?> ExecuteAsync(RuntimeLifecycleExecutionRequest request, CancellationToken cancellationToken);
    ValueTask<RuntimeLifecycleObservation?> ObserveAsync(RuntimeLifecycleObservationRequest request, CancellationToken cancellationToken);
}

public sealed record RuntimeLifecycleResult(RuntimeLifecycleCheckpoint? Checkpoint, RuntimeLifecycleTerminalStatus Status, RuntimeLifecycleErrorCode ErrorCode)
{
    public bool RequiresReconciliation => Status == RuntimeLifecycleTerminalStatus.ReconciliationRequired;
}

public static class RuntimeLifecycleFingerprint
{
    public static RuntimeLifecyclePlanFingerprint Plan(HostRuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.SchemaVersion != 2 || !Enum.IsDefined(plan.Role) || !Enum.IsDefined(plan.Driver) || !Enum.IsDefined(plan.Architecture) ||
            plan.AllocationId is null || plan.ArtifactDigest is null || plan.Resources is null ||
            (plan.Driver == HostRuntimeDriver.NativeSystemd) != (plan.Systemd is not null) ||
            (plan.Driver == HostRuntimeDriver.OciContainer) != (plan.Oci is not null))
            throw new ArgumentException("Host runtime plan is not a supported closed plan.", nameof(plan));
        var fields = new List<string> { "host-runtime-plan-v1", plan.SchemaVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)plan.Role).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)plan.Driver).ToString(System.Globalization.CultureInfo.InvariantCulture), plan.AllocationId.Value, plan.ArtifactDigest.Value, ((int)plan.Architecture).ToString(System.Globalization.CultureInfo.InvariantCulture) };
        AddResources(fields, plan.Resources);
        if (plan.Systemd is not null)
        {
            fields.Add("systemd"); fields.Add(plan.Systemd.UnitName); fields.Add(plan.Systemd.Executable); AddList(fields, plan.Systemd.Arguments); AddList(fields, plan.Systemd.Properties);
        }
        if (plan.Oci is not null)
        {
            fields.Add("oci"); fields.Add(plan.Oci.ContainerId); fields.Add(plan.Oci.ImageReference); fields.Add(plan.Oci.Platform);
            fields.Add(plan.Oci.Security.RunAsUser.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(plan.Oci.Security.RunAsGroup.ToString(System.Globalization.CultureInfo.InvariantCulture));
            fields.Add(plan.Oci.Security.NoNewPrivileges ? "1" : "0"); fields.Add(plan.Oci.Security.ReadOnlyRootFileSystem ? "1" : "0"); AddList(fields, plan.Oci.Security.DroppedCapabilities); fields.Add(plan.Oci.Security.SeccompProfile); fields.Add(plan.Oci.Security.CgroupParent); AddResources(fields, plan.Oci.Resources);
        }
        return new(Hash(Canonical(fields)));
    }

    public static RuntimeLifecycleOperationKey Operation(RuntimeLifecycleOperationRequest request) => new(Hash(Canonical([
        "runtime-lifecycle-operation-v1", request.Cell.Value, request.Node.Value, request.Plan.AllocationId.Value, request.WorkloadGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), request.AcceptedConvergenceDigest.Sha256, ((int)request.Action).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)request.Plan.Driver).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)request.Plan.Role).ToString(System.Globalization.CultureInfo.InvariantCulture), request.PlanFingerprint.Value])));

    public static string DispatchToken(RuntimeLifecycleOperationRequest request) => Hash(Canonical(["runtime-lifecycle-dispatch-v1", request.OperationKey.Value, request.WriterEpoch.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), request.AuthorizationEvidenceDigest.Sha256]));

    public static RuntimeDigest Event(RuntimeLifecycleCheckpoint checkpoint) => new(Hash(Canonical([
        "runtime-lifecycle-event-v1", checkpoint.PreviousEventDigest.Sha256, checkpoint.OperationKey.Value, checkpoint.Cell.Value, checkpoint.Node.Value, checkpoint.AllocationId,
        checkpoint.WorkloadGeneration.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.AcceptedConvergenceDigest.Sha256, checkpoint.PlanFingerprint.Value,
        ((int)checkpoint.Driver).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.Role).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.Action).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.Phase).ToString(System.Globalization.CultureInfo.InvariantCulture),
        checkpoint.WriterEpoch.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.AuthorizationEvidenceDigest.Sha256, checkpoint.ExecutorAttempt.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.DispatchToken.Sha256,
        ((int)checkpoint.CallStatus).ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.LastObservationFingerprint?.Value ?? "", checkpoint.LastObservationWatermark.ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.DeadlineEvidence.Digest.Sha256, checkpoint.DeadlineEvidence.Watermark.ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.CompensationPolicy).ToString(System.Globalization.CultureInfo.InvariantCulture), checkpoint.JournalRevision.ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.TerminalStatus).ToString(System.Globalization.CultureInfo.InvariantCulture), ((int)checkpoint.ErrorCode).ToString(System.Globalization.CultureInfo.InvariantCulture)])));

    public static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Canonical(IEnumerable<string> values)
    {
        var builder = new StringBuilder();
        foreach (var value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            builder.Append(value.Length).Append(':').Append(value).Append(';');
        }
        return builder.ToString();
    }

    private static void AddResources(ICollection<string> fields, TerraScale.Orchestrator.Runtime.RuntimeResourceLimits resources)
    {
        fields.Add(resources.MemoryMaxBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(resources.TasksMax.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(resources.CpuQuotaPercent.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(resources.CpuWeight.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(resources.IoWeight.ToString(System.Globalization.CultureInfo.InvariantCulture)); fields.Add(resources.Nice.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static void AddList(ICollection<string> fields, IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        fields.Add(values.Count.ToString(System.Globalization.CultureInfo.InvariantCulture));
        foreach (var value in values) fields.Add(value ?? throw new ArgumentException("Plan contains null execution material."));
    }
}

