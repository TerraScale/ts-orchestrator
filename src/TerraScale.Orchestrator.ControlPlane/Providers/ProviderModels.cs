using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

/// <summary>Technical caller-input snapshot limits; these are not provider inventory or ownership policy.</summary>
public static class ProviderTechnicalInputLimits
{
    public const int MaximumOperationEvidenceCount = 4_096;
    public const int MaximumApprovalCount = 64;
    public const int MaximumCompensationCount = 64;
    public const int MaximumHandoffInventoryCount = 4_096;
}

internal static class ProviderInputSnapshot
{
    internal static T[] Copy<T>(IEnumerable<T> source, int maximum, string parameterName, string inputName)
    {
        ArgumentNullException.ThrowIfNull(source, parameterName);
        var values = new List<T>(Math.Min(maximum, 256));
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (values.Count == maximum)
                    throw new ArgumentException($"{inputName} exceeds the technical snapshot bound.", parameterName);
                values.Add(enumerator.Current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            throw new ArgumentException($"{inputName} could not be captured within the technical snapshot bound.", parameterName);
        }
        return values.ToArray();
    }
}

internal static partial class ProviderIdentity
{
    public static string Validate(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 96 || !Pattern().IsMatch(value))
        {
            throw new ArgumentException("Provider identity must be a bounded canonical token.", name);
        }
        return value;
    }

    public static string ValidateNative(string value, string name)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        if (value.Length is < 1 or > 256 || !NativePattern().IsMatch(value))
        {
            throw new ArgumentException("Provider-native identity must be bounded and canonical.", name);
        }
        return value;
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9]*(?:[.-][a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex Pattern();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:/=+@-]{0,255}$", RegexOptions.CultureInvariant)]
    private static partial Regex NativePattern();
}

public abstract record ProviderToken
{
    internal ProviderToken(string value, string name) => Value = ProviderIdentity.Validate(value, name);
    internal ProviderToken(string value, string name, bool providerNative) =>
        Value = providerNative ? ProviderIdentity.ValidateNative(value, name) : ProviderIdentity.Validate(value, name);
    public string Value { get; }
    public sealed override string ToString() => Value;
}

public sealed record ProviderOperationId : ProviderToken { public ProviderOperationId(string value) : base(value, nameof(value)) { } }
public sealed record ProviderCellId : ProviderToken { public ProviderCellId(string value) : base(value, nameof(value)) { } }
public sealed record ProviderCompartmentId : ProviderToken { public ProviderCompartmentId(string value) : base(value, nameof(value)) { } }
public sealed record ProviderResourceId : ProviderToken { public ProviderResourceId(string value) : base(value, nameof(value), providerNative: true) { } }
public sealed record ProviderCreateKey : ProviderToken { public ProviderCreateKey(string value) : base(value, nameof(value)) { } }
public sealed record ProviderTemplateId : ProviderToken { public ProviderTemplateId(string value) : base(value, nameof(value)) { } }
public sealed record ProviderPlacementId : ProviderToken { public ProviderPlacementId(string value) : base(value, nameof(value)) { } }
public sealed record ProviderBackendId : ProviderToken { public ProviderBackendId(string value) : base(value, nameof(value), providerNative: true) { } }
public sealed record ProviderIdempotencyKey : ProviderToken { public ProviderIdempotencyKey(string value) : base(value, nameof(value)) { } }
public sealed record ProviderWorkRequestId : ProviderToken { public ProviderWorkRequestId(string value) : base(value, nameof(value), providerNative: true) { } }

public sealed record ProviderGeneration
{
    public ProviderGeneration(ulong value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public ulong Value { get; }
}

public sealed record ProviderEpoch
{
    public ProviderEpoch(ulong value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public ulong Value { get; }
}

public sealed record ProviderByteCount
{
    public ProviderByteCount(ulong value) => Value = value > 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    public ulong Value { get; }
}

public sealed record ProviderBootstrapEnvelopeDigest
{
    public ProviderBootstrapEnvelopeDigest(string sha256)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        if (sha256.Length != 64 || sha256.Any(character => character is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("Bootstrap envelope digest must be canonical SHA-256.", nameof(sha256));
        Sha256 = sha256;
    }
    public string Sha256 { get; }
}

public enum ProviderResourceKind
{
    Node = 1, Volume = 2, Attachment = 3, Backend = 4,
}

public enum ProviderAction
{
    CreateNode = 1, Observe = 2, StartNode = 3, StopNode = 4, TerminateNode = 5,
    CreateVolume = 6, ExpandVolume = 7, ChangeVolumePerformance = 8,
    AttachVolume = 9, DetachVolume = 10, RegisterBackend = 11, DeregisterBackend = 12,
}

public enum ProviderTerminalState
{
    Present = 1, Running = 2, Stopped = 3, Terminated = 4, Expanded = 5,
    PerformanceChanged = 6, Attached = 7, Detached = 8, Registered = 9, Deregistered = 10,
}

public enum ProviderApproval
{
    RegionalAuthority = 1, DestructiveMutation = 2, StatefulController = 3, CostBudget = 4, SecurityReview = 5,
}

public enum ProviderCompensation
{
    ObserveOnly = 1, StopCreatedNode = 2, TerminateCreatedNode = 3, DetachNewAttachment = 4, DeregisterNewBackend = 5,
}

public enum ProviderVolumePerformance { Balanced = 1, Throughput = 2, Iops = 3 }

public enum DeadlineEvidenceStatus { Valid = 1, Expired = 2, Unknown = 3 }
public sealed record DeadlineEvidence
{
    public DeadlineEvidence(DeadlineEvidenceStatus status, ProviderGeneration evidenceGeneration)
    {
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        Status = status;
        EvidenceGeneration = evidenceGeneration ?? throw new ArgumentNullException(nameof(evidenceGeneration));
    }
    public DeadlineEvidenceStatus Status { get; }
    public ProviderGeneration EvidenceGeneration { get; }
}

public abstract record ProviderTarget
{
    internal ProviderTarget() { }
    internal abstract string Projection { get; }
}
public sealed record ExistingProviderResource : ProviderTarget
{
    public ExistingProviderResource(ProviderResourceId id) => Id = id ?? throw new ArgumentNullException(nameof(id));
    public ProviderResourceId Id { get; }
    internal override string Projection => $"resource:{Id.Value}";
}
public sealed record IdempotentProviderCreate : ProviderTarget
{
    public IdempotentProviderCreate(ProviderCreateKey key) => Key = key ?? throw new ArgumentNullException(nameof(key));
    public ProviderCreateKey Key { get; }
    internal override string Projection => $"create:{Key.Value}";
}

public abstract record ProviderActionParameters
{
    internal ProviderActionParameters() { }
    internal abstract string Projection { get; }
}
public sealed record ObserveProviderParameters : ProviderActionParameters { internal override string Projection => "observe"; }
public sealed record StartNodeProviderParameters : ProviderActionParameters { internal override string Projection => "start-node"; }
public sealed record StopNodeProviderParameters : ProviderActionParameters { internal override string Projection => "stop-node"; }
public sealed record TerminateNodeProviderParameters : ProviderActionParameters { internal override string Projection => "terminate-node"; }
public sealed record DetachVolumeProviderParameters : ProviderActionParameters { internal override string Projection => "detach-volume"; }
public sealed record CreateNodeProviderParameters : ProviderActionParameters
{
    public CreateNodeProviderParameters(ProviderTemplateId templateId, ProviderPlacementId placementId, ProviderBootstrapEnvelopeDigest bootstrapEnvelopeDigest)
    {
        TemplateId = templateId ?? throw new ArgumentNullException(nameof(templateId));
        PlacementId = placementId ?? throw new ArgumentNullException(nameof(placementId));
        BootstrapEnvelopeDigest = bootstrapEnvelopeDigest ?? throw new ArgumentNullException(nameof(bootstrapEnvelopeDigest));
    }
    public ProviderTemplateId TemplateId { get; }
    public ProviderPlacementId PlacementId { get; }
    public ProviderBootstrapEnvelopeDigest BootstrapEnvelopeDigest { get; }
    internal override string Projection => string.Join('|', "create-node", TemplateId.Value, PlacementId.Value, BootstrapEnvelopeDigest.Sha256);
}
public sealed record CreateVolumeProviderParameters : ProviderActionParameters
{
    public CreateVolumeProviderParameters(ProviderByteCount size, ProviderVolumePerformance performance)
    {
        Size = size ?? throw new ArgumentNullException(nameof(size));
        if (!Enum.IsDefined(performance)) throw new ArgumentOutOfRangeException(nameof(performance));
        Performance = performance;
    }
    public ProviderByteCount Size { get; }
    public ProviderVolumePerformance Performance { get; }
    internal override string Projection => string.Join('|', "create-volume", Size.Value.ToString(CultureInfo.InvariantCulture), Performance);
}
public sealed record ExpandVolumeProviderParameters : ProviderActionParameters
{
    public ExpandVolumeProviderParameters(ProviderByteCount newSize) => NewSize = newSize ?? throw new ArgumentNullException(nameof(newSize));
    public ProviderByteCount NewSize { get; }
    internal override string Projection => $"expand-volume|{NewSize.Value.ToString(CultureInfo.InvariantCulture)}";
}
public sealed record ChangeVolumePerformanceProviderParameters : ProviderActionParameters
{
    public ChangeVolumePerformanceProviderParameters(ProviderVolumePerformance performance)
    {
        if (!Enum.IsDefined(performance)) throw new ArgumentOutOfRangeException(nameof(performance));
        Performance = performance;
    }
    public ProviderVolumePerformance Performance { get; }
    internal override string Projection => $"change-volume-performance|{Performance}";
}
public sealed record AttachVolumeProviderParameters : ProviderActionParameters
{
    public AttachVolumeProviderParameters(ProviderResourceId volumeId, ProviderResourceId nodeId)
    {
        VolumeId = volumeId ?? throw new ArgumentNullException(nameof(volumeId));
        NodeId = nodeId ?? throw new ArgumentNullException(nameof(nodeId));
    }
    public ProviderResourceId VolumeId { get; }
    public ProviderResourceId NodeId { get; }
    internal override string Projection => string.Join('|', "attach-volume", VolumeId.Value, NodeId.Value);
}
public sealed record RegisterBackendProviderParameters : ProviderActionParameters
{
    public RegisterBackendProviderParameters(ProviderBackendId backendId) => BackendId = backendId ?? throw new ArgumentNullException(nameof(backendId));
    public ProviderBackendId BackendId { get; }
    internal override string Projection => $"register-backend|{BackendId.Value}";
}
public sealed record DeregisterBackendProviderParameters : ProviderActionParameters
{
    public DeregisterBackendProviderParameters(ProviderBackendId backendId) => BackendId = backendId ?? throw new ArgumentNullException(nameof(backendId));
    public ProviderBackendId BackendId { get; }
    internal override string Projection => $"deregister-backend|{BackendId.Value}";
}

public sealed class ProviderOperationContext
{
    public ProviderOperationContext(
        ProviderOperationId operationId, ProviderCellId cellId, ProviderCompartmentId compartmentId,
        ProviderEpoch controllerEpoch, ProviderResourceKind resourceKind, ProviderAction action,
        ProviderTarget target, ProviderGeneration expectedGeneration, ProviderObservedState expectedObservedState,
        ProviderTerminalState desiredTerminalState,
        IEnumerable<ProviderApproval> approvals, DeadlineEvidence deadlineEvidence,
        ProviderIdempotencyKey idempotencyKey, IEnumerable<ProviderCompensation> permittedCompensations,
        ProviderActionParameters actionParameters)
    {
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        CompartmentId = compartmentId ?? throw new ArgumentNullException(nameof(compartmentId));
        ControllerEpoch = controllerEpoch ?? throw new ArgumentNullException(nameof(controllerEpoch));
        if (!Enum.IsDefined(resourceKind) || !Enum.IsDefined(action) || !Enum.IsDefined(expectedObservedState) || !Enum.IsDefined(desiredTerminalState))
            throw new ArgumentOutOfRangeException(nameof(action));
        ResourceKind = resourceKind; Action = action; DesiredTerminalState = desiredTerminalState;
        Target = target ?? throw new ArgumentNullException(nameof(target));
        ExpectedGeneration = expectedGeneration ?? throw new ArgumentNullException(nameof(expectedGeneration));
        ExpectedObservedState = expectedObservedState;
        Approvals = CopyEnums(approvals, ProviderTechnicalInputLimits.MaximumApprovalCount, nameof(approvals));
        DeadlineEvidence = deadlineEvidence ?? throw new ArgumentNullException(nameof(deadlineEvidence));
        IdempotencyKey = idempotencyKey ?? throw new ArgumentNullException(nameof(idempotencyKey));
        PermittedCompensations = CopyEnums(permittedCompensations, ProviderTechnicalInputLimits.MaximumCompensationCount, nameof(permittedCompensations));
        ActionParameters = actionParameters ?? throw new ArgumentNullException(nameof(actionParameters));
        var isCreate = action is ProviderAction.CreateNode or ProviderAction.CreateVolume;
        if (isCreate && target is not IdempotentProviderCreate)
            throw new ArgumentException("Create actions require a create key.");
        if (!isCreate && target is not ExistingProviderResource)
            throw new ArgumentException("Non-create actions require an existing resource target.");
    }

    public ProviderOperationId OperationId { get; }
    public ProviderCellId CellId { get; }
    public ProviderCompartmentId CompartmentId { get; }
    public ProviderEpoch ControllerEpoch { get; }
    public ProviderResourceKind ResourceKind { get; }
    public ProviderAction Action { get; }
    public ProviderTarget Target { get; }
    public ProviderGeneration ExpectedGeneration { get; }
    public ProviderObservedState ExpectedObservedState { get; }
    public ProviderTerminalState DesiredTerminalState { get; }
    public IReadOnlyList<ProviderApproval> Approvals { get; }
    public DeadlineEvidence DeadlineEvidence { get; }
    public ProviderIdempotencyKey IdempotencyKey { get; }
    public IReadOnlyList<ProviderCompensation> PermittedCompensations { get; }
    public ProviderActionParameters ActionParameters { get; }

    internal string Fingerprint => string.Join('|', OperationId.Value, CellId.Value, CompartmentId.Value,
        Invariant(ControllerEpoch.Value), ResourceKind, Action, Target.Projection, Invariant(ExpectedGeneration.Value), ExpectedObservedState,
        DesiredTerminalState, string.Join(',', Approvals), DeadlineEvidence.Status,
        Invariant(DeadlineEvidence.EvidenceGeneration.Value), IdempotencyKey.Value,
        string.Join(',', PermittedCompensations), ActionParameters.Projection);

    private static string Invariant(ulong value) => value.ToString(CultureInfo.InvariantCulture);

    private static IReadOnlyList<T> CopyEnums<T>(IEnumerable<T> source, int maximum, string name) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = ProviderInputSnapshot.Copy(source, maximum, name, "Provider enum input");
        if (values.Any(value => !Enum.IsDefined(value))) throw new ArgumentOutOfRangeException(name);
        if (values.Length != values.Distinct().Count()) throw new ArgumentException("Duplicate values are invalid.", name);
        return new ReadOnlyCollection<T>(values.Order().ToArray());
    }
}

public sealed record RegionalProviderAuthority
{
    public RegionalProviderAuthority(ProviderCellId cellId, ProviderCompartmentId compartmentId, ProviderEpoch currentEpoch)
    { CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); CompartmentId = compartmentId ?? throw new ArgumentNullException(nameof(compartmentId)); CurrentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch)); }
    public ProviderCellId CellId { get; }
    public ProviderCompartmentId CompartmentId { get; }
    public ProviderEpoch CurrentEpoch { get; }
}

public sealed record ProviderOwnershipRecord
{
    public ProviderOwnershipRecord(ProviderResourceId resourceId, ProviderCellId cellId, ProviderCompartmentId compartmentId, ProviderGeneration generation)
    { ResourceId = resourceId ?? throw new ArgumentNullException(nameof(resourceId)); CellId = cellId ?? throw new ArgumentNullException(nameof(cellId)); CompartmentId = compartmentId ?? throw new ArgumentNullException(nameof(compartmentId)); Generation = generation ?? throw new ArgumentNullException(nameof(generation)); }
    public ProviderResourceId ResourceId { get; }
    public ProviderCellId CellId { get; }
    public ProviderCompartmentId CompartmentId { get; }
    public ProviderGeneration Generation { get; }
}

public sealed record ProviderInventoryTagEvidence
{
    public ProviderInventoryTagEvidence(
        ProviderResourceId resourceId, ProviderCellId cellId, ProviderCompartmentId compartmentId,
        ProviderOperationId operationId, ProviderGeneration generation)
    {
        ResourceId = resourceId ?? throw new ArgumentNullException(nameof(resourceId));
        CellId = cellId ?? throw new ArgumentNullException(nameof(cellId));
        CompartmentId = compartmentId ?? throw new ArgumentNullException(nameof(compartmentId));
        OperationId = operationId ?? throw new ArgumentNullException(nameof(operationId));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
    }
    public ProviderResourceId ResourceId { get; }
    public ProviderCellId CellId { get; }
    public ProviderCompartmentId CompartmentId { get; }
    public ProviderOperationId OperationId { get; }
    public ProviderGeneration Generation { get; }
}

public enum ProviderObservationCompleteness { Complete = 1, Incomplete = 2 }
public enum ProviderObservedState { Absent = 1, Present = 2, Running = 3, Stopped = 4, Terminated = 5 }
public sealed record ProviderResourceObservation
{
    public ProviderResourceObservation(ProviderResourceId resourceId, ProviderGeneration generation, ProviderObservedState state)
    {
        ResourceId = resourceId ?? throw new ArgumentNullException(nameof(resourceId));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        if (!Enum.IsDefined(state)) throw new ArgumentOutOfRangeException(nameof(state));
        State = state;
    }
    public ProviderResourceId ResourceId { get; }
    public ProviderGeneration Generation { get; }
    public ProviderObservedState State { get; }
}

public sealed record ProviderCreateObservation
{
    public ProviderCreateObservation(
        ProviderCreateKey createKey, ProviderGeneration generation, ProviderObservedState state,
        ProviderResourceId? resolvedResourceId)
    {
        CreateKey = createKey ?? throw new ArgumentNullException(nameof(createKey));
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
        if (!Enum.IsDefined(state)) throw new ArgumentOutOfRangeException(nameof(state));
        if ((state == ProviderObservedState.Absent) != (resolvedResourceId is null))
            throw new ArgumentException("Only an absent create observation may omit the resolved resource ID.", nameof(resolvedResourceId));
        State = state;
        ResolvedResourceId = resolvedResourceId;
    }
    public ProviderCreateKey CreateKey { get; }
    public ProviderGeneration Generation { get; }
    public ProviderObservedState State { get; }
    public ProviderResourceId? ResolvedResourceId { get; }
}

public enum ProviderCallStatus { NotCalled = 1, Accepted = 2, ResponseLost = 3, Completed = 4 }
public sealed record ProviderCallEvidence
{
    public ProviderCallEvidence(
        ProviderOperationContext context, ProviderCallStatus status, ProviderWorkRequestId? workRequestId)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        if (status == ProviderCallStatus.NotCalled && workRequestId is not null)
            throw new ArgumentException("A call that was not made cannot have a work request ID.", nameof(workRequestId));
        Context = context;
        Status = status;
        WorkRequestId = workRequestId;
    }
    public ProviderOperationContext Context { get; }
    public ProviderCallStatus Status { get; }
    public ProviderWorkRequestId? WorkRequestId { get; }
}

public sealed record DurableProviderAuthorization
{
    private DurableProviderAuthorization(string fingerprint, ProviderOperationId operationId, ProviderTerminalState terminal, bool irreversible)
    { Fingerprint = fingerprint; OperationId = operationId; Terminal = terminal; Irreversible = irreversible; }
    internal string Fingerprint { get; }
    public ProviderOperationId OperationId { get; }
    public ProviderTerminalState Terminal { get; }
    public bool Irreversible { get; }
    internal static DurableProviderAuthorization Capture(ProviderOperationContext context, bool irreversible)
    { ArgumentNullException.ThrowIfNull(context); return new(context.Fingerprint, context.OperationId, context.DesiredTerminalState, irreversible); }
}

public sealed class ProviderAuthorizationRequest
{
    public ProviderAuthorizationRequest(
        ProviderOperationContext context, RegionalProviderAuthority? authority,
        IEnumerable<ProviderOwnershipRecord> ownershipRecords, IEnumerable<ProviderInventoryTagEvidence> tags,
        ProviderObservationCompleteness observationCompleteness, IEnumerable<ProviderResourceObservation> observations,
        IEnumerable<ProviderCreateObservation> createObservations,
        IEnumerable<ProviderApproval> requiredApprovals, DurableProviderAuthorization? priorAuthorization,
        ProviderCallEvidence callEvidence)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context)); Authority = authority;
        OwnershipRecords = Copy(ownershipRecords, nameof(ownershipRecords)); Tags = Copy(tags, nameof(tags));
        if (!Enum.IsDefined(observationCompleteness)) throw new ArgumentOutOfRangeException(nameof(observationCompleteness));
        ObservationCompleteness = observationCompleteness; Observations = Copy(observations, nameof(observations));
        CreateObservations = Copy(createObservations, nameof(createObservations));
        RequiredApprovals = CopyEnums(requiredApprovals, nameof(requiredApprovals)); PriorAuthorization = priorAuthorization;
        CallEvidence = callEvidence ?? throw new ArgumentNullException(nameof(callEvidence));
    }
    public ProviderOperationContext Context { get; }
    public RegionalProviderAuthority? Authority { get; }
    public IReadOnlyList<ProviderOwnershipRecord> OwnershipRecords { get; }
    public IReadOnlyList<ProviderInventoryTagEvidence> Tags { get; }
    public ProviderObservationCompleteness ObservationCompleteness { get; }
    public IReadOnlyList<ProviderResourceObservation> Observations { get; }
    public IReadOnlyList<ProviderCreateObservation> CreateObservations { get; }
    public IReadOnlyList<ProviderApproval> RequiredApprovals { get; }
    public DurableProviderAuthorization? PriorAuthorization { get; }
    public ProviderCallEvidence CallEvidence { get; }
    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string name) where T : notnull
    { var copy = ProviderInputSnapshot.Copy(source, ProviderTechnicalInputLimits.MaximumOperationEvidenceCount, name, "Provider evidence input"); if (copy.Any(x => x is null)) throw new ArgumentException("Null evidence.", name); return new ReadOnlyCollection<T>(copy); }
    private static IReadOnlyList<T> CopyEnums<T>(IEnumerable<T> source, string name) where T : struct, Enum
    { var copy = ProviderInputSnapshot.Copy(source, ProviderTechnicalInputLimits.MaximumApprovalCount, name, "Provider approval input"); if (copy.Any(x => !Enum.IsDefined(x))) throw new ArgumentOutOfRangeException(name); if (copy.Length != copy.Distinct().Count()) throw new ArgumentException("Duplicate approvals.", name); return new ReadOnlyCollection<T>(copy.Order().ToArray()); }
}

public enum ProviderDecisionCode
{
    EvidenceComplete = 1, EvidenceUnique = 2, EvidenceConsistent = 3, AuthorityPresent = 4,
    ScopeMatches = 5, EpochCurrentOrDurablyResumable = 6, OwnershipMatches = 7,
    GenerationMatches = 8, DeadlineValid = 9, ApprovalsComplete = 10,
    PriorAuthorizationCompatible = 11, ActionResourceCompatible = 12, TagsConsistent = 13,
    TagsNotAuthority = 14, HandoffInventoryUnique = 15, HandoffInventoryExact = 16,
    HandoffScopeMatches = 17, HandoffRetainUnmanage = 18, HandoffJournalReceipt = 19,
    HandoffProviderReady = 20, HandoffTrustReady = 21, HandoffBackupReady = 22,
    HandoffFenceActivated = 23, CallEvidenceMatches = 24,
    HandoffGenerationNotRollback = 25,
}
public enum ProviderDecisionOutcome { Passed = 1, Rejected = 2, Held = 3, NotApplicable = 4 }
public sealed record ProviderDecisionReason
{
    internal ProviderDecisionReason(ProviderDecisionCode code, ProviderDecisionOutcome outcome, ulong observed, ulong required)
    { Code = code; Outcome = outcome; Observed = observed; Required = required; }
    public ProviderDecisionCode Code { get; }
    public ProviderDecisionOutcome Outcome { get; }
    public ulong Observed { get; }
    public ulong Required { get; }
}

public abstract record ProviderIntent { internal ProviderIntent(ProviderOperationContext context) => Context = context; public ProviderOperationContext Context { get; } }
public sealed record ObserveProviderResourceIntent : ProviderIntent { internal ObserveProviderResourceIntent(ProviderOperationContext c) : base(c) { } }
public sealed record ObserveResolvedProviderCreateIntent : ProviderIntent
{
    internal ObserveResolvedProviderCreateIntent(ProviderOperationContext context, ProviderCreateObservation observation) : base(context)
    {
        CreateKey = observation.CreateKey;
        ResolvedResourceId = observation.ResolvedResourceId ?? throw new ArgumentException("Resolved create observation requires a resource ID.", nameof(observation));
    }
    public ProviderCreateKey CreateKey { get; }
    public ProviderResourceId ResolvedResourceId { get; }
}
public sealed record ReadProviderWorkRequestIntent : ProviderIntent { internal ReadProviderWorkRequestIntent(ProviderOperationContext c, ProviderWorkRequestId id) : base(c) => WorkRequestId = id; public ProviderWorkRequestId WorkRequestId { get; } }
public abstract record ProviderMutationIntent : ProviderIntent { internal ProviderMutationIntent(ProviderOperationContext c) : base(c) { } }
public sealed record CreateNodeProviderIntent : ProviderMutationIntent { internal CreateNodeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (CreateNodeProviderParameters)c.ActionParameters; public CreateNodeProviderParameters Parameters { get; } }
public sealed record StartNodeProviderIntent : ProviderMutationIntent { internal StartNodeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (StartNodeProviderParameters)c.ActionParameters; public StartNodeProviderParameters Parameters { get; } }
public sealed record StopNodeProviderIntent : ProviderMutationIntent { internal StopNodeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (StopNodeProviderParameters)c.ActionParameters; public StopNodeProviderParameters Parameters { get; } }
public sealed record TerminateNodeProviderIntent : ProviderMutationIntent { internal TerminateNodeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (TerminateNodeProviderParameters)c.ActionParameters; public TerminateNodeProviderParameters Parameters { get; } }
public sealed record CreateVolumeProviderIntent : ProviderMutationIntent { internal CreateVolumeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (CreateVolumeProviderParameters)c.ActionParameters; public CreateVolumeProviderParameters Parameters { get; } }
public sealed record ExpandVolumeProviderIntent : ProviderMutationIntent { internal ExpandVolumeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (ExpandVolumeProviderParameters)c.ActionParameters; public ExpandVolumeProviderParameters Parameters { get; } }
public sealed record ChangeVolumePerformanceProviderIntent : ProviderMutationIntent { internal ChangeVolumePerformanceProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (ChangeVolumePerformanceProviderParameters)c.ActionParameters; public ChangeVolumePerformanceProviderParameters Parameters { get; } }
public sealed record AttachVolumeProviderIntent : ProviderMutationIntent { internal AttachVolumeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (AttachVolumeProviderParameters)c.ActionParameters; public AttachVolumeProviderParameters Parameters { get; } }
public sealed record DetachVolumeProviderIntent : ProviderMutationIntent { internal DetachVolumeProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (DetachVolumeProviderParameters)c.ActionParameters; public DetachVolumeProviderParameters Parameters { get; } }
public sealed record RegisterBackendProviderIntent : ProviderMutationIntent { internal RegisterBackendProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (RegisterBackendProviderParameters)c.ActionParameters; public RegisterBackendProviderParameters Parameters { get; } }
public sealed record DeregisterBackendProviderIntent : ProviderMutationIntent { internal DeregisterBackendProviderIntent(ProviderOperationContext c) : base(c) => Parameters = (DeregisterBackendProviderParameters)c.ActionParameters; public DeregisterBackendProviderParameters Parameters { get; } }

public sealed record ProviderAuthorizationDecision
{
    private readonly ProviderOperationContext? _durablyAcceptedContext;
    internal ProviderAuthorizationDecision(bool authorized, IReadOnlyList<ProviderDecisionReason> trace,
        IReadOnlyList<ProviderIntent> intents, ProviderOperationContext? durablyAcceptedContext)
    {
        Authorized = authorized;
        Trace = trace ?? throw new ArgumentNullException(nameof(trace));
        Intents = intents ?? throw new ArgumentNullException(nameof(intents));
        _durablyAcceptedContext = durablyAcceptedContext;
    }
    public bool Authorized { get; }
    public IReadOnlyList<ProviderDecisionReason> Trace { get; }
    public IReadOnlyList<ProviderIntent> Intents { get; }
    public DurableProviderAuthorization CaptureDurableAuthorization()
    {
        if (!Authorized || _durablyAcceptedContext is null)
            throw new InvalidOperationException("Only an exact provider-accepted operation may be captured durably.");
        return DurableProviderAuthorization.Capture(_durablyAcceptedContext, irreversible: true);
    }
}

public sealed record HandoffInventoryItem
{
    public HandoffInventoryItem(ProviderResourceId resourceId, ProviderResourceKind kind, ProviderGeneration generation)
    {
        ResourceId = resourceId ?? throw new ArgumentNullException(nameof(resourceId));
        if (!Enum.IsDefined(kind)) throw new ArgumentOutOfRangeException(nameof(kind));
        Kind = kind;
        Generation = generation ?? throw new ArgumentNullException(nameof(generation));
    }
    public ProviderResourceId ResourceId { get; }
    public ProviderResourceKind Kind { get; }
    public ProviderGeneration Generation { get; }
}
public enum HandoffEvidenceStatus { Verified = 1, Missing = 2, Conflicting = 3 }
public sealed class FreshBootstrapInventory
{
    public FreshBootstrapInventory(IEnumerable<HandoffInventoryItem> expected, IEnumerable<HandoffInventoryItem> pulumi, IEnumerable<HandoffInventoryItem> regional)
    { Expected = Copy(expected); Pulumi = Copy(pulumi); Regional = Copy(regional); }
    public IReadOnlyList<HandoffInventoryItem> Expected { get; }
    public IReadOnlyList<HandoffInventoryItem> Pulumi { get; }
    public IReadOnlyList<HandoffInventoryItem> Regional { get; }
    private static IReadOnlyList<HandoffInventoryItem> Copy(IEnumerable<HandoffInventoryItem> source)
    { var copy = ProviderInputSnapshot.Copy(source, ProviderTechnicalInputLimits.MaximumHandoffInventoryCount, nameof(source), "Handoff inventory input"); if (copy.Any(x => x is null)) throw new ArgumentException("Null inventory item."); return new ReadOnlyCollection<HandoffInventoryItem>(copy); }
}

public sealed record HandoffInventoryFingerprint
{
    private HandoffInventoryFingerprint(string value) => Value = value;
    internal string Value { get; }
    internal static HandoffInventoryFingerprint Compute(IEnumerable<HandoffInventoryItem> items)
    {
        var projection = string.Join(';', items.OrderBy(item => item.ResourceId.Value, StringComparer.Ordinal)
            .ThenBy(item => item.Kind).ThenBy(item => item.Generation.Value)
            .Select(item => string.Join('|', item.ResourceId.Value, item.Kind,
                item.Generation.Value.ToString(CultureInfo.InvariantCulture))));
        return new(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(projection))).ToLowerInvariant());
    }
}

public sealed record HandoffScope
{
    private HandoffScope(
        ProviderCellId cellId, ProviderCompartmentId compartmentId, ProviderGeneration bootstrapGeneration,
        ProviderOperationId operationId, HandoffInventoryFingerprint inventoryFingerprint)
    {
        CellId = cellId;
        CompartmentId = compartmentId;
        BootstrapGeneration = bootstrapGeneration;
        OperationId = operationId;
        InventoryFingerprint = inventoryFingerprint;
    }
    public ProviderCellId CellId { get; }
    public ProviderCompartmentId CompartmentId { get; }
    public ProviderGeneration BootstrapGeneration { get; }
    public ProviderOperationId OperationId { get; }
    public HandoffInventoryFingerprint InventoryFingerprint { get; }
    public static HandoffScope ForFreshBootstrap(
        ProviderCellId cellId, ProviderCompartmentId compartmentId, ProviderGeneration bootstrapGeneration,
        ProviderOperationId operationId, FreshBootstrapInventory inventory)
    {
        ArgumentNullException.ThrowIfNull(inventory);
        return new(
            cellId ?? throw new ArgumentNullException(nameof(cellId)),
            compartmentId ?? throw new ArgumentNullException(nameof(compartmentId)),
            bootstrapGeneration ?? throw new ArgumentNullException(nameof(bootstrapGeneration)),
            operationId ?? throw new ArgumentNullException(nameof(operationId)),
            HandoffInventoryFingerprint.Compute(inventory.Expected));
    }
}

public abstract record HandoffProof
{
    internal HandoffProof(HandoffScope scope, HandoffEvidenceStatus status)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        Status = status;
    }
    public HandoffScope Scope { get; }
    public HandoffEvidenceStatus Status { get; }
}
public sealed record RetainUnmanageHandoffProof : HandoffProof { public RetainUnmanageHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }
public sealed record RegionalJournalHandoffProof : HandoffProof { public RegionalJournalHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }
public sealed record ProviderReadyHandoffProof : HandoffProof { public ProviderReadyHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }
public sealed record TrustReadyHandoffProof : HandoffProof { public TrustReadyHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }
public sealed record BackupReadyHandoffProof : HandoffProof { public BackupReadyHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }
public sealed record RegionalFenceHandoffProof : HandoffProof { public RegionalFenceHandoffProof(HandoffScope scope, HandoffEvidenceStatus status) : base(scope, status) { } }

public sealed record HandoffEvidence
{
    public HandoffEvidence(
        RetainUnmanageHandoffProof retainUnmanage, RegionalJournalHandoffProof regionalJournalReceipt,
        ProviderReadyHandoffProof providerReady, TrustReadyHandoffProof trustReady,
        BackupReadyHandoffProof backupReady, RegionalFenceHandoffProof regionalFenceActivated)
    {
        RetainUnmanage = retainUnmanage ?? throw new ArgumentNullException(nameof(retainUnmanage));
        RegionalJournalReceipt = regionalJournalReceipt ?? throw new ArgumentNullException(nameof(regionalJournalReceipt));
        ProviderReady = providerReady ?? throw new ArgumentNullException(nameof(providerReady));
        TrustReady = trustReady ?? throw new ArgumentNullException(nameof(trustReady));
        BackupReady = backupReady ?? throw new ArgumentNullException(nameof(backupReady));
        RegionalFenceActivated = regionalFenceActivated ?? throw new ArgumentNullException(nameof(regionalFenceActivated));
    }
    public RetainUnmanageHandoffProof RetainUnmanage { get; }
    public RegionalJournalHandoffProof RegionalJournalReceipt { get; }
    public ProviderReadyHandoffProof ProviderReady { get; }
    public TrustReadyHandoffProof TrustReady { get; }
    public BackupReadyHandoffProof BackupReady { get; }
    public RegionalFenceHandoffProof RegionalFenceActivated { get; }
}
public sealed record HandoffRequest
{
    public HandoffRequest(
        FreshBootstrapInventory inventory, HandoffScope expectedScope,
        ProviderGeneration currentAcceptedBootstrapGeneration, HandoffEvidence evidence)
    {
        Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        ExpectedScope = expectedScope ?? throw new ArgumentNullException(nameof(expectedScope));
        CurrentAcceptedBootstrapGeneration = currentAcceptedBootstrapGeneration ??
            throw new ArgumentNullException(nameof(currentAcceptedBootstrapGeneration));
        Evidence = evidence ?? throw new ArgumentNullException(nameof(evidence));
    }
    public FreshBootstrapInventory Inventory { get; }
    public HandoffScope ExpectedScope { get; }
    public ProviderGeneration CurrentAcceptedBootstrapGeneration { get; }
    public HandoffEvidence Evidence { get; }
}
public sealed record EnableRegionalSelfManagementIntent
{
    internal EnableRegionalSelfManagementIntent(
        FreshBootstrapInventory inventory, HandoffScope scope,
        ProviderGeneration currentAcceptedBootstrapGeneration)
    {
        Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
        CurrentAcceptedBootstrapGeneration = currentAcceptedBootstrapGeneration ??
            throw new ArgumentNullException(nameof(currentAcceptedBootstrapGeneration));
    }
    public FreshBootstrapInventory Inventory { get; }
    public HandoffScope Scope { get; }
    public ProviderGeneration CurrentAcceptedBootstrapGeneration { get; }
}
public sealed record HandoffDecision
{
    internal HandoffDecision(bool ready, IReadOnlyList<ProviderDecisionReason> trace, EnableRegionalSelfManagementIntent? intent)
    {
        Ready = ready;
        Trace = trace ?? throw new ArgumentNullException(nameof(trace));
        Intent = intent;
    }
    public bool Ready { get; }
    public IReadOnlyList<ProviderDecisionReason> Trace { get; }
    public EnableRegionalSelfManagementIntent? Intent { get; }
}
