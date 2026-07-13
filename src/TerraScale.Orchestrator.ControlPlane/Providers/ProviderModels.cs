using System.Collections.ObjectModel;
using System.Globalization;
using System.Text.RegularExpressions;

namespace TerraScale.Orchestrator.ControlPlane.Providers;

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

public sealed class ProviderOperationContext
{
    public ProviderOperationContext(
        ProviderOperationId operationId, ProviderCellId cellId, ProviderCompartmentId compartmentId,
        ProviderEpoch controllerEpoch, ProviderResourceKind resourceKind, ProviderAction action,
        ProviderTarget target, ProviderGeneration expectedGeneration, ProviderObservedState expectedObservedState,
        ProviderTerminalState desiredTerminalState,
        IEnumerable<ProviderApproval> approvals, DeadlineEvidence deadlineEvidence,
        ProviderIdempotencyKey idempotencyKey, IEnumerable<ProviderCompensation> permittedCompensations,
        ProviderTemplateId? templateId)
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
        Approvals = CopyEnums(approvals, nameof(approvals));
        DeadlineEvidence = deadlineEvidence ?? throw new ArgumentNullException(nameof(deadlineEvidence));
        IdempotencyKey = idempotencyKey ?? throw new ArgumentNullException(nameof(idempotencyKey));
        PermittedCompensations = CopyEnums(permittedCompensations, nameof(permittedCompensations));
        TemplateId = templateId;
        var isCreate = action is ProviderAction.CreateNode or ProviderAction.CreateVolume;
        if (action == ProviderAction.CreateNode && (target is not IdempotentProviderCreate || templateId is null))
            throw new ArgumentException("Create node requires a create key and template ID.");
        if (action == ProviderAction.CreateVolume && target is not IdempotentProviderCreate)
            throw new ArgumentException("Create volume requires a create key.");
        if (action != ProviderAction.CreateNode && templateId is not null)
            throw new ArgumentException("Template ID is only valid for create node.");
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
    public ProviderTemplateId? TemplateId { get; }

    internal string Fingerprint => string.Join('|', OperationId.Value, CellId.Value, CompartmentId.Value,
        Invariant(ControllerEpoch.Value), ResourceKind, Action, Target.Projection, Invariant(ExpectedGeneration.Value), ExpectedObservedState,
        DesiredTerminalState, string.Join(',', Approvals), DeadlineEvidence.Status,
        Invariant(DeadlineEvidence.EvidenceGeneration.Value), IdempotencyKey.Value,
        string.Join(',', PermittedCompensations), TemplateId?.Value ?? "-");

    private static string Invariant(ulong value) => value.ToString(CultureInfo.InvariantCulture);

    private static IReadOnlyList<T> CopyEnums<T>(IEnumerable<T> source, string name) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(source, name);
        var values = source.ToArray();
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

public enum ProviderCallStatus { NotCalled = 1, Accepted = 2, ResponseLost = 3, Completed = 4 }
public sealed record ProviderCallEvidence
{
    public ProviderCallEvidence(ProviderCallStatus status, ProviderWorkRequestId? workRequestId)
    {
        if (!Enum.IsDefined(status)) throw new ArgumentOutOfRangeException(nameof(status));
        if (status == ProviderCallStatus.NotCalled && workRequestId is not null)
            throw new ArgumentException("A call that was not made cannot have a work request ID.", nameof(workRequestId));
        Status = status;
        WorkRequestId = workRequestId;
    }
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
    public static DurableProviderAuthorization Capture(ProviderOperationContext context, bool irreversible)
    { ArgumentNullException.ThrowIfNull(context); return new(context.Fingerprint, context.OperationId, context.DesiredTerminalState, irreversible); }
}

public sealed class ProviderAuthorizationRequest
{
    public ProviderAuthorizationRequest(
        ProviderOperationContext context, RegionalProviderAuthority? authority,
        IEnumerable<ProviderOwnershipRecord> ownershipRecords, IEnumerable<ProviderInventoryTagEvidence> tags,
        ProviderObservationCompleteness observationCompleteness, IEnumerable<ProviderResourceObservation> observations,
        IEnumerable<ProviderApproval> requiredApprovals, DurableProviderAuthorization? priorAuthorization,
        ProviderCallEvidence callEvidence)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context)); Authority = authority;
        OwnershipRecords = Copy(ownershipRecords, nameof(ownershipRecords)); Tags = Copy(tags, nameof(tags));
        if (!Enum.IsDefined(observationCompleteness)) throw new ArgumentOutOfRangeException(nameof(observationCompleteness));
        ObservationCompleteness = observationCompleteness; Observations = Copy(observations, nameof(observations));
        RequiredApprovals = CopyEnums(requiredApprovals, nameof(requiredApprovals)); PriorAuthorization = priorAuthorization;
        CallEvidence = callEvidence ?? throw new ArgumentNullException(nameof(callEvidence));
    }
    public ProviderOperationContext Context { get; }
    public RegionalProviderAuthority? Authority { get; }
    public IReadOnlyList<ProviderOwnershipRecord> OwnershipRecords { get; }
    public IReadOnlyList<ProviderInventoryTagEvidence> Tags { get; }
    public ProviderObservationCompleteness ObservationCompleteness { get; }
    public IReadOnlyList<ProviderResourceObservation> Observations { get; }
    public IReadOnlyList<ProviderApproval> RequiredApprovals { get; }
    public DurableProviderAuthorization? PriorAuthorization { get; }
    public ProviderCallEvidence CallEvidence { get; }
    private static IReadOnlyList<T> Copy<T>(IEnumerable<T> source, string name) where T : notnull
    { ArgumentNullException.ThrowIfNull(source, name); var copy = source.ToArray(); if (copy.Any(x => x is null)) throw new ArgumentException("Null evidence.", name); return new ReadOnlyCollection<T>(copy); }
    private static IReadOnlyList<T> CopyEnums<T>(IEnumerable<T> source, string name) where T : struct, Enum
    { ArgumentNullException.ThrowIfNull(source, name); var copy = source.ToArray(); if (copy.Any(x => !Enum.IsDefined(x))) throw new ArgumentOutOfRangeException(name); if (copy.Length != copy.Distinct().Count()) throw new ArgumentException("Duplicate approvals.", name); return new ReadOnlyCollection<T>(copy.Order().ToArray()); }
}

public enum ProviderDecisionCode
{
    EvidenceComplete = 1, EvidenceUnique = 2, EvidenceConsistent = 3, AuthorityPresent = 4,
    ScopeMatches = 5, EpochCurrentOrDurablyResumable = 6, OwnershipMatches = 7,
    GenerationMatches = 8, DeadlineValid = 9, ApprovalsComplete = 10,
    PriorAuthorizationCompatible = 11, ActionResourceCompatible = 12, TagsConsistent = 13,
    TagsNotAuthority = 14, HandoffInventoryUnique = 15, HandoffInventoryExact = 16,
    HandoffRetainUnmanage = 17, HandoffJournalReceipt = 18, HandoffProviderReady = 19,
    HandoffTrustReady = 20, HandoffBackupReady = 21, HandoffFenceActivated = 22,
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
public sealed record ReadProviderWorkRequestIntent : ProviderIntent { internal ReadProviderWorkRequestIntent(ProviderOperationContext c, ProviderWorkRequestId id) : base(c) => WorkRequestId = id; public ProviderWorkRequestId WorkRequestId { get; } }
public abstract record ProviderMutationIntent : ProviderIntent { internal ProviderMutationIntent(ProviderOperationContext c) : base(c) { } }
public sealed record CreateNodeProviderIntent : ProviderMutationIntent { internal CreateNodeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record StartNodeProviderIntent : ProviderMutationIntent { internal StartNodeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record StopNodeProviderIntent : ProviderMutationIntent { internal StopNodeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record TerminateNodeProviderIntent : ProviderMutationIntent { internal TerminateNodeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record CreateVolumeProviderIntent : ProviderMutationIntent { internal CreateVolumeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record ExpandVolumeProviderIntent : ProviderMutationIntent { internal ExpandVolumeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record ChangeVolumePerformanceProviderIntent : ProviderMutationIntent { internal ChangeVolumePerformanceProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record AttachVolumeProviderIntent : ProviderMutationIntent { internal AttachVolumeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record DetachVolumeProviderIntent : ProviderMutationIntent { internal DetachVolumeProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record RegisterBackendProviderIntent : ProviderMutationIntent { internal RegisterBackendProviderIntent(ProviderOperationContext c) : base(c) { } }
public sealed record DeregisterBackendProviderIntent : ProviderMutationIntent { internal DeregisterBackendProviderIntent(ProviderOperationContext c) : base(c) { } }

public sealed record ProviderAuthorizationDecision
{
    internal ProviderAuthorizationDecision(bool authorized, IReadOnlyList<ProviderDecisionReason> trace, IReadOnlyList<ProviderIntent> intents)
    {
        Authorized = authorized;
        Trace = trace ?? throw new ArgumentNullException(nameof(trace));
        Intents = intents ?? throw new ArgumentNullException(nameof(intents));
    }
    public bool Authorized { get; }
    public IReadOnlyList<ProviderDecisionReason> Trace { get; }
    public IReadOnlyList<ProviderIntent> Intents { get; }
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
    { ArgumentNullException.ThrowIfNull(source); var copy = source.ToArray(); if (copy.Any(x => x is null)) throw new ArgumentException("Null inventory item."); return new ReadOnlyCollection<HandoffInventoryItem>(copy); }
}
public sealed record HandoffEvidence
{
    public HandoffEvidence(
        HandoffEvidenceStatus retainUnmanage, HandoffEvidenceStatus regionalJournalReceipt,
        HandoffEvidenceStatus providerReady, HandoffEvidenceStatus trustReady,
        HandoffEvidenceStatus backupReady, HandoffEvidenceStatus regionalFenceActivated)
    {
        var statuses = new[] { retainUnmanage, regionalJournalReceipt, providerReady, trustReady, backupReady, regionalFenceActivated };
        if (statuses.Any(status => !Enum.IsDefined(status))) throw new ArgumentOutOfRangeException(nameof(retainUnmanage));
        RetainUnmanage = retainUnmanage;
        RegionalJournalReceipt = regionalJournalReceipt;
        ProviderReady = providerReady;
        TrustReady = trustReady;
        BackupReady = backupReady;
        RegionalFenceActivated = regionalFenceActivated;
    }
    public HandoffEvidenceStatus RetainUnmanage { get; }
    public HandoffEvidenceStatus RegionalJournalReceipt { get; }
    public HandoffEvidenceStatus ProviderReady { get; }
    public HandoffEvidenceStatus TrustReady { get; }
    public HandoffEvidenceStatus BackupReady { get; }
    public HandoffEvidenceStatus RegionalFenceActivated { get; }
}
public sealed record EnableRegionalSelfManagementIntent
{
    internal EnableRegionalSelfManagementIntent(FreshBootstrapInventory inventory) =>
        Inventory = inventory ?? throw new ArgumentNullException(nameof(inventory));
    public FreshBootstrapInventory Inventory { get; }
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
