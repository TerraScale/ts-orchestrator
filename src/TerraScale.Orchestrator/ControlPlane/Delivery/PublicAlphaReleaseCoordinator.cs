using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

public enum PublicAlphaRegion { Unknown, Gru, Sfo, Fra }
public enum PublicAlphaEndpoint { Unknown, Global, StrictRegional }
public enum PublicAlphaRegionHealth { Unknown, Healthy, Unhealthy }
public enum PublicAlphaRoutingError { None, InvalidRequest, RegionNotSelected, RegionNotHealthy, NoHealthySelectedRegion }
public enum PublicAlphaGatePhase { Unknown, PreActivation, PostActivation }
public enum PublicAlphaGateStatus { Unknown, Passed, Failed }
public enum PublicAlphaClientKind { Unknown, RawApi, DotNetSdk, TypeScriptSdk, Mcp }

internal static class PublicAlphaDigest
{
    public static bool IsValid(string? value) =>
        value is { Length: 71 } && value.StartsWith("sha256:", StringComparison.Ordinal) &&
        value[7..].All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public enum PublicAlphaGateKind
{
    Unknown,
    ServiceHealth,
    ErrorRate,
    ApiLatency,
    TenantIsolation,
    ReplicationHealth,
    BillingReconciliation,
    CustomerJourney,
}

public enum PublicAlphaReleaseErrorCode
{
    Unknown,
    InvalidInput,
    RegionSetMismatch,
    PreparationFailed,
    RequiredEvidenceMissing,
    RequiredEvidenceFailed,
    RequiredEvidenceStale,
    EvidenceDigestMismatch,
    RegionQualificationDenied,
    ApprovalDenied,
    ReadinessDenied,
}

public static class PublicAlphaRegionCatalog
{
    private static readonly IReadOnlyList<PublicAlphaRegion> Regions =
        new ReadOnlyCollection<PublicAlphaRegion>(
        [PublicAlphaRegion.Gru, PublicAlphaRegion.Sfo, PublicAlphaRegion.Fra]);

    public const string GlobalHostName = "api.terrascale.tech";
    public static IReadOnlyList<PublicAlphaRegion> LaunchRegions => Regions;

    public static string Code(PublicAlphaRegion region) => region switch
    {
        PublicAlphaRegion.Gru => "gru",
        PublicAlphaRegion.Sfo => "sfo",
        PublicAlphaRegion.Fra => "fra",
        _ => throw new ArgumentOutOfRangeException(nameof(region)),
    };

    public static string RegionalHostName(PublicAlphaRegion region) => $"{Code(region)}.{GlobalHostName}";
}

public sealed record PublicAlphaRegionHealthEvidence(PublicAlphaRegion Region, PublicAlphaRegionHealth Health);

public sealed record PublicAlphaRoutingRequest(
    PublicAlphaEndpoint Endpoint,
    PublicAlphaRegion? RequestedRegion,
    IReadOnlyList<PublicAlphaRegion> SelectedRegions,
    IReadOnlyList<PublicAlphaRegion> NearestRegions,
    IReadOnlyList<PublicAlphaRegionHealthEvidence> Health);

public sealed class PublicAlphaRoutingDecision
{
    internal PublicAlphaRoutingDecision(PublicAlphaRegion? region, PublicAlphaRoutingError error)
    {
        Region = region;
        Error = error;
    }

    public PublicAlphaRegion? Region { get; }
    public PublicAlphaRoutingError Error { get; }
}

public static class PublicAlphaRoutingPolicy
{
    public static PublicAlphaRoutingDecision Decide(PublicAlphaRoutingRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryUnique(request.SelectedRegions, out var selected) || selected.Count == 0 ||
            !TryUnique(request.NearestRegions, out var nearest) ||
            request.Health is null || request.Health.Count > PublicAlphaRegionCatalog.LaunchRegions.Count ||
            request.Health.Any(item => item is null ||
                !PublicAlphaRegionCatalog.LaunchRegions.Contains(item.Region) || !Enum.IsDefined(item.Health)) ||
            request.Health.Select(static item => item.Region).Distinct().Count() != request.Health.Count)
        {
            return new(null, PublicAlphaRoutingError.InvalidRequest);
        }

        var health = request.Health.ToDictionary(static item => item.Region, static item => item.Health);
        if (request.Endpoint == PublicAlphaEndpoint.StrictRegional)
        {
            if (request.RequestedRegion is not { } requested)
                return new(null, PublicAlphaRoutingError.InvalidRequest);
            if (!selected.Contains(requested))
                return new(null, PublicAlphaRoutingError.RegionNotSelected);
            return health.GetValueOrDefault(requested) == PublicAlphaRegionHealth.Healthy
                ? new(requested, PublicAlphaRoutingError.None)
                : new(null, PublicAlphaRoutingError.RegionNotHealthy);
        }

        if (request.Endpoint != PublicAlphaEndpoint.Global || request.RequestedRegion is not null)
            return new(null, PublicAlphaRoutingError.InvalidRequest);

        foreach (var region in nearest)
            if (selected.Contains(region) && health.GetValueOrDefault(region) == PublicAlphaRegionHealth.Healthy)
                return new(region, PublicAlphaRoutingError.None);

        return new(null, PublicAlphaRoutingError.NoHealthySelectedRegion);
    }

    private static bool TryUnique(IReadOnlyList<PublicAlphaRegion>? input, out HashSet<PublicAlphaRegion> values)
    {
        values = [];
        if (input is null || input.Any(region => !PublicAlphaRegionCatalog.LaunchRegions.Contains(region)))
            return false;
        return input.All(values.Add);
    }
}

public sealed record PublicAlphaReleaseIdentity(
    string ReleaseId,
    string SourceRevision,
    string CandidateDigest,
    string PreviousQualifiedDigest,
    string ConfigurationRevision,
    string MigrationSetDigest,
    string PreviousQualifiedConfigurationRevision,
    string PreviousQualifiedMigrationSetDigest,
    DateTimeOffset CreatedAt);

public sealed record PublicAlphaRegionReleaseState(
    PublicAlphaRegion Region,
    string? PreparedDigest,
    string ServingDigest,
    bool PreparationFailed);

public sealed record PublicAlphaMetricThreshold(
    string Metric,
    string Unit,
    TimeSpan Window,
    string Source,
    string QualifiedBaseline);

public sealed record PublicAlphaGateEvidence(
    PublicAlphaGateKind Kind,
    PublicAlphaGatePhase Phase,
    PublicAlphaRegion Region,
    string CandidateDigest,
    DateTimeOffset ObservedAt,
    PublicAlphaGateStatus Status,
    string EvidenceDigest,
    PublicAlphaMetricThreshold? Threshold);

public sealed record PublicAlphaClientEvidence(
    PublicAlphaClientKind Kind,
    string Version,
    string ArtifactDigest,
    string CandidateDigest,
    string JourneySpecificationDigest,
    bool Passed);

public sealed class PublicAlphaCrossClientHandoff
{
    internal PublicAlphaCrossClientHandoff(
        string releaseId,
        string sourceRevision,
        string configurationRevision,
        string migrationSetDigest,
        string previousQualifiedDigest,
        string previousQualifiedConfigurationRevision,
        string previousQualifiedMigrationSetDigest,
        string candidateDigest,
        string handoffDigest,
        bool digestVerified,
        DateTimeOffset observedAt,
        IReadOnlyList<PublicAlphaClientEvidence> clients)
    {
        ReleaseId = releaseId;
        SourceRevision = sourceRevision;
        ConfigurationRevision = configurationRevision;
        MigrationSetDigest = migrationSetDigest;
        PreviousQualifiedDigest = previousQualifiedDigest;
        PreviousQualifiedConfigurationRevision = previousQualifiedConfigurationRevision;
        PreviousQualifiedMigrationSetDigest = previousQualifiedMigrationSetDigest;
        CandidateDigest = candidateDigest;
        HandoffDigest = handoffDigest;
        DigestVerified = digestVerified;
        ObservedAt = observedAt;
        Clients = new ReadOnlyCollection<PublicAlphaClientEvidence>(clients.ToArray());
    }

    public string ReleaseId { get; }
    public string SourceRevision { get; }
    public string ConfigurationRevision { get; }
    public string MigrationSetDigest { get; }
    public string PreviousQualifiedDigest { get; }
    public string PreviousQualifiedConfigurationRevision { get; }
    public string PreviousQualifiedMigrationSetDigest { get; }
    public string CandidateDigest { get; }
    public string HandoffDigest { get; }
    public bool DigestVerified { get; }
    public DateTimeOffset ObservedAt { get; }
    public IReadOnlyList<PublicAlphaClientEvidence> Clients { get; }
}

public sealed record PublicAlphaFinalApproval(
    string ApprovalId,
    string Actor,
    string CandidateDigest,
    DateTimeOffset ObservedAt,
    string ManualQaEvidenceDigest,
    bool Approved);

public sealed record PublicAlphaReleaseRequest(
    PublicAlphaReleaseIdentity Release,
    DateTimeOffset DecisionTime,
    TimeSpan MaximumEvidenceAge,
    bool ActivationCommitted,
    IReadOnlyList<PublicAlphaRegionReleaseState> Regions,
    IReadOnlyList<PublicAlphaGateEvidence> Gates,
    PublicAlphaCrossClientHandoff? CrossClientHandoff,
    PublicAlphaRegionQualificationDecision? RegionQualification,
    PublicAlphaReadinessDecision? Readiness,
    PublicAlphaFinalApproval? FinalApproval);

public sealed class PublicAlphaReleaseError
{
    internal PublicAlphaReleaseError(
        PublicAlphaReleaseErrorCode code,
        PublicAlphaRegion? region = null,
        PublicAlphaGateKind? gate = null)
    {
        Code = code;
        Region = region;
        Gate = gate;
    }

    public PublicAlphaReleaseErrorCode Code { get; }
    public PublicAlphaRegion? Region { get; }
    public PublicAlphaGateKind? Gate { get; }
}

public abstract class PublicAlphaReleaseIntent
{
    private protected PublicAlphaReleaseIntent() { }
}

public sealed class PreparePublicAlphaRegionIntent : PublicAlphaReleaseIntent
{
    internal PreparePublicAlphaRegionIntent(PublicAlphaRegion region, string candidateDigest)
    {
        Region = region;
        CandidateDigest = candidateDigest;
    }

    public PublicAlphaRegion Region { get; }
    public string CandidateDigest { get; }
}

public sealed class ActivatePublicAlphaReleaseIntent : PublicAlphaReleaseIntent
{
    internal ActivatePublicAlphaReleaseIntent(string candidateDigest)
    {
        CandidateDigest = candidateDigest;
        Regions = PublicAlphaRegionCatalog.LaunchRegions;
    }

    public string CandidateDigest { get; }
    public IReadOnlyList<PublicAlphaRegion> Regions { get; }
}

public sealed class RollbackPublicAlphaReleaseIntent : PublicAlphaReleaseIntent
{
    internal RollbackPublicAlphaReleaseIntent(
        string failedDigest,
        string rollbackDigest,
        string configurationRevision,
        string migrationSetDigest)
    {
        FailedDigest = failedDigest;
        RollbackDigest = rollbackDigest;
        ConfigurationRevision = configurationRevision;
        MigrationSetDigest = migrationSetDigest;
        Regions = PublicAlphaRegionCatalog.LaunchRegions;
    }

    public string FailedDigest { get; }
    public string RollbackDigest { get; }
    public string ConfigurationRevision { get; }
    public string MigrationSetDigest { get; }
    public IReadOnlyList<PublicAlphaRegion> Regions { get; }
    public bool RebuildAllowed => false;
}

public sealed class ConvergePublicAlphaRegionIntent : PublicAlphaReleaseIntent
{
    internal ConvergePublicAlphaRegionIntent(PublicAlphaRegion region, string digest)
    {
        Region = region;
        Digest = digest;
    }

    public PublicAlphaRegion Region { get; }
    public string Digest { get; }
}

public sealed record PublicAlphaReceiptEvidenceLink(string Kind, string Digest);
public sealed record PublicAlphaReceiptEvent(string Decision, string Actor, DateTimeOffset RecordedAt, string GlobalDigest);

public sealed class PublicAlphaReleaseReceipt
{
    internal PublicAlphaReleaseReceipt(
        PublicAlphaReleaseIdentity release,
        IReadOnlyList<PublicAlphaReceiptEvidenceLink> evidenceLinks,
        IReadOnlyList<PublicAlphaReceiptEvent> events)
    {
        ReleaseId = release.ReleaseId;
        SourceRevision = release.SourceRevision;
        CandidateDigest = release.CandidateDigest;
        PreviousQualifiedDigest = release.PreviousQualifiedDigest;
        ConfigurationRevision = release.ConfigurationRevision;
        MigrationSetDigest = release.MigrationSetDigest;
        PreviousQualifiedConfigurationRevision = release.PreviousQualifiedConfigurationRevision;
        PreviousQualifiedMigrationSetDigest = release.PreviousQualifiedMigrationSetDigest;
        CreatedAt = release.CreatedAt;
        Regions = PublicAlphaRegionCatalog.LaunchRegions;
        EvidenceLinks = new ReadOnlyCollection<PublicAlphaReceiptEvidenceLink>(evidenceLinks.ToArray());
        Events = new ReadOnlyCollection<PublicAlphaReceiptEvent>(events.ToArray());
        Digest = ComputeDigest(this);
    }

    public string ReleaseId { get; }
    public string SourceRevision { get; }
    public string CandidateDigest { get; }
    public string PreviousQualifiedDigest { get; }
    public string ConfigurationRevision { get; }
    public string MigrationSetDigest { get; }
    public string PreviousQualifiedConfigurationRevision { get; }
    public string PreviousQualifiedMigrationSetDigest { get; }
    public DateTimeOffset CreatedAt { get; }
    public IReadOnlyList<PublicAlphaRegion> Regions { get; }
    public IReadOnlyList<PublicAlphaReceiptEvidenceLink> EvidenceLinks { get; }
    public IReadOnlyList<PublicAlphaReceiptEvent> Events { get; }
    public string Digest { get; }

    private static string ComputeDigest(PublicAlphaReleaseReceipt receipt)
    {
        var canonical = new StringBuilder()
            .AppendLine(receipt.ReleaseId)
            .AppendLine(receipt.SourceRevision)
            .AppendLine(receipt.CandidateDigest)
            .AppendLine(receipt.PreviousQualifiedDigest)
            .AppendLine(receipt.ConfigurationRevision)
            .AppendLine(receipt.MigrationSetDigest)
            .AppendLine(receipt.PreviousQualifiedConfigurationRevision)
            .AppendLine(receipt.PreviousQualifiedMigrationSetDigest)
            .AppendLine(receipt.CreatedAt.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture));
        foreach (var region in receipt.Regions)
            canonical.AppendLine(PublicAlphaRegionCatalog.Code(region));
        foreach (var link in receipt.EvidenceLinks.OrderBy(static item => item.Kind, StringComparer.Ordinal)
                     .ThenBy(static item => item.Digest, StringComparer.Ordinal))
            canonical.Append(link.Kind).Append('=').AppendLine(link.Digest);
        foreach (var item in receipt.Events)
            canonical.Append(item.Decision).Append('|').Append(item.Actor).Append('|')
                .Append(item.RecordedAt.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture))
                .Append('|').AppendLine(item.GlobalDigest);
        return $"sha256:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())))}";
    }
}

public sealed class PublicAlphaReleaseDecision
{
    internal PublicAlphaReleaseDecision(
        IReadOnlyList<PublicAlphaReleaseIntent> intents,
        IReadOnlyList<PublicAlphaReleaseError> errors,
        PublicAlphaReleaseReceipt receipt)
    {
        Intents = intents;
        Errors = errors;
        Receipt = receipt;
    }

    public IReadOnlyList<PublicAlphaReleaseIntent> Intents { get; }
    public IReadOnlyList<PublicAlphaReleaseError> Errors { get; }
    public PublicAlphaReleaseReceipt Receipt { get; }
}

public static class PublicAlphaReleaseCoordinator
{
    private const string FinalLaunchApprover = "mariogk";
    private static readonly IReadOnlyList<PublicAlphaGateKind> CustomerGates =
        new ReadOnlyCollection<PublicAlphaGateKind>(Enum.GetValues<PublicAlphaGateKind>()
            .Where(static kind => kind != PublicAlphaGateKind.Unknown).ToArray());
    private static readonly IReadOnlyList<PublicAlphaClientKind> PublicClients =
        new ReadOnlyCollection<PublicAlphaClientKind>(Enum.GetValues<PublicAlphaClientKind>()
            .Where(static kind => kind != PublicAlphaClientKind.Unknown).ToArray());

    public static IReadOnlyList<PublicAlphaGateKind> RequiredCustomerGates => CustomerGates;
    public static IReadOnlyList<PublicAlphaClientKind> RequiredClients => PublicClients;

    public static PublicAlphaReleaseDecision Decide(PublicAlphaReleaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Release);
        var errors = ValidateRequest(request);
        var links = EvidenceLinks(request);

        if (errors.Count != 0)
            return Decision(request.Release, [], errors, links, []);

        var targetDigest = request.ActivationCommitted
            ? request.Release.CandidateDigest
            : request.Release.PreviousQualifiedDigest;
        var divergent = request.Regions.Where(region =>
            !string.Equals(region.ServingDigest, targetDigest, StringComparison.Ordinal)).ToArray();
        if (request.ActivationCommitted)
        {
            ValidateGates(request, PublicAlphaGatePhase.PostActivation, errors);
            ValidateCrossClientHandoff(request, errors);
            ValidateRegionQualification(request, errors);
            ValidateReadiness(request, errors);
            ValidateApproval(request, errors);
            if (errors.Count != 0)
            {
                PublicAlphaReleaseIntent[] rollback =
                    [new RollbackPublicAlphaReleaseIntent(
                        request.Release.CandidateDigest,
                        request.Release.PreviousQualifiedDigest,
                        request.Release.PreviousQualifiedConfigurationRevision,
                        request.Release.PreviousQualifiedMigrationSetDigest)];
                PublicAlphaReceiptEvent[] events =
                    [new("rollback", "terrascale-orchestrator", request.DecisionTime, request.Release.PreviousQualifiedDigest)];
                return Decision(request.Release, rollback, errors, links, events);
            }

            if (divergent.Length != 0)
            {
                var intents = divergent.Select(region =>
                    (PublicAlphaReleaseIntent)new ConvergePublicAlphaRegionIntent(region.Region, targetDigest)).ToArray();
                PublicAlphaReceiptEvent[] events =
                    [new("converge", "terrascale-orchestrator", request.DecisionTime, targetDigest)];
                return Decision(request.Release, intents, [], links, events);
            }

            return Decision(request.Release, [], [], links,
                [new("verified", "terrascale-orchestrator", request.DecisionTime, request.Release.CandidateDigest)]);
        }

        var failedPreparation = request.Regions.Where(static region => region.PreparationFailed).ToArray();
        if (failedPreparation.Length != 0)
        {
            errors.AddRange(failedPreparation.Select(region =>
                new PublicAlphaReleaseError(PublicAlphaReleaseErrorCode.PreparationFailed, region.Region)));
            return Decision(request.Release, [], errors, links, []);
        }

        if (divergent.Length != 0)
        {
            var intents = divergent.Select(region =>
                (PublicAlphaReleaseIntent)new ConvergePublicAlphaRegionIntent(region.Region, targetDigest)).ToArray();
            PublicAlphaReceiptEvent[] events =
                [new("converge", "terrascale-orchestrator", request.DecisionTime, targetDigest)];
            return Decision(request.Release, intents, [], links, events);
        }

        var unprepared = request.Regions.Where(region =>
            !string.Equals(region.PreparedDigest, request.Release.CandidateDigest, StringComparison.Ordinal)).ToArray();
        if (unprepared.Length != 0)
        {
            var intents = unprepared.Select(region =>
                (PublicAlphaReleaseIntent)new PreparePublicAlphaRegionIntent(region.Region, request.Release.CandidateDigest)).ToArray();
            return Decision(request.Release, intents, [], links, []);
        }

        ValidateGates(request, PublicAlphaGatePhase.PreActivation, errors);
        ValidateCrossClientHandoff(request, errors);
        ValidateRegionQualification(request, errors);
        ValidateReadiness(request, errors);
        ValidateApproval(request, errors);

        if (errors.Count != 0)
            return Decision(request.Release, [], errors, links, []);

        PublicAlphaReleaseIntent[] activation = [new ActivatePublicAlphaReleaseIntent(request.Release.CandidateDigest)];
        PublicAlphaReceiptEvent[] activationEvents =
            [new("activate", request.FinalApproval!.Actor, request.DecisionTime, request.Release.CandidateDigest)];
        return Decision(request.Release, activation, [], links, activationEvents);
    }

    private static List<PublicAlphaReleaseError> ValidateRequest(PublicAlphaReleaseRequest request)
    {
        var errors = new List<PublicAlphaReleaseError>();
        if (!SafeLabel(request.Release.ReleaseId) || !ObjectId(request.Release.SourceRevision) ||
            !Digest(request.Release.CandidateDigest) || !Digest(request.Release.PreviousQualifiedDigest) ||
            string.Equals(request.Release.CandidateDigest, request.Release.PreviousQualifiedDigest, StringComparison.Ordinal) ||
            !SafeLabel(request.Release.ConfigurationRevision) || !Digest(request.Release.MigrationSetDigest) ||
            !SafeLabel(request.Release.PreviousQualifiedConfigurationRevision) ||
            !Digest(request.Release.PreviousQualifiedMigrationSetDigest) ||
            request.Release.CreatedAt == default || request.DecisionTime == default ||
            request.Release.CreatedAt > request.DecisionTime || request.MaximumEvidenceAge <= TimeSpan.Zero)
            errors.Add(new(PublicAlphaReleaseErrorCode.InvalidInput));

        if (request.Regions is null || request.Regions.Count != PublicAlphaRegionCatalog.LaunchRegions.Count ||
            request.Regions.Any(static region => region is null) ||
            request.Regions.Select(static region => region.Region).Distinct().Count() != request.Regions.Count ||
            !request.Regions.Select(static region => region.Region).ToHashSet()
                .SetEquals(PublicAlphaRegionCatalog.LaunchRegions) ||
            request.Regions.Any(static region => !Digest(region.ServingDigest) ||
                region.PreparedDigest is not null && !Digest(region.PreparedDigest)))
            errors.Add(new(PublicAlphaReleaseErrorCode.RegionSetMismatch));
        return errors;
    }

    private static void ValidateGates(
        PublicAlphaReleaseRequest request,
        PublicAlphaGatePhase phase,
        List<PublicAlphaReleaseError> errors)
    {
        var expectedCount = PublicAlphaRegionCatalog.LaunchRegions.Count * RequiredCustomerGates.Count;
        if (request.Gates is null || request.Gates.Count != expectedCount ||
            request.Gates.Any(static item => item is null) ||
            request.Gates.Select(static item => (item.Phase, item.Region, item.Kind)).Distinct().Count() !=
                request.Gates.Count ||
            request.Gates.Any(item => item.Phase != phase ||
                !PublicAlphaRegionCatalog.LaunchRegions.Contains(item.Region) ||
                !RequiredCustomerGates.Contains(item.Kind)))
        {
            errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceMissing));
            return;
        }

        foreach (var region in PublicAlphaRegionCatalog.LaunchRegions)
            foreach (var kind in RequiredCustomerGates)
            {
                var matching = request.Gates.Where(item =>
                    item.Region == region && item.Kind == kind && item.Phase == phase).ToArray();
                if (matching.Length != 1)
                {
                    errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceMissing, region, kind));
                    continue;
                }

                var evidence = matching[0];
                if (!string.Equals(evidence.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal) ||
                    !Digest(evidence.EvidenceDigest))
                    errors.Add(new(PublicAlphaReleaseErrorCode.EvidenceDigestMismatch, region, kind));
                else if (!Fresh(evidence.ObservedAt, request))
                    errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceStale, region, kind));
                else if (evidence.Status != PublicAlphaGateStatus.Passed)
                    errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceFailed, region, kind));

                if (kind is PublicAlphaGateKind.ErrorRate or PublicAlphaGateKind.ApiLatency &&
                    (evidence.Threshold is not { } threshold || threshold.Window <= TimeSpan.Zero ||
                     !Required(threshold.Metric) || !Required(threshold.Unit) || !Required(threshold.Source) ||
                     !Required(threshold.QualifiedBaseline)))
                    errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceMissing, region, kind));
            }
    }

    private static void ValidateCrossClientHandoff(
        PublicAlphaReleaseRequest request,
        List<PublicAlphaReleaseError> errors)
    {
        var handoff = request.CrossClientHandoff;
        if (handoff is null || !handoff.DigestVerified || !Digest(handoff.HandoffDigest) ||
            !Fresh(handoff.ObservedAt, request) || handoff.Clients is null ||
            handoff.Clients.Count != RequiredClients.Count ||
            handoff.Clients.Any(static client => client is null) ||
            handoff.Clients.Select(static client => client.Kind).Distinct().Count() != handoff.Clients.Count)
        {
            errors.Add(new(PublicAlphaReleaseErrorCode.RequiredEvidenceMissing));
            return;
        }

        if (!string.Equals(handoff.ReleaseId, request.Release.ReleaseId, StringComparison.Ordinal) ||
            !string.Equals(handoff.SourceRevision, request.Release.SourceRevision, StringComparison.Ordinal) ||
            !string.Equals(handoff.ConfigurationRevision, request.Release.ConfigurationRevision, StringComparison.Ordinal) ||
            !string.Equals(handoff.MigrationSetDigest, request.Release.MigrationSetDigest, StringComparison.Ordinal) ||
            !string.Equals(handoff.PreviousQualifiedDigest, request.Release.PreviousQualifiedDigest, StringComparison.Ordinal) ||
            !string.Equals(handoff.PreviousQualifiedConfigurationRevision,
                request.Release.PreviousQualifiedConfigurationRevision, StringComparison.Ordinal) ||
            !string.Equals(handoff.PreviousQualifiedMigrationSetDigest,
                request.Release.PreviousQualifiedMigrationSetDigest, StringComparison.Ordinal) ||
            !string.Equals(handoff.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal))
        {
            errors.Add(new(PublicAlphaReleaseErrorCode.EvidenceDigestMismatch));
            return;
        }

        var journeySpecifications = handoff.Clients.Select(static client => client.JourneySpecificationDigest)
            .Distinct(StringComparer.Ordinal).ToArray();
        if (!handoff.Clients.Select(static client => client.Kind).ToHashSet().SetEquals(RequiredClients) ||
            journeySpecifications.Length != 1 || handoff.Clients.Any(client =>
                !client.Passed || !Required(client.Version) || !Digest(client.ArtifactDigest) ||
                !Digest(client.JourneySpecificationDigest) ||
                !string.Equals(client.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal)))
            errors.Add(new(PublicAlphaReleaseErrorCode.EvidenceDigestMismatch));
    }

    private static void ValidateApproval(
        PublicAlphaReleaseRequest request,
        List<PublicAlphaReleaseError> errors)
    {
        var approval = request.FinalApproval;
        if (approval is null || !approval.Approved || !SafeLabel(approval.ApprovalId) || !SafeLabel(approval.Actor) ||
            !Digest(approval.ManualQaEvidenceDigest) ||
            !string.Equals(approval.Actor, FinalLaunchApprover, StringComparison.Ordinal) ||
            !string.Equals(approval.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal) ||
            !Fresh(approval.ObservedAt, request))
            errors.Add(new(PublicAlphaReleaseErrorCode.ApprovalDenied));
    }

    private static void ValidateReadiness(
        PublicAlphaReleaseRequest request,
        List<PublicAlphaReleaseError> errors)
    {
        if (request.Readiness is not { Authorized: true } readiness ||
            readiness.Errors.Count != 0 || readiness.EvidenceDigests.Count == 0 ||
            readiness.EvidenceDigests.Any(static digest => !Digest(digest)) ||
            readiness.EvidenceDigests.Distinct(StringComparer.Ordinal).Count() != readiness.EvidenceDigests.Count ||
            !string.Equals(readiness.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal) ||
            !Fresh(readiness.QualifiedAt, request) || !Fresh(readiness.OldestEvidenceAt, request) ||
            readiness.OldestEvidenceAt > readiness.QualifiedAt)
            errors.Add(new(PublicAlphaReleaseErrorCode.ReadinessDenied));
    }

    private static void ValidateRegionQualification(
        PublicAlphaReleaseRequest request,
        List<PublicAlphaReleaseError> errors)
    {
        if (request.RegionQualification is not { Authorized: true } qualification ||
            qualification.Errors.Count != 0 || qualification.EvidenceDigests.Count == 0 ||
            qualification.EvidenceDigests.Any(static digest => !Digest(digest)) ||
            qualification.EvidenceDigests.Distinct(StringComparer.Ordinal).Count() != qualification.EvidenceDigests.Count ||
            !string.Equals(qualification.CandidateDigest, request.Release.CandidateDigest, StringComparison.Ordinal) ||
            !Fresh(qualification.QualifiedAt, request) || !Fresh(qualification.OldestEvidenceAt, request) ||
            qualification.OldestEvidenceAt > qualification.QualifiedAt)
            errors.Add(new(PublicAlphaReleaseErrorCode.RegionQualificationDenied));
    }

    private static IReadOnlyList<PublicAlphaReceiptEvidenceLink> EvidenceLinks(PublicAlphaReleaseRequest request)
    {
        var links = new List<PublicAlphaReceiptEvidenceLink>();
        if (request.Gates is not null)
            links.AddRange(request.Gates.Where(static gate => gate is not null &&
                    PublicAlphaRegionCatalog.LaunchRegions.Contains(gate.Region) && Digest(gate.EvidenceDigest))
                .Select(gate => new PublicAlphaReceiptEvidenceLink(
                    $"gate/{gate.Phase}/{PublicAlphaRegionCatalog.Code(gate.Region)}/{gate.Kind}", gate.EvidenceDigest)));
        if (request.CrossClientHandoff is { } handoff && Digest(handoff.HandoffDigest))
            links.Add(new("cross-client-handoff", handoff.HandoffDigest));
        if (request.RegionQualification is { } regionQualification)
            links.AddRange(regionQualification.EvidenceDigests.Where(Digest)
                .Select(static digest => new PublicAlphaReceiptEvidenceLink("region-qualification", digest)));
        if (request.Readiness is { } readiness)
            links.AddRange(readiness.EvidenceDigests.Where(Digest)
                .Select(static digest => new PublicAlphaReceiptEvidenceLink("production-readiness", digest)));
        if (request.FinalApproval is { } approval && Digest(approval.ManualQaEvidenceDigest))
            links.Add(new("manual-qa", approval.ManualQaEvidenceDigest));
        if (request.FinalApproval is { } finalApproval && SafeLabel(finalApproval.ApprovalId))
            links.Add(new("final-approval", $"sha256:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(finalApproval.ApprovalId)))}"));
        return new ReadOnlyCollection<PublicAlphaReceiptEvidenceLink>(links.Distinct().ToArray());
    }

    private static PublicAlphaReleaseDecision Decision(
        PublicAlphaReleaseIdentity release,
        IReadOnlyList<PublicAlphaReleaseIntent> intents,
        IReadOnlyList<PublicAlphaReleaseError> errors,
        IReadOnlyList<PublicAlphaReceiptEvidenceLink> links,
        IReadOnlyList<PublicAlphaReceiptEvent> events) =>
        new(new ReadOnlyCollection<PublicAlphaReleaseIntent>(intents.ToArray()),
            new ReadOnlyCollection<PublicAlphaReleaseError>(errors.ToArray()),
            new(release, links, new ReadOnlyCollection<PublicAlphaReceiptEvent>(events.ToArray())));

    private static bool Fresh(DateTimeOffset observedAt, PublicAlphaReleaseRequest request) =>
        observedAt <= request.DecisionTime && request.DecisionTime - observedAt <= request.MaximumEvidenceAge;

    private static bool Required(string? value) => value is { Length: <= 256 } && !string.IsNullOrWhiteSpace(value);
    private static bool SafeLabel(string? value) => Required(value) &&
        !value!.Contains('\n', StringComparison.Ordinal) && !value.Contains('\r', StringComparison.Ordinal) &&
        !new[] { "authorization:", "bearer ", "password", "secret", "token", "query=" }
            .Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    private static bool Digest(string? value) => PublicAlphaDigest.IsValid(value);
    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}

public enum PublicAlphaReadinessKind
{
    Unknown,
    ControlPlaneRestartAndDuplicateDelivery,
    ProviderActuatorRecovery,
    PlacementAndJournalRecovery,
    RegionalAgentRecovery,
    NetworkPartitionRecovery,
    DuplicateDeliveryRecovery,
    StaleMetricRejection,
    ExpiredCredentialRejection,
    ProviderFailureRecovery,
    CredentialScopeAndRedaction,
    ProviderAuthorizationAndAudit,
    HealthFreshnessAndCollectionAlerts,
    OperatorDashboardCoverage,
    DiscordFailureIsolation,
    CustomerDocumentAccessDenial,
    RunbookCoverage,
    ProductionThreeRegionRehearsal,
    RegionalEndpointQualification,
    RegistrationEmailPaymentOnboardingAndDashboard,
    CustomerDatabaseApiJourneyAllRegions,
    PublicStatusPublished,
    SecurityDisclosurePublished,
    LegalPoliciesPublished,
    SupportTermsPublished,
    LaunchDocumentationPublished,
    TargetedRegionalManualQa,
    SevenDayProductionSoak,
    ReadinessAuditClear,
}

public enum PublicAlphaReadinessStatus { Unknown, Passed, Failed }
public enum PublicAlphaReadinessErrorCode { Unknown, Missing, Failed, Stale, DigestMismatch }

public sealed record PublicAlphaReadinessEvidence(
    PublicAlphaReadinessKind Kind,
    string CandidateDigest,
    DateTimeOffset ObservedAt,
    PublicAlphaReadinessStatus Status,
    string EvidenceDigest);

public sealed record PublicAlphaReadinessRequest(
    string CandidateDigest,
    DateTimeOffset DecisionTime,
    TimeSpan MaximumEvidenceAge,
    IReadOnlyList<PublicAlphaReadinessEvidence> Evidence);

public sealed record PublicAlphaReadinessError(PublicAlphaReadinessKind Kind, PublicAlphaReadinessErrorCode Code);
public sealed class PublicAlphaReadinessDecision
{
    internal PublicAlphaReadinessDecision(
        string candidateDigest,
        DateTimeOffset qualifiedAt,
        DateTimeOffset oldestEvidenceAt,
        bool authorized,
        IReadOnlyList<PublicAlphaReadinessError> errors,
        IReadOnlyList<string> evidenceDigests)
    {
        CandidateDigest = candidateDigest;
        QualifiedAt = qualifiedAt;
        OldestEvidenceAt = oldestEvidenceAt;
        Authorized = authorized;
        Errors = new ReadOnlyCollection<PublicAlphaReadinessError>(errors.ToArray());
        EvidenceDigests = new ReadOnlyCollection<string>(evidenceDigests.ToArray());
    }

    public string CandidateDigest { get; }
    public DateTimeOffset QualifiedAt { get; }
    public DateTimeOffset OldestEvidenceAt { get; }
    public bool Authorized { get; }
    public IReadOnlyList<PublicAlphaReadinessError> Errors { get; }
    public IReadOnlyList<string> EvidenceDigests { get; }
}

public static class PublicAlphaReadinessGate
{
    private static readonly IReadOnlyList<PublicAlphaReadinessKind> Areas =
        new ReadOnlyCollection<PublicAlphaReadinessKind>(Enum.GetValues<PublicAlphaReadinessKind>()
            .Where(static kind => kind != PublicAlphaReadinessKind.Unknown).ToArray());

    public static IReadOnlyList<PublicAlphaReadinessKind> RequiredAreas => Areas;

    public static PublicAlphaReadinessDecision Decide(PublicAlphaReadinessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var errors = new List<PublicAlphaReadinessError>();
        if (!Digest(request.CandidateDigest) || request.DecisionTime == default ||
            request.MaximumEvidenceAge <= TimeSpan.Zero || request.Evidence is null)
            return new(request.CandidateDigest, request.DecisionTime, request.DecisionTime, false,
                [new(PublicAlphaReadinessKind.ControlPlaneRestartAndDuplicateDelivery,
                    PublicAlphaReadinessErrorCode.Missing)], []);
        if (request.Evidence.Count != RequiredAreas.Count ||
            request.Evidence.Any(item => item is null || !RequiredAreas.Contains(item.Kind)) ||
            request.Evidence.Select(static item => item.Kind).Distinct().Count() != request.Evidence.Count)
            return new(request.CandidateDigest, request.DecisionTime, request.DecisionTime, false,
                [new(PublicAlphaReadinessKind.Unknown, PublicAlphaReadinessErrorCode.Missing)], []);

        foreach (var kind in RequiredAreas)
        {
            var matching = request.Evidence.Where(item => item.Kind == kind).ToArray();
            if (matching.Length != 1)
                errors.Add(new(kind, PublicAlphaReadinessErrorCode.Missing));
            else if (!string.Equals(matching[0].CandidateDigest, request.CandidateDigest, StringComparison.Ordinal) ||
                     !Digest(matching[0].EvidenceDigest))
                errors.Add(new(kind, PublicAlphaReadinessErrorCode.DigestMismatch));
            else if (matching[0].ObservedAt == default || matching[0].ObservedAt > request.DecisionTime ||
                     request.DecisionTime - matching[0].ObservedAt > request.MaximumEvidenceAge)
                errors.Add(new(kind, PublicAlphaReadinessErrorCode.Stale));
            else if (matching[0].Status != PublicAlphaReadinessStatus.Passed)
                errors.Add(new(kind, PublicAlphaReadinessErrorCode.Failed));
        }

        var digests = request.Evidence.Where(static evidence => Digest(evidence.EvidenceDigest))
            .Select(static evidence => evidence.EvidenceDigest).Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal).ToArray();
        var oldestEvidenceAt = request.Evidence.Select(static evidence => evidence.ObservedAt).Min();
        return new(request.CandidateDigest, request.DecisionTime, oldestEvidenceAt, errors.Count == 0,
            new ReadOnlyCollection<PublicAlphaReadinessError>(errors),
            new ReadOnlyCollection<string>(digests));
    }

    private static bool Digest(string? value) => PublicAlphaDigest.IsValid(value);
}
