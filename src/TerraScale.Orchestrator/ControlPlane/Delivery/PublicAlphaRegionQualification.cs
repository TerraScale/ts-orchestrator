using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

public enum PublicAlphaRegionalTestKind
{
    Unknown,
    Read,
    Write,
    Query,
    Replication,
    TenantIsolation,
    Failover,
}

public enum PublicAlphaRegionQualificationErrorCode
{
    Unknown,
    InvalidInput,
    MissingEvidence,
    CandidateMismatch,
    StaleEvidence,
    ProbeFailed,
    TestFailed,
}

public sealed record PublicAlphaExternalEndpointProbe(
    PublicAlphaEndpoint Endpoint,
    PublicAlphaRegion? RequestedRegion,
    string Uri,
    PublicAlphaRegion ObservedRegion,
    string CandidateDigest,
    DateTimeOffset ObservedAt,
    bool DnsResolved,
    bool TimedOut,
    int HttpStatusCode,
    string TlsProtocol,
    bool CertificateHostnameValid,
    DateTimeOffset CertificateNotBefore,
    DateTimeOffset CertificateNotAfter,
    PublicAlphaRegionHealth Health,
    string EvidenceDigest);

public sealed record PublicAlphaRegionalTestEvidence(
    PublicAlphaRegion Region,
    PublicAlphaRegionalTestKind Kind,
    string CandidateDigest,
    DateTimeOffset ObservedAt,
    PublicAlphaGateStatus Status,
    string EvidenceDigest);

public sealed record PublicAlphaRegionQualificationRequest(
    string CandidateDigest,
    DateTimeOffset DecisionTime,
    TimeSpan MaximumEvidenceAge,
    IReadOnlyList<PublicAlphaExternalEndpointProbe> Probes,
    IReadOnlyList<PublicAlphaRegionalTestEvidence> Tests);

public sealed record PublicAlphaRegionQualificationError(
    PublicAlphaRegionQualificationErrorCode Code,
    PublicAlphaRegion? Region = null,
    PublicAlphaRegionalTestKind? Test = null);

public sealed class PublicAlphaRegionQualificationDecision
{
    internal PublicAlphaRegionQualificationDecision(
        string candidateDigest,
        DateTimeOffset qualifiedAt,
        DateTimeOffset oldestEvidenceAt,
        IReadOnlyList<PublicAlphaRegionQualificationError> errors,
        IReadOnlyList<string> evidenceDigests)
    {
        CandidateDigest = candidateDigest;
        QualifiedAt = qualifiedAt;
        OldestEvidenceAt = oldestEvidenceAt;
        Errors = new ReadOnlyCollection<PublicAlphaRegionQualificationError>(errors.ToArray());
        EvidenceDigests = new ReadOnlyCollection<string>(evidenceDigests.ToArray());
    }

    public string CandidateDigest { get; }
    public DateTimeOffset QualifiedAt { get; }
    public DateTimeOffset OldestEvidenceAt { get; }
    public bool Authorized => Errors.Count == 0;
    public IReadOnlyList<PublicAlphaRegionQualificationError> Errors { get; }
    public IReadOnlyList<string> EvidenceDigests { get; }
}

public static class PublicAlphaRegionQualificationGate
{
    private static readonly IReadOnlyList<PublicAlphaRegionalTestKind> Tests =
        new ReadOnlyCollection<PublicAlphaRegionalTestKind>(Enum.GetValues<PublicAlphaRegionalTestKind>()
            .Where(static kind => kind != PublicAlphaRegionalTestKind.Unknown).ToArray());

    public static IReadOnlyList<PublicAlphaRegionalTestKind> RequiredTests => Tests;

    public static PublicAlphaRegionQualificationDecision Decide(PublicAlphaRegionQualificationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var errors = new List<PublicAlphaRegionQualificationError>();
        if (!PublicAlphaDigest.IsValid(request.CandidateDigest) || request.DecisionTime == default ||
            request.MaximumEvidenceAge <= TimeSpan.Zero ||
            request.Probes is null || request.Tests is null ||
            request.Probes.Any(static probe => probe is null) ||
            request.Tests.Any(static item => item is null))
            return Decision(request, [new(PublicAlphaRegionQualificationErrorCode.InvalidInput)]);

        ValidateProbes(request, errors);
        ValidateTests(request, errors);
        var evidenceDigests = request.Probes.Select(static item => item.EvidenceDigest)
            .Concat(request.Tests.Select(static item => item.EvidenceDigest)).ToArray();
        if (evidenceDigests.Distinct(StringComparer.Ordinal).Count() != evidenceDigests.Length)
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.MissingEvidence));
        return Decision(request, errors);
    }

    private static void ValidateProbes(
        PublicAlphaRegionQualificationRequest request,
        List<PublicAlphaRegionQualificationError> errors)
    {
        var expected = PublicAlphaRegionCatalog.LaunchRegions.Count + 1;
        if (request.Probes.Count != expected ||
            request.Probes.Any(static probe => probe is null) ||
            request.Probes.Select(static probe => (probe.Endpoint, probe.RequestedRegion)).Distinct().Count() != expected)
        {
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.MissingEvidence));
            return;
        }

        ValidateProbe(request, errors, PublicAlphaEndpoint.Global, null);
        foreach (var region in PublicAlphaRegionCatalog.LaunchRegions)
            ValidateProbe(request, errors, PublicAlphaEndpoint.StrictRegional, region);
    }

    private static void ValidateProbe(
        PublicAlphaRegionQualificationRequest request,
        List<PublicAlphaRegionQualificationError> errors,
        PublicAlphaEndpoint endpoint,
        PublicAlphaRegion? requestedRegion)
    {
        var matching = request.Probes.Where(probe =>
            probe.Endpoint == endpoint && probe.RequestedRegion == requestedRegion).ToArray();
        if (matching.Length != 1)
        {
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.MissingEvidence, requestedRegion));
            return;
        }

        var probe = matching[0];
        var expectedUri = endpoint == PublicAlphaEndpoint.Global
            ? $"https://{PublicAlphaRegionCatalog.GlobalHostName}/"
            : $"https://{PublicAlphaRegionCatalog.RegionalHostName(requestedRegion!.Value)}/";
        if (!string.Equals(probe.CandidateDigest, request.CandidateDigest, StringComparison.Ordinal) ||
            !PublicAlphaDigest.IsValid(probe.EvidenceDigest))
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.CandidateMismatch, requestedRegion));
        else if (!Fresh(probe.ObservedAt, request))
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.StaleEvidence, requestedRegion));
        else if (!string.Equals(probe.Uri, expectedUri, StringComparison.Ordinal) || !probe.DnsResolved ||
                 probe.TimedOut || probe.HttpStatusCode is < 200 or >= 300 ||
                 probe.TlsProtocol is not ("TLS1.2" or "TLS1.3") || !probe.CertificateHostnameValid ||
                 probe.CertificateNotBefore > probe.ObservedAt || probe.CertificateNotAfter <= request.DecisionTime ||
                 probe.Health != PublicAlphaRegionHealth.Healthy ||
                 !PublicAlphaRegionCatalog.LaunchRegions.Contains(probe.ObservedRegion) ||
                 requestedRegion is { } strictRegion && probe.ObservedRegion != strictRegion)
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.ProbeFailed, requestedRegion));
    }

    private static void ValidateTests(
        PublicAlphaRegionQualificationRequest request,
        List<PublicAlphaRegionQualificationError> errors)
    {
        var expected = PublicAlphaRegionCatalog.LaunchRegions.Count * RequiredTests.Count;
        if (request.Tests.Count != expected ||
            request.Tests.Any(static item => item is null) ||
            request.Tests.Select(static item => (item.Region, item.Kind)).Distinct().Count() != expected)
        {
            errors.Add(new(PublicAlphaRegionQualificationErrorCode.MissingEvidence));
            return;
        }

        foreach (var region in PublicAlphaRegionCatalog.LaunchRegions)
        foreach (var kind in RequiredTests)
        {
            var matching = request.Tests.Where(item => item.Region == region && item.Kind == kind).ToArray();
            if (matching.Length != 1)
            {
                errors.Add(new(PublicAlphaRegionQualificationErrorCode.MissingEvidence, region, kind));
                continue;
            }

            var evidence = matching[0];
            if (!string.Equals(evidence.CandidateDigest, request.CandidateDigest, StringComparison.Ordinal) ||
                !PublicAlphaDigest.IsValid(evidence.EvidenceDigest))
                errors.Add(new(PublicAlphaRegionQualificationErrorCode.CandidateMismatch, region, kind));
            else if (!Fresh(evidence.ObservedAt, request))
                errors.Add(new(PublicAlphaRegionQualificationErrorCode.StaleEvidence, region, kind));
            else if (evidence.Status != PublicAlphaGateStatus.Passed)
                errors.Add(new(PublicAlphaRegionQualificationErrorCode.TestFailed, region, kind));
        }
    }

    private static PublicAlphaRegionQualificationDecision Decision(
        PublicAlphaRegionQualificationRequest request,
        IReadOnlyList<PublicAlphaRegionQualificationError> errors)
    {
        var probes = (request.Probes ?? []).Where(static item => item is not null).ToArray();
        var tests = (request.Tests ?? []).Where(static item => item is not null).ToArray();
        var digests = probes.Select(static item => item.EvidenceDigest)
            .Concat(tests.Select(static item => item.EvidenceDigest))
            .Where(PublicAlphaDigest.IsValid).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var oldestEvidenceAt = probes.Select(static item => item.ObservedAt)
            .Concat(tests.Select(static item => item.ObservedAt))
            .DefaultIfEmpty(request.DecisionTime)
            .Min();
        return new(request.CandidateDigest, request.DecisionTime, oldestEvidenceAt, errors, digests);
    }

    private static bool Fresh(DateTimeOffset observedAt, PublicAlphaRegionQualificationRequest request) =>
        observedAt <= request.DecisionTime && request.DecisionTime - observedAt <= request.MaximumEvidenceAge;
}
