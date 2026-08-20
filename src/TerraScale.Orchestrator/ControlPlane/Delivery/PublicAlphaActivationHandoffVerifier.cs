using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

public static class PublicAlphaActivationHandoffVerifier
{
    private const string Schema = "terrascale.public-alpha-handoff/v1";
    private const int MaximumDocumentBytes = 2 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    public static PublicAlphaCrossClientHandoff ParseAndVerify(
        string json,
        DateTimeOffset decisionTime,
        TimeSpan maximumEvidenceAge)
    {
        if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > MaximumDocumentBytes ||
            maximumEvidenceAge <= TimeSpan.Zero)
            throw new InvalidDataException("The Public Alpha activation handoff is empty or exceeds its input bound.");
        DeployHandoff handoff;
        try
        {
            handoff = JsonSerializer.Deserialize<DeployHandoff>(json, JsonOptions)
                ?? throw new InvalidDataException("The Public Alpha activation handoff is empty.");
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException("The Public Alpha activation handoff JSON is invalid.", exception);
        }

        if (!string.Equals(handoff.Schema, Schema, StringComparison.Ordinal) ||
            !Digest(handoff.HandoffDigest) ||
            !string.Equals(handoff.HandoffDigest, ComputeDigest(handoff), StringComparison.Ordinal))
            throw new InvalidDataException("The Public Alpha activation handoff digest does not match its contents.");

        var allowedAge = ValidateIdentity(handoff, decisionTime, maximumEvidenceAge);
        ValidateArtifacts(handoff);
        ValidateRollback(handoff);
        ValidateRegions(handoff, decisionTime, allowedAge);
        ValidateClients(handoff, decisionTime, allowedAge);
        ValidateGates(handoff, decisionTime, allowedAge);
        ValidatePublicEndpoints(handoff, decisionTime, allowedAge);
        ValidateRetention(handoff);

        return new(
            handoff.ReleaseId,
            handoff.SourceRevision,
            handoff.ConfigurationRevision,
            handoff.MigrationSetDigest,
            handoff.PreviousQualified.CandidateDigest,
            handoff.PreviousQualified.ConfigurationRevision,
            handoff.PreviousQualified.MigrationSetDigest,
            handoff.CandidateDigest,
            handoff.HandoffDigest,
            true,
            OldestEvidenceAt(handoff),
            handoff.Clients.OrderBy(static client => client.Kind).Select(client => new PublicAlphaClientEvidence(
                ClientKind(client.Kind),
                client.Version,
                client.ArtifactDigest,
                client.CandidateDigest,
                client.JourneySpecificationDigest,
                client.Passed)).ToArray());
    }

    private static DateTimeOffset OldestEvidenceAt(DeployHandoff handoff) =>
        handoff.Regions.Select(static item => item.ObservedAt)
            .Concat(handoff.Clients.Select(static item => item.ObservedAt))
            .Concat(handoff.Gates.Select(static item => item.ObservedAt))
            .Concat(handoff.PublicEndpoints.Select(static item => item.ObservedAt))
            .Min();

    private static TimeSpan ValidateIdentity(
        DeployHandoff handoff,
        DateTimeOffset decisionTime,
        TimeSpan maximumEvidenceAge)
    {
        var allowedAge = handoff.MaximumEvidenceAge < maximumEvidenceAge
            ? handoff.MaximumEvidenceAge
            : maximumEvidenceAge;
        if (!Required(handoff.ReleaseId) || !ObjectId(handoff.SourceRevision) || !ObjectId(handoff.SourceTree) ||
            !Required(handoff.ConfigurationRevision) || !Digest(handoff.CandidateDigest) ||
            !Digest(handoff.MigrationSetDigest) || !Digest(handoff.JourneySpecificationDigest) ||
            handoff.MaximumEvidenceAge <= TimeSpan.Zero || handoff.BuiltAt > handoff.QualifiedAt ||
            handoff.QualifiedAt > decisionTime || decisionTime - handoff.QualifiedAt > allowedAge ||
            handoff.BuildEnvironment is null || !Required(handoff.BuildEnvironment.OperatingSystem) ||
            !Required(handoff.BuildEnvironment.SdkVersion) || !Digest(handoff.BuildEnvironment.RunnerImageDigest) ||
            !Digest(handoff.BuildEnvironment.DependencyLockDigest))
            throw new InvalidDataException("The Public Alpha activation handoff identity or build evidence is invalid.");
        return allowedAge;
    }

    private static void ValidateArtifacts(DeployHandoff handoff)
    {
        var required = Enum.GetValues<DeployArtifactKind>();
        if (handoff.Artifacts is null || handoff.Artifacts.Count != required.Length ||
            handoff.Artifacts.Select(static item => item.Kind).Distinct().Count() != handoff.Artifacts.Count ||
            !handoff.Artifacts.Select(static item => item.Kind).ToHashSet().SetEquals(required) ||
            handoff.Artifacts.Any(static item => !Required(item.Version) || !Digest(item.Digest)))
            throw new InvalidDataException("The Public Alpha activation handoff artifacts are incomplete.");
    }

    private static void ValidateRollback(DeployHandoff handoff)
    {
        var rollback = handoff.PreviousQualified;
        if (rollback is null || !ObjectId(rollback.SourceTree) || !Digest(rollback.CandidateDigest) ||
            string.Equals(rollback.CandidateDigest, handoff.CandidateDigest, StringComparison.Ordinal) ||
            !Required(rollback.ConfigurationRevision) || !Digest(rollback.MigrationSetDigest) ||
            !Digest(rollback.ExpectedArtifactDigest) || !Digest(rollback.RetainedArtifactDigest) ||
            !string.Equals(rollback.ExpectedArtifactDigest, rollback.RetainedArtifactDigest, StringComparison.Ordinal) ||
            !rollback.Retained || !rollback.SchemaCompatible)
            throw new InvalidDataException("The Public Alpha activation handoff has no usable rollback target.");
    }

    private static void ValidateRegions(DeployHandoff handoff, DateTimeOffset decisionTime, TimeSpan allowedAge)
    {
        var required = Enum.GetValues<DeployRegion>();
        if (handoff.Regions is null || handoff.Regions.Count != required.Length ||
            handoff.Regions.Select(static item => item.Region).Distinct().Count() != handoff.Regions.Count ||
            !handoff.Regions.Select(static item => item.Region).ToHashSet().SetEquals(required))
            throw new InvalidDataException("The Public Alpha activation handoff region set is incomplete.");

        foreach (var region in handoff.Regions)
            if (!string.Equals(region.CandidateDigest, handoff.CandidateDigest, StringComparison.Ordinal) ||
                !string.Equals(region.GlobalHostName, PublicAlphaRegionCatalog.GlobalHostName, StringComparison.Ordinal) ||
                !string.Equals(region.StrictRegionalHostName,
                    PublicAlphaRegionCatalog.RegionalHostName(Region(region.Region)), StringComparison.Ordinal) ||
                !Fresh(region.ObservedAt, handoff, decisionTime, allowedAge) ||
                !region.DownloadDigestMatched || !region.StartupPassed ||
                !region.SchemaCompatible || !Digest(region.EvidenceDigest))
                throw new InvalidDataException("The Public Alpha activation handoff contains an unqualified region.");
    }

    private static void ValidateClients(DeployHandoff handoff, DateTimeOffset decisionTime, TimeSpan allowedAge)
    {
        var required = Enum.GetValues<DeployClientKind>();
        if (handoff.Clients is null || handoff.Clients.Count != required.Length ||
            handoff.Clients.Select(static item => item.Kind).Distinct().Count() != handoff.Clients.Count ||
            !handoff.Clients.Select(static item => item.Kind).ToHashSet().SetEquals(required))
            throw new InvalidDataException("The Public Alpha activation handoff client set is incomplete.");
        var artifacts = handoff.Artifacts.ToDictionary(static item => item.Kind);
        foreach (var client in handoff.Clients)
            if (!Required(client.Version) || !Digest(client.ArtifactDigest) ||
                !string.Equals(client.ArtifactDigest, artifacts[ArtifactKind(client.Kind)].Digest, StringComparison.Ordinal) ||
                !string.Equals(client.CandidateDigest, handoff.CandidateDigest, StringComparison.Ordinal) ||
                !string.Equals(client.JourneySpecificationDigest, handoff.JourneySpecificationDigest, StringComparison.Ordinal) ||
                !Fresh(client.ObservedAt, handoff, decisionTime, allowedAge) ||
                !client.Passed || !Digest(client.EvidenceDigest))
                throw new InvalidDataException("The Public Alpha activation handoff contains failed client evidence.");
    }

    private static void ValidateGates(DeployHandoff handoff, DateTimeOffset decisionTime, TimeSpan allowedAge)
    {
        var expected = Enum.GetValues<DeployRegion>().Length * Enum.GetValues<DeployGateKind>().Length;
        if (handoff.Gates is null || handoff.Gates.Count != expected ||
            handoff.Gates.Select(static item => (item.Region, item.Kind)).Distinct().Count() != handoff.Gates.Count)
            throw new InvalidDataException("The Public Alpha activation handoff gate set is incomplete.");
        foreach (var region in Enum.GetValues<DeployRegion>())
            foreach (var kind in Enum.GetValues<DeployGateKind>())
            {
                var evidence = handoff.Gates.SingleOrDefault(item => item.Region == region && item.Kind == kind);
                if (evidence is null || !string.Equals(evidence.CandidateDigest, handoff.CandidateDigest, StringComparison.Ordinal) ||
                    !Fresh(evidence.ObservedAt, handoff, decisionTime, allowedAge) ||
                    !evidence.Passed || !Digest(evidence.EvidenceDigest))
                    throw new InvalidDataException("The Public Alpha activation handoff contains failed gate evidence.");
            }
    }

    private static void ValidatePublicEndpoints(
        DeployHandoff handoff,
        DateTimeOffset decisionTime,
        TimeSpan allowedAge)
    {
        var required = Enum.GetValues<DeployPublicEndpointKind>();
        if (handoff.PublicEndpoints is null || handoff.PublicEndpoints.Count != required.Length ||
            handoff.PublicEndpoints.Select(static item => item.Kind).Distinct().Count() != handoff.PublicEndpoints.Count ||
            !handoff.PublicEndpoints.Select(static item => item.Kind).ToHashSet().SetEquals(required))
            throw new InvalidDataException("The Public Alpha activation handoff endpoint evidence is incomplete.");

        foreach (var endpoint in handoff.PublicEndpoints)
        {
            var requested = PublicEndpointRequestUri(endpoint.Kind);
            var expectedFinal = PublicEndpointFinalUri(endpoint.Kind);
            if (!Uri.TryCreate(endpoint.RequestedUri, UriKind.Absolute, out var actualRequested) ||
                !Uri.TryCreate(endpoint.FinalUri, UriKind.Absolute, out var actualFinal) ||
                !string.Equals(actualRequested.AbsoluteUri, requested.AbsoluteUri, StringComparison.Ordinal) ||
                !string.Equals(actualFinal.AbsoluteUri, expectedFinal.AbsoluteUri, StringComparison.Ordinal) ||
                !endpoint.DnsResolved || endpoint.TimedOut || endpoint.HttpStatusCode is < 200 or >= 300 ||
                endpoint.TlsProtocol is not ("TLS1.2" or "TLS1.3") ||
                !Fresh(endpoint.ObservedAt, handoff, decisionTime, allowedAge) || !Digest(endpoint.EvidenceDigest))
                throw new InvalidDataException("The Public Alpha activation handoff contains an unqualified public endpoint.");

            if (endpoint.Kind == DeployPublicEndpointKind.LegacyDashboardRegistrationRedirect &&
                (!string.Equals(actualRequested.AbsolutePath, actualFinal.AbsolutePath, StringComparison.Ordinal) ||
                 !string.Equals(actualRequested.Query, actualFinal.Query, StringComparison.Ordinal)))
                throw new InvalidDataException("The Public Alpha legacy Dashboard redirect does not preserve path and query.");
        }
    }

    private static void ValidateRetention(DeployHandoff handoff)
    {
        if (handoff.RetentionProtectedTrees is null || handoff.RetentionProtectedTrees.Count != 2 ||
            !handoff.RetentionProtectedTrees.ToHashSet(StringComparer.Ordinal)
                .SetEquals([handoff.SourceTree, handoff.PreviousQualified.SourceTree]))
            throw new InvalidDataException("The Public Alpha activation handoff retention references are incomplete.");
        if (handoff.RetentionProtectedDigests is null || handoff.RetentionProtectedDigests.Count != 2 ||
            !handoff.RetentionProtectedDigests.ToHashSet(StringComparer.Ordinal)
                .SetEquals([handoff.CandidateDigest, handoff.PreviousQualified.CandidateDigest]))
            throw new InvalidDataException("The Public Alpha activation handoff digest retention is incomplete.");
    }

    private static string ComputeDigest(DeployHandoff handoff)
    {
        var canonical = JsonSerializer.SerializeToUtf8Bytes(handoff with { HandoffDigest = string.Empty }, JsonOptions);
        return $"sha256:{Convert.ToHexStringLower(SHA256.HashData(canonical))}";
    }

    internal static string ComputeDigest(string json)
    {
        var handoff = JsonSerializer.Deserialize<DeployHandoff>(json, JsonOptions)
            ?? throw new InvalidDataException("The Public Alpha activation handoff is empty.");
        return ComputeDigest(handoff);
    }

    private static bool Fresh(
        DateTimeOffset observedAt,
        DeployHandoff handoff,
        DateTimeOffset decisionTime,
        TimeSpan allowedAge) =>
        observedAt <= handoff.QualifiedAt && handoff.QualifiedAt - observedAt <= handoff.MaximumEvidenceAge &&
        observedAt <= decisionTime && decisionTime - observedAt <= allowedAge;

    private static PublicAlphaRegion Region(DeployRegion region) => region switch
    {
        DeployRegion.Gru => PublicAlphaRegion.Gru,
        DeployRegion.Sfo => PublicAlphaRegion.Sfo,
        DeployRegion.Fra => PublicAlphaRegion.Fra,
        _ => throw new InvalidDataException("The Public Alpha activation handoff contains an unknown region."),
    };

    private static PublicAlphaClientKind ClientKind(DeployClientKind kind) => kind switch
    {
        DeployClientKind.RawApi => PublicAlphaClientKind.RawApi,
        DeployClientKind.DotNetSdk => PublicAlphaClientKind.DotNetSdk,
        DeployClientKind.TypeScriptSdk => PublicAlphaClientKind.TypeScriptSdk,
        DeployClientKind.Mcp => PublicAlphaClientKind.Mcp,
        _ => throw new InvalidDataException("The Public Alpha activation handoff contains an unknown client."),
    };

    private static DeployArtifactKind ArtifactKind(DeployClientKind kind) => kind switch
    {
        DeployClientKind.RawApi => DeployArtifactKind.RawApiReference,
        DeployClientKind.DotNetSdk => DeployArtifactKind.DotNetSdk,
        DeployClientKind.TypeScriptSdk => DeployArtifactKind.TypeScriptSdk,
        DeployClientKind.Mcp => DeployArtifactKind.Mcp,
        _ => throw new InvalidDataException("The Public Alpha activation handoff contains an unknown client."),
    };

    private static bool Required(string? value) => value is { Length: <= 256 } && !string.IsNullOrWhiteSpace(value);
    private static bool Digest(string? value) => PublicAlphaDigest.IsValid(value);
    private static bool ObjectId(string? value) => value is { Length: 40 or 64 } &&
        value.All(static character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static Uri PublicEndpointRequestUri(DeployPublicEndpointKind kind) => new(kind switch
    {
        DeployPublicEndpointKind.Status => "https://status.terrascale.tech/",
        DeployPublicEndpointKind.Security => "https://docs.terrascale.tech/en/security/",
        DeployPublicEndpointKind.Terms => "https://docs.terrascale.tech/en/legal/terms/",
        DeployPublicEndpointKind.Privacy => "https://docs.terrascale.tech/en/legal/privacy/",
        DeployPublicEndpointKind.AcceptableUse => "https://docs.terrascale.tech/en/legal/acceptable-use/",
        DeployPublicEndpointKind.Support => "https://docs.terrascale.tech/en/support/",
        DeployPublicEndpointKind.SecurityContact => "https://docs.terrascale.tech/.well-known/security.txt",
        DeployPublicEndpointKind.Registration => "https://dash.terrascale.tech/register",
        DeployPublicEndpointKind.LegacyDashboardRegistrationRedirect =>
            "https://dashboard.terrascale.tech/register?probe=public-alpha",
        _ => throw new InvalidDataException("The Public Alpha activation handoff contains an unknown public endpoint."),
    });

    private static Uri PublicEndpointFinalUri(DeployPublicEndpointKind kind) =>
        kind == DeployPublicEndpointKind.LegacyDashboardRegistrationRedirect
            ? new("https://dash.terrascale.tech/register?probe=public-alpha")
            : PublicEndpointRequestUri(kind);

    private enum DeployRegion { Gru, Sfo, Fra }
    private enum DeployArtifactKind { Server, MigrationSet, DeploymentMetadata, RawApiReference, DotNetSdk, TypeScriptSdk, Mcp }
    private enum DeployClientKind { RawApi, DotNetSdk, TypeScriptSdk, Mcp }
    private enum DeployGateKind { TenantIsolation, Metering, Replication, Monitoring, RegistrationToDatabase }
    private enum DeployPublicEndpointKind
    {
        Status,
        Security,
        Terms,
        Privacy,
        AcceptableUse,
        Support,
        SecurityContact,
        Registration,
        LegacyDashboardRegistrationRedirect,
    }

    private sealed record DeployBuildEnvironment(
        string OperatingSystem,
        string SdkVersion,
        string RunnerImageDigest,
        string DependencyLockDigest);

    private sealed record DeployArtifact(DeployArtifactKind Kind, string Version, string Digest);
    private sealed record DeployRollbackTarget(
        string SourceTree,
        string CandidateDigest,
        string ConfigurationRevision,
        string MigrationSetDigest,
        string ExpectedArtifactDigest,
        string RetainedArtifactDigest,
        bool Retained,
        bool SchemaCompatible);

    private sealed record DeployRegionQualification(
        DeployRegion Region,
        string CandidateDigest,
        string GlobalHostName,
        string StrictRegionalHostName,
        DateTimeOffset ObservedAt,
        bool DownloadDigestMatched,
        bool StartupPassed,
        bool SchemaCompatible,
        string EvidenceDigest);

    private sealed record DeployClientQualification(
        DeployClientKind Kind,
        string Version,
        string ArtifactDigest,
        string CandidateDigest,
        string JourneySpecificationDigest,
        DateTimeOffset ObservedAt,
        bool Passed,
        string EvidenceDigest);

    private sealed record DeployGateQualification(
        DeployGateKind Kind,
        DeployRegion Region,
        string CandidateDigest,
        DateTimeOffset ObservedAt,
        bool Passed,
        string EvidenceDigest);

    private sealed record DeployPublicEndpointQualification(
        DeployPublicEndpointKind Kind,
        string RequestedUri,
        string FinalUri,
        DateTimeOffset ObservedAt,
        bool DnsResolved,
        bool TimedOut,
        int HttpStatusCode,
        string TlsProtocol,
        string EvidenceDigest);

    private sealed record DeployHandoff(
        string Schema,
        string ReleaseId,
        string SourceRevision,
        string SourceTree,
        string ConfigurationRevision,
        string CandidateDigest,
        string MigrationSetDigest,
        string JourneySpecificationDigest,
        DateTimeOffset BuiltAt,
        DateTimeOffset QualifiedAt,
        TimeSpan MaximumEvidenceAge,
        DeployBuildEnvironment BuildEnvironment,
        IReadOnlyList<DeployArtifact> Artifacts,
        DeployRollbackTarget PreviousQualified,
        IReadOnlyList<DeployRegionQualification> Regions,
        IReadOnlyList<DeployClientQualification> Clients,
        IReadOnlyList<DeployGateQualification> Gates,
        IReadOnlyList<DeployPublicEndpointQualification> PublicEndpoints,
        IReadOnlyList<string> RetentionProtectedTrees,
        IReadOnlyList<string> RetentionProtectedDigests,
        string HandoffDigest);
}
