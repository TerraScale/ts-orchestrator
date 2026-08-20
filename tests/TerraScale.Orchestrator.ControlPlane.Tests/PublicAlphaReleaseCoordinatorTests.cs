using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class PublicAlphaReleaseCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 19, 18, 0, 0, TimeSpan.Zero);
    private static readonly string Candidate = Digest("candidate");
    private static readonly string PreviousCandidate = Digest("previous");
    private static readonly string FixtureCandidate = Digest("candidate-fixture");
    private static readonly string SourceRevision = ObjectId("source-revision");

    [Test]
    public async Task ExactThreeRegionEvidenceCrossesOneGlobalActivationBarrier()
    {
        var decision = PublicAlphaReleaseCoordinator.Decide(Request());

        var intent = (ActivatePublicAlphaReleaseIntent)decision.Intents.Single();
        await Assert.That(intent.CandidateDigest).IsEqualTo(Candidate);
        await Assert.That(intent.Regions).IsEquivalentTo(PublicAlphaRegionCatalog.LaunchRegions);
        await Assert.That(decision.Errors).IsEmpty();
        await Assert.That(decision.Receipt.ReleaseId).IsEqualTo("release-42");
        await Assert.That(decision.Receipt.EvidenceLinks).IsNotEmpty();
    }

    [Test]
    public async Task EveryRequiredCustomerGateFailsClosedBeforeActivation()
    {
        foreach (var kind in PublicAlphaReleaseCoordinator.RequiredCustomerGates)
        {
            var evidence = Gates(PublicAlphaGatePhase.PreActivation)
                .Select(item => item.Kind == kind && item.Region == PublicAlphaRegion.Gru
                    ? item with { Status = PublicAlphaGateStatus.Failed }
                    : item)
                .ToArray();

            var decision = PublicAlphaReleaseCoordinator.Decide(Request(gates: evidence));

            await Assert.That(decision.Intents).IsEmpty();
            await Assert.That(decision.Errors.Any(error =>
                error.Code == PublicAlphaReleaseErrorCode.RequiredEvidenceFailed && error.Gate == kind)).IsTrue();
        }
    }

    [Test]
    public async Task UnrecognizedOrDuplicateGateEvidenceFailsClosed()
    {
        var duplicate = Gates(PublicAlphaGatePhase.PreActivation)
            .Append(Gates(PublicAlphaGatePhase.PreActivation)[0])
            .ToArray();
        var unknown = Gates(PublicAlphaGatePhase.PreActivation)
            .Append(new(
                (PublicAlphaGateKind)999,
                PublicAlphaGatePhase.PreActivation,
                PublicAlphaRegion.Gru,
                Candidate,
                Now - TimeSpan.FromMinutes(2),
                PublicAlphaGateStatus.Passed,
                Digest("unknown-gate"),
                null))
            .ToArray();

        var undefinedRegion = Gates(PublicAlphaGatePhase.PreActivation)
            .Select((item, index) => index == 0 ? item with { Region = (PublicAlphaRegion)999 } : item)
            .ToArray();

        foreach (var gates in new[] { duplicate, unknown, undefinedRegion })
        {
            var decision = PublicAlphaReleaseCoordinator.Decide(Request(gates: gates));
            await Assert.That(decision.Intents).IsEmpty();
            await Assert.That(decision.Errors).IsNotEmpty();
        }
    }

    [Test]
    public async Task FailedPostActivationGateRollsEveryRegionBackToRetainedDigest()
    {
        foreach (var kind in PublicAlphaReleaseCoordinator.RequiredCustomerGates)
        {
            var gates = Gates(PublicAlphaGatePhase.PostActivation)
                .Select(item => item.Kind == kind && item.Region == PublicAlphaRegion.Sfo
                    ? item with { Status = PublicAlphaGateStatus.Failed }
                    : item)
                .ToArray();
            var decision = PublicAlphaReleaseCoordinator.Decide(Request(
                activationCommitted: true,
                regions: Regions(Candidate),
                gates: gates));

            var rollback = (RollbackPublicAlphaReleaseIntent)decision.Intents.Single();
            await Assert.That(rollback.RollbackDigest).IsEqualTo(PreviousCandidate);
            await Assert.That(rollback.Regions).IsEquivalentTo(PublicAlphaRegionCatalog.LaunchRegions);
            await Assert.That(rollback.RebuildAllowed).IsFalse();
        }
    }

    [Test]
    public async Task PartialActivationConvergesTowardTheCommittedGlobalVersion()
    {
        var beforeBarrier = PublicAlphaReleaseCoordinator.Decide(Request(
            regions: Regions(PreviousCandidate, Candidate, PreviousCandidate)));
        var beforeRepair = (ConvergePublicAlphaRegionIntent)beforeBarrier.Intents.Single();
        await Assert.That(beforeRepair.Region).IsEqualTo(PublicAlphaRegion.Sfo);
        await Assert.That(beforeRepair.Digest).IsEqualTo(PreviousCandidate);

        var afterBarrier = PublicAlphaReleaseCoordinator.Decide(Request(
            activationCommitted: true,
            regions: Regions(Candidate, PreviousCandidate, Candidate),
            gates: Gates(PublicAlphaGatePhase.PostActivation)));
        var afterRepair = (ConvergePublicAlphaRegionIntent)afterBarrier.Intents.Single();
        await Assert.That(afterRepair.Region).IsEqualTo(PublicAlphaRegion.Sfo);
        await Assert.That(afterRepair.Digest).IsEqualTo(Candidate);
    }

    [Test]
    public async Task FailedPostActivationGateRollsBackDuringPartialActivation()
    {
        var gates = Gates(PublicAlphaGatePhase.PostActivation)
            .Select(item => item.Kind == PublicAlphaGateKind.CustomerJourney && item.Region == PublicAlphaRegion.Fra
                ? item with { Status = PublicAlphaGateStatus.Failed }
                : item).ToArray();

        var decision = PublicAlphaReleaseCoordinator.Decide(Request(
            activationCommitted: true,
            regions: Regions(Candidate, PreviousCandidate, Candidate),
            gates: gates));

        var rollback = (RollbackPublicAlphaReleaseIntent)decision.Intents.Single();
        await Assert.That(rollback.RollbackDigest).IsEqualTo(PreviousCandidate);
    }

    [Test]
    public async Task DigestFieldsRequireACompleteSha256Value()
    {
        var decision = PublicAlphaReleaseCoordinator.Decide(Request() with
        {
            Release = Request().Release with { CandidateDigest = "sha256:not-a-digest" },
        });

        await Assert.That(decision.Intents).IsEmpty();
        await Assert.That(decision.Errors.Any(static error =>
            error.Code == PublicAlphaReleaseErrorCode.InvalidInput)).IsTrue();
    }

    [Test]
    public async Task MissingStaleOrMismatchedCrossClientEvidenceCannotAuthorizeActivation()
    {
        var cases = new PublicAlphaReleaseRequest[]
        {
            Request() with { CrossClientHandoff = null },
            Request(handoff: Handoff(observedAt: Now - TimeSpan.FromHours(2))),
            Request(handoff: Handoff(candidateDigest: Digest("other"))),
            Request(handoff: Handoff(digestVerified: false)),
            Request(handoff: Handoff(clients: Handoff().Clients.Take(Handoff().Clients.Count - 1).ToArray())),
        };

        foreach (var request in cases)
        {
            var decision = PublicAlphaReleaseCoordinator.Decide(request);
            await Assert.That(decision.Intents).IsEmpty();
            await Assert.That(decision.Errors).IsNotEmpty();
        }
    }

    [Test]
    public async Task VerifiedHandoffIdentityMustMatchTheReleaseItAuthorizes()
    {
        var mismatched = new[]
        {
            Handoff(releaseId: "release-other"),
            Handoff(sourceRevision: ObjectId("other-source")),
            Handoff(configurationRevision: "config-other"),
            Handoff(migrationSetDigest: Digest("other-migrations")),
            Handoff(previousQualifiedDigest: Digest("other-previous")),
        };

        foreach (var handoff in mismatched)
        {
            var decision = PublicAlphaReleaseCoordinator.Decide(Request(handoff: handoff));

            await Assert.That(decision.Intents).IsEmpty();
            await Assert.That(decision.Errors.Any(static error =>
                error.Code == PublicAlphaReleaseErrorCode.EvidenceDigestMismatch)).IsTrue();
        }
    }

    [Test]
    public async Task DeployHandoffDigestIsVerifiedBeforeTheActivationGateCanConsumeIt()
    {
        var path = Path.Combine(
            FindRepositoryRoot(),
            "tests",
            "TerraScale.Orchestrator.ControlPlane.Tests",
            "Fixtures",
            "public-alpha-handoff-v1.json");
        var json = await File.ReadAllTextAsync(path);
        var verified = PublicAlphaActivationHandoffVerifier.ParseAndVerify(
            json,
            new(2026, 8, 19, 18, 5, 0, TimeSpan.Zero),
            TimeSpan.FromMinutes(30));

        await Assert.That(verified.CandidateDigest).IsEqualTo(FixtureCandidate);
        await Assert.That(verified.DigestVerified).IsTrue();
        await Assert.That(verified.Clients.Select(static client => client.Kind))
            .IsEquivalentTo(PublicAlphaReleaseCoordinator.RequiredClients);

        var tampered = json.Replace(FixtureCandidate, Digest("other"), StringComparison.Ordinal);
        await Assert.That(() => PublicAlphaActivationHandoffVerifier.ParseAndVerify(
            tampered,
            new(2026, 8, 19, 18, 5, 0, TimeSpan.Zero),
            TimeSpan.FromMinutes(30))).Throws<InvalidDataException>();

        var extended = json.Replace("{", "{\"unrecognizedAuthority\":true,", StringComparison.Ordinal);
        await Assert.That(() => PublicAlphaActivationHandoffVerifier.ParseAndVerify(
            extended,
            new(2026, 8, 19, 18, 5, 0, TimeSpan.Zero),
            TimeSpan.FromMinutes(30))).Throws<InvalidDataException>();

        await Assert.That(() => PublicAlphaActivationHandoffVerifier.ParseAndVerify(
            json,
            new(2026, 8, 19, 18, 29, 0, TimeSpan.Zero),
            TimeSpan.FromMinutes(30))).Throws<InvalidDataException>();
    }

    [Test]
    public async Task DeployHandoffCanonicalEndpointsAreIndependentlyVerified()
    {
        var json = await File.ReadAllTextAsync(HandoffFixturePath());
        var decisionTime = new DateTimeOffset(2026, 8, 19, 18, 5, 0, TimeSpan.Zero);
        var normalized = WithVerifiedDigest(HandoffDocument(json));
        var accepted = PublicAlphaActivationHandoffVerifier.ParseAndVerify(
            normalized, decisionTime, TimeSpan.FromMinutes(30));
        await Assert.That(accepted.DigestVerified).IsTrue();

        var cases = new List<JsonObject>();
        var dnsFailure = HandoffDocument(json);
        Endpoint(dnsFailure, 0)["dnsResolved"] = false;
        cases.Add(dnsFailure);
        var timeout = HandoffDocument(json);
        Endpoint(timeout, 7)["timedOut"] = true;
        cases.Add(timeout);
        var notFound = HandoffDocument(json);
        Endpoint(notFound, 1)["httpStatusCode"] = 404;
        cases.Add(notFound);
        var obsoleteTls = HandoffDocument(json);
        Endpoint(obsoleteTls, 2)["tlsProtocol"] = "TLS1.1";
        cases.Add(obsoleteTls);
        var stale = HandoffDocument(json);
        Endpoint(stale, 3)["observedAt"] = "2026-08-19T16:00:00+00:00";
        cases.Add(stale);
        var wrongCanonicalUri = HandoffDocument(json);
        Endpoint(wrongCanonicalUri, 4)["requestedUri"] = "https://docs.terrascale.tech/en/legal/terms/";
        cases.Add(wrongCanonicalUri);
        var redirectDropsQuery = HandoffDocument(json);
        Endpoint(redirectDropsQuery, 8)["finalUri"] = "https://dash.terrascale.tech/register";
        cases.Add(redirectDropsQuery);

        foreach (var document in cases)
            await Assert.That(() => PublicAlphaActivationHandoffVerifier.ParseAndVerify(
                WithVerifiedDigest(document), decisionTime, TimeSpan.FromMinutes(30))).Throws<InvalidDataException>();
    }

    [Test]
    public async Task RoutingNeverUsesUnknownOrUnselectedRegions()
    {
        var global = PublicAlphaRoutingPolicy.Decide(new(
            PublicAlphaEndpoint.Global,
            null,
            [PublicAlphaRegion.Gru, PublicAlphaRegion.Sfo],
            [PublicAlphaRegion.Gru, PublicAlphaRegion.Fra, PublicAlphaRegion.Sfo],
            [
                new(PublicAlphaRegion.Gru, PublicAlphaRegionHealth.Unknown),
                new(PublicAlphaRegion.Fra, PublicAlphaRegionHealth.Healthy),
                new(PublicAlphaRegion.Sfo, PublicAlphaRegionHealth.Healthy),
            ]));
        await Assert.That(global.Region).IsEqualTo(PublicAlphaRegion.Sfo);

        var strict = PublicAlphaRoutingPolicy.Decide(new(
            PublicAlphaEndpoint.StrictRegional,
            PublicAlphaRegion.Fra,
            [PublicAlphaRegion.Gru, PublicAlphaRegion.Sfo],
            [PublicAlphaRegion.Fra],
            [new(PublicAlphaRegion.Fra, PublicAlphaRegionHealth.Healthy)]));
        await Assert.That(strict.Region).IsNull();
        await Assert.That(strict.Error).IsEqualTo(PublicAlphaRoutingError.RegionNotSelected);

        var invalidHealth = PublicAlphaRoutingPolicy.Decide(new(
            PublicAlphaEndpoint.Global,
            null,
            [PublicAlphaRegion.Gru],
            [PublicAlphaRegion.Gru],
            [new((PublicAlphaRegion)999, PublicAlphaRegionHealth.Healthy)]));
        await Assert.That(invalidHealth.Error).IsEqualTo(PublicAlphaRoutingError.InvalidRequest);
    }

    [Test]
    public async Task EveryProductionReadinessAreaIsRequiredAndDigestBound()
    {
        var complete = ReadinessEvidence();
        var accepted = PublicAlphaReadinessGate.Decide(new(
            Candidate, Now, TimeSpan.FromMinutes(30), complete));
        await Assert.That(accepted.Authorized).IsTrue();

        foreach (var kind in PublicAlphaReadinessGate.RequiredAreas)
        {
            var failed = complete.Select(item => item.Kind == kind
                ? item with { Status = PublicAlphaReadinessStatus.Failed }
                : item).ToArray();
            var decision = PublicAlphaReadinessGate.Decide(new(
                Candidate, Now, TimeSpan.FromMinutes(30), failed));
            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Errors.Any(error => error.Kind == kind)).IsTrue();
        }

        var unknown = complete.Append(new(
            (PublicAlphaReadinessKind)999,
            Candidate,
            Now - TimeSpan.FromMinutes(2),
            PublicAlphaReadinessStatus.Passed,
            Digest("unknown-readiness"))).ToArray();
        await Assert.That(PublicAlphaReadinessGate.Decide(new(
            Candidate, Now, TimeSpan.FromMinutes(30), unknown)).Authorized).IsFalse();
    }

    [Test]
    public async Task ExternalPublicAlphaObligationsAreFailClosedActivationGates()
    {
        var external = new[]
        {
            PublicAlphaReadinessKind.ProductionThreeRegionRehearsal,
            PublicAlphaReadinessKind.RegionalEndpointQualification,
            PublicAlphaReadinessKind.RegistrationEmailPaymentOnboardingAndDashboard,
            PublicAlphaReadinessKind.CustomerDatabaseApiJourneyAllRegions,
            PublicAlphaReadinessKind.PublicStatusPublished,
            PublicAlphaReadinessKind.SecurityDisclosurePublished,
            PublicAlphaReadinessKind.LegalPoliciesPublished,
            PublicAlphaReadinessKind.SupportTermsPublished,
            PublicAlphaReadinessKind.LaunchDocumentationPublished,
            PublicAlphaReadinessKind.TargetedRegionalManualQa,
            PublicAlphaReadinessKind.SevenDayProductionSoak,
            PublicAlphaReadinessKind.ReadinessAuditClear,
        };

        await Assert.That(external.All(kind => PublicAlphaReadinessGate.RequiredAreas.Contains(kind))).IsTrue();
    }

    [Test]
    public async Task FailedProductionReadinessCannotBeOverriddenByFinalApproval()
    {
        var failed = ReadinessEvidence().Select(item =>
            item.Kind == PublicAlphaReadinessKind.ProviderActuatorRecovery
                ? item with { Status = PublicAlphaReadinessStatus.Failed }
                : item).ToArray();
        var request = Request() with
        {
            Readiness = PublicAlphaReadinessGate.Decide(new(
                Candidate, Now, TimeSpan.FromMinutes(30), failed)),
        };

        var decision = PublicAlphaReleaseCoordinator.Decide(request);
        await Assert.That(decision.Intents).IsEmpty();
        await Assert.That(decision.Errors.Any(static error =>
            error.Code == PublicAlphaReleaseErrorCode.ReadinessDenied)).IsTrue();
    }

    [Test]
    public async Task FinalLaunchApprovalMustComeFromTheNamedOwner()
    {
        var request = Request() with
        {
            FinalApproval = new(
                "approval-1",
                "another-operator",
                Candidate,
                Now - TimeSpan.FromMinutes(1),
                true),
        };

        var decision = PublicAlphaReleaseCoordinator.Decide(request);

        await Assert.That(decision.Intents).IsEmpty();
        await Assert.That(decision.Errors.Any(static error =>
            error.Code == PublicAlphaReleaseErrorCode.ApprovalDenied)).IsTrue();
    }

    [Test]
    public async Task ReceiptContainsOnlyRedactedDigestBoundReferences()
    {
        var receipt = PublicAlphaReleaseCoordinator.Decide(Request()).Receipt;
        var text = string.Join('\n', receipt.EvidenceLinks.Select(link => $"{link.Kind}:{link.Digest}"));

        await Assert.That(receipt.CandidateDigest).IsEqualTo(Candidate);
        await Assert.That(receipt.PreviousQualifiedDigest).IsEqualTo(PreviousCandidate);
        await Assert.That(receipt.ConfigurationRevision).IsEqualTo("config-7");
        await Assert.That(receipt.MigrationSetDigest).IsEqualTo(Digest("migrations"));
        await Assert.That(text).DoesNotContain("secret");
        await Assert.That(text).DoesNotContain("query=");
    }

    private static PublicAlphaReleaseRequest Request(
        bool activationCommitted = false,
        IReadOnlyList<PublicAlphaRegionReleaseState>? regions = null,
        IReadOnlyList<PublicAlphaGateEvidence>? gates = null,
        PublicAlphaCrossClientHandoff? handoff = null) => new(
        new(
            "release-42",
            SourceRevision,
            Candidate,
            PreviousCandidate,
            "config-7",
            Digest("migrations"),
            Now - TimeSpan.FromMinutes(20)),
        Now,
        TimeSpan.FromMinutes(30),
        activationCommitted,
        regions ?? Regions(PreviousCandidate),
        gates ?? Gates(PublicAlphaGatePhase.PreActivation),
        handoff ?? Handoff(),
        PublicAlphaReadinessGate.Decide(new(
            Candidate, Now, TimeSpan.FromMinutes(30), ReadinessEvidence())),
        new("approval-1", "mariogk", Candidate, Now - TimeSpan.FromMinutes(1), true));

    private static PublicAlphaRegionReleaseState[] Regions(
        string gru,
        string? sfo = null,
        string? fra = null) =>
    [
        new(PublicAlphaRegion.Gru, Candidate, gru, false),
        new(PublicAlphaRegion.Sfo, Candidate, sfo ?? gru, false),
        new(PublicAlphaRegion.Fra, Candidate, fra ?? gru, false),
    ];

    private static PublicAlphaGateEvidence[] Gates(PublicAlphaGatePhase phase) =>
        PublicAlphaRegionCatalog.LaunchRegions.SelectMany(region =>
            PublicAlphaReleaseCoordinator.RequiredCustomerGates.Select(kind => new PublicAlphaGateEvidence(
                kind,
                phase,
                region,
                Candidate,
                Now - TimeSpan.FromMinutes(2),
                PublicAlphaGateStatus.Passed,
                Digest($"{phase}-{region}-{kind}"),
                kind is PublicAlphaGateKind.ErrorRate or PublicAlphaGateKind.ApiLatency
                    ? new($"terrascale.{kind}", kind == PublicAlphaGateKind.ApiLatency ? "milliseconds" : "ratio",
                        TimeSpan.FromMinutes(5), "prometheus-qualified", "baseline-2026-08")
                    : null))).ToArray();

    private static PublicAlphaCrossClientHandoff Handoff(
        string? candidateDigest = null,
        bool digestVerified = true,
        DateTimeOffset? observedAt = null,
        IReadOnlyList<PublicAlphaClientEvidence>? clients = null,
        string releaseId = "release-42",
        string? sourceRevision = null,
        string configurationRevision = "config-7",
        string? migrationSetDigest = null,
        string? previousQualifiedDigest = null) => new(
        releaseId,
        sourceRevision ?? SourceRevision,
        configurationRevision,
        migrationSetDigest ?? Digest("migrations"),
        previousQualifiedDigest ?? PreviousCandidate,
        candidateDigest ?? Candidate,
        Digest("handoff"),
        digestVerified,
        observedAt ?? Now - TimeSpan.FromMinutes(2),
        clients ?? PublicAlphaReleaseCoordinator.RequiredClients.Select(kind => new PublicAlphaClientEvidence(
            kind,
            "1.0.0-alpha.1",
            Digest(kind.ToString()),
            Candidate,
            Digest("journey-spec"),
            true)).ToArray());

    private static PublicAlphaReadinessEvidence[] ReadinessEvidence() =>
        PublicAlphaReadinessGate.RequiredAreas.Select(kind => new PublicAlphaReadinessEvidence(
            kind,
            Candidate,
            Now - TimeSpan.FromMinutes(2),
            PublicAlphaReadinessStatus.Passed,
            Digest($"readiness-{kind}"))).ToArray();

    private static string Digest(string value) => $"sha256:{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)))}";

    private static string ObjectId(string value) => Digest(value)[7..];

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "TerraScale.Orchestrator.slnx")))
                return directory.FullName;
        throw new InvalidOperationException("TerraScale.Orchestrator repository root is unavailable.");
    }

    private static string HandoffFixturePath() => Path.Combine(
        FindRepositoryRoot(),
        "tests",
        "TerraScale.Orchestrator.ControlPlane.Tests",
        "Fixtures",
        "public-alpha-handoff-v1.json");

    private static JsonObject HandoffDocument(string json) =>
        JsonNode.Parse(json)?.AsObject() ?? throw new InvalidDataException("The handoff fixture is invalid.");

    private static JsonObject Endpoint(JsonObject handoff, int index) =>
        handoff["publicEndpoints"]?.AsArray()[index]?.AsObject() ??
        throw new InvalidDataException("The handoff fixture endpoint is missing.");

    private static string WithVerifiedDigest(JsonObject handoff)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true,
        };
        handoff["handoffDigest"] = string.Empty;
        var json = JsonSerializer.Serialize(handoff, options);
        handoff["handoffDigest"] = PublicAlphaActivationHandoffVerifier.ComputeDigest(json);
        return JsonSerializer.Serialize(handoff, options);
    }
}
