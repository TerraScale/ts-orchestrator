using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class PublicAlphaRegionQualificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 19, 18, 0, 0, TimeSpan.Zero);
    private static readonly string Candidate = Digest("candidate");

    [Test]
    public async Task ExactExternalEndpointsAndRegionalTestsAuthorizeQualification()
    {
        var decision = PublicAlphaRegionQualificationGate.Decide(Request());

        await Assert.That(decision.Authorized).IsTrue();
        await Assert.That(decision.CandidateDigest).IsEqualTo(Candidate);
        await Assert.That(decision.EvidenceDigests.Count).IsEqualTo(
            4 + PublicAlphaRegionCatalog.LaunchRegions.Count * PublicAlphaRegionQualificationGate.RequiredTests.Count);
    }

    [Test]
    public async Task DnsHttpTlsCertificateHealthIdentityAndFreshnessFailClosed()
    {
        var cases = new[]
        {
            Probes().Select((item, index) => index == 0 ? item with { DnsResolved = false } : item).ToArray(),
            Probes().Select((item, index) => index == 0 ? item with { TimedOut = true } : item).ToArray(),
            Probes().Select((item, index) => index == 0 ? item with { HttpStatusCode = 503 } : item).ToArray(),
            Probes().Select((item, index) => index == 0 ? item with { TlsProtocol = "TLS1.1" } : item).ToArray(),
            Probes().Select((item, index) => index == 0 ? item with { CertificateHostnameValid = false } : item).ToArray(),
            Probes().Select((item, index) => index == 0 ? item with { Health = PublicAlphaRegionHealth.Unknown } : item).ToArray(),
            Probes().Select((item, index) => index == 1 ? item with { ObservedRegion = PublicAlphaRegion.Fra } : item).ToArray(),
            Probes().Select((item, index) => index == 1 ? item with { ObservedAt = Now - TimeSpan.FromHours(2) } : item).ToArray(),
        };

        foreach (var probes in cases)
        {
            var decision = PublicAlphaRegionQualificationGate.Decide(Request(probes: probes));
            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Errors).IsNotEmpty();
        }
    }

    [Test]
    public async Task EveryRegionalTestIsRequiredForEveryLaunchRegionAndCandidate()
    {
        foreach (var kind in PublicAlphaRegionQualificationGate.RequiredTests)
        {
            var failed = Tests().Select(item => item.Region == PublicAlphaRegion.Sfo && item.Kind == kind
                ? item with { Status = PublicAlphaGateStatus.Failed }
                : item).ToArray();
            var decision = PublicAlphaRegionQualificationGate.Decide(Request(tests: failed));

            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Errors.Any(error =>
                error.Code == PublicAlphaRegionQualificationErrorCode.TestFailed && error.Test == kind)).IsTrue();
        }

        var mismatch = Tests().Select((item, index) => index == 0
            ? item with { CandidateDigest = Digest("other") }
            : item).ToArray();
        await Assert.That(PublicAlphaRegionQualificationGate.Decide(Request(tests: mismatch)).Authorized).IsFalse();

    }

    [Test]
    public async Task NullEvidenceAndTimelessDecisionsFailClosed()
    {
        var probes = Probes().Select((item, index) => index == 0 ? null! : item).ToArray();
        var tests = Tests().Select((item, index) => index == 0 ? null! : item).ToArray();
        var cases = new[]
        {
            Request(probes: probes),
            Request(tests: tests),
            Request(decisionTime: default(DateTimeOffset)),
        };

        foreach (var request in cases)
        {
            var decision = PublicAlphaRegionQualificationGate.Decide(request);
            await Assert.That(decision.Authorized).IsFalse();
            await Assert.That(decision.Errors).IsNotEmpty();
        }
    }

    [Test]
    public async Task RoutingPolicyKeepsUnselectedRegionsOutOfGlobalAndStrictTraffic()
    {
        var global = PublicAlphaRoutingPolicy.Decide(new(
            PublicAlphaEndpoint.Global,
            null,
            [PublicAlphaRegion.Gru],
            [PublicAlphaRegion.Fra, PublicAlphaRegion.Gru],
            [
                new(PublicAlphaRegion.Fra, PublicAlphaRegionHealth.Healthy),
                new(PublicAlphaRegion.Gru, PublicAlphaRegionHealth.Healthy),
            ]));
        var strictRegional = PublicAlphaRoutingPolicy.Decide(new(
            PublicAlphaEndpoint.StrictRegional,
            PublicAlphaRegion.Fra,
            [PublicAlphaRegion.Gru],
            [PublicAlphaRegion.Fra],
            [new(PublicAlphaRegion.Fra, PublicAlphaRegionHealth.Healthy)]));

        await Assert.That(global.Region).IsEqualTo(PublicAlphaRegion.Gru);
        await Assert.That(strictRegional.Error).IsEqualTo(PublicAlphaRoutingError.RegionNotSelected);
    }

    internal static PublicAlphaRegionQualificationDecision Decision(
        string? candidate = null,
        DateTimeOffset? decisionTime = null,
        DateTimeOffset? observedAt = null) =>
        PublicAlphaRegionQualificationGate.Decide(Request(
            candidate ?? Candidate,
            decisionTime,
            probes: Probes(candidate ?? Candidate, observedAt),
            tests: Tests(candidate ?? Candidate, observedAt)));

    private static PublicAlphaRegionQualificationRequest Request(
        string? candidate = null,
        DateTimeOffset? decisionTime = null,
        IReadOnlyList<PublicAlphaExternalEndpointProbe>? probes = null,
        IReadOnlyList<PublicAlphaRegionalTestEvidence>? tests = null) => new(
        candidate ?? Candidate,
        decisionTime ?? Now,
        TimeSpan.FromMinutes(30),
        probes ?? Probes(candidate ?? Candidate),
        tests ?? Tests(candidate ?? Candidate));

    private static PublicAlphaExternalEndpointProbe[] Probes(
        string? candidate = null,
        DateTimeOffset? observedAt = null) =>
    [
        Probe(PublicAlphaEndpoint.Global, null, PublicAlphaRegion.Gru, candidate ?? Candidate, observedAt),
        .. PublicAlphaRegionCatalog.LaunchRegions.Select(region =>
            Probe(PublicAlphaEndpoint.StrictRegional, region, region, candidate ?? Candidate, observedAt)),
    ];

    private static PublicAlphaExternalEndpointProbe Probe(
        PublicAlphaEndpoint endpoint,
        PublicAlphaRegion? requestedRegion,
        PublicAlphaRegion observedRegion,
        string candidate,
        DateTimeOffset? observedAt = null) => new(
        endpoint,
        requestedRegion,
        endpoint == PublicAlphaEndpoint.Global
            ? $"https://{PublicAlphaRegionCatalog.GlobalHostName}/"
            : $"https://{PublicAlphaRegionCatalog.RegionalHostName(requestedRegion!.Value)}/",
        observedRegion,
        candidate,
        observedAt ?? Now - TimeSpan.FromMinutes(2),
        true,
        false,
        200,
        "TLS1.3",
        true,
        Now - TimeSpan.FromDays(30),
        Now + TimeSpan.FromDays(30),
        PublicAlphaRegionHealth.Healthy,
        Digest($"probe-{endpoint}-{requestedRegion}"));

    private static PublicAlphaRegionalTestEvidence[] Tests(
        string? candidate = null,
        DateTimeOffset? observedAt = null) =>
        PublicAlphaRegionCatalog.LaunchRegions.SelectMany(region =>
            PublicAlphaRegionQualificationGate.RequiredTests.Select(kind => new PublicAlphaRegionalTestEvidence(
                region,
                kind,
                candidate ?? Candidate,
                observedAt ?? Now - TimeSpan.FromMinutes(2),
                PublicAlphaGateStatus.Passed,
                Digest($"test-{region}-{kind}")))).ToArray();

    private static string Digest(string value) => $"sha256:{Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(value)))}";
}
