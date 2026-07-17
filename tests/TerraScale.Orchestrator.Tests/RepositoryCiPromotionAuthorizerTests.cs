using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPromotionAuthorizerTests
{
    [Test]
    public async Task VerifiedAggregateEvidenceCreatesOnlyProductionPromotionWork()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var authorization = RepositoryCiPromotionAuthorizer.Authorize(
            qualified,
            Evidence(qualified),
            9,
            10,
            100);

        await Assert.That(authorization.Id).IsEqualTo($"promotion-{authorization.Digest}");
        await Assert.That(authorization.Job.Kind).IsEqualTo(JobKind.Promotion);
        await Assert.That(authorization.Job.Tree.Value).IsEqualTo(qualified.Sources[0].Tree);
        await Assert.That(authorization.Job.AllowedZones).IsEquivalentTo([TrustZone.ProductionRelease]);
        await Assert.That(authorization.Job.RequiredCapabilities)
            .IsEquivalentTo([RunnerCapability.Promote, RunnerCapability.ProductionDeploy]);
        await Assert.That(authorization.Job.RequiredCapabilities).DoesNotContain(RunnerCapability.Compile);
        await Assert.That(authorization.Job.RequiredCapabilities).DoesNotContain(RunnerCapability.Sign);
        var decision = DeliveryEngine.DecideJob(
            authorization.Job,
            [new(new("production-runner"), TrustZone.ProductionRelease, 20, true,
                [RunnerCapability.Promote, RunnerCapability.ProductionDeploy])],
            256);
        await Assert.That(decision.Errors).IsEmpty();
    }

    [Test]
    public async Task CandidateAndQualifiedDigestsMustMatchTheEvidenceSubject()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var evidence = Evidence(qualified);
        var cases = new[]
        {
            evidence with { QualifiedDigest = Digest(90) },
            evidence with { CandidateDigest = Digest(91) },
            evidence with { TestsDigest = "not-a-digest" },
        };

        foreach (var value in cases)
            await Assert.That(() => RepositoryCiPromotionAuthorizer.Authorize(
                    qualified, value, 9, 10, 100))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task EveryVerificationAndCompatibilityGateIsMandatory()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var evidence = Evidence(qualified);
        var cases = new[]
        {
            evidence with { TestsVerified = false },
            evidence with { EvidenceVerified = false },
            evidence with { SignatureVerified = false },
            evidence with { ApprovalVerified = false },
            evidence with { Compatibility = evidence.Compatibility with { CurrentToCurrentCompatible = false } },
            evidence with { Compatibility = evidence.Compatibility with { CurrentToPreviousCompatible = false } },
            evidence with { Compatibility = evidence.Compatibility with { PreviousToCurrentCompatible = false } },
        };

        foreach (var value in cases)
            await Assert.That(() => RepositoryCiPromotionAuthorizer.Authorize(
                    qualified, value, 9, 10, 100))
                .Throws<InvalidDataException>();
    }

    [Test]
    public async Task EvidenceAndRunnerWindowChangesProduceDistinctIdempotency()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var evidence = Evidence(qualified);
        var first = RepositoryCiPromotionAuthorizer.Authorize(qualified, evidence, 9, 10, 100);
        var evidenceChanged = RepositoryCiPromotionAuthorizer.Authorize(
            qualified,
            evidence with { Approval = new("approval-2") },
            9,
            10,
            100);
        var windowChanged = RepositoryCiPromotionAuthorizer.Authorize(qualified, evidence, 9, 10, 101);

        await Assert.That(evidenceChanged.Job.Idempotency).IsNotEqualTo(first.Job.Idempotency);
        await Assert.That(windowChanged.Job.Idempotency).IsNotEqualTo(first.Job.Idempotency);
    }

    [Test]
    public async Task TrustedBuildRunnerCannotReceivePromotionWork()
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var authorization = RepositoryCiPromotionAuthorizer.Authorize(
            qualified,
            Evidence(qualified),
            9,
            10,
            100);

        var decision = DeliveryEngine.DecideJob(
            authorization.Job,
            [new(new("trusted-runner"), TrustZone.TrustedBuild, 20, true,
                [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign])],
            256);

        await Assert.That(decision.Errors.Single().Code).IsEqualTo(DeliveryErrorCode.TrustZoneDenied);
    }

    private static RepositoryCiDeploymentEvidence Evidence(RepositoryCiQualifiedCandidate qualified) => new(
        qualified.Digest,
        qualified.Candidate.Digest,
        Digest(1),
        Digest(2),
        Digest(3),
        Digest(4),
        Digest(5),
        new("deployment-evidence-signer"),
        new("deployment-evidence-signature"),
        new("operator-approval"),
        new(
            new(Digest(6)),
            new(Digest(7)),
            new(Digest(8)),
            true,
            true,
            true),
        true,
        true,
        true,
        true);

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);
}
