using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoCiTriggerPlannerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");

    [Test]
    public async Task FeaturePullRequestsAreAlwaysUntrustedValidationWork()
    {
        var plan = ForgejoCiTriggerPlanner.Plan(PullRequest(
            "feature/native-ci",
            "develop",
            "contributor/TerraScale.Orchestrator"));
        var job = plan.CreateJobRequest(Resolved(signatureVerified: false), 7, 10, 100);

        await Assert.That(plan.Reason).IsEqualTo(ForgejoCiTriggerReason.FeatureValidation);
        await Assert.That(plan.JobKind).IsEqualTo(JobKind.ProductValidation);
        await Assert.That(plan.TrustZone).IsEqualTo(TrustZone.UntrustedProduct);
        await Assert.That(plan.Capabilities).IsEquivalentTo([RunnerCapability.Compile, RunnerCapability.Test]);
        await Assert.That(plan.MayPublishArtifacts).IsFalse();
        await Assert.That(DeliveryEngine.DecideJob(job,
            [new(new("untrusted-1"), TrustZone.UntrustedProduct, 20, true,
                [RunnerCapability.Compile, RunnerCapability.Test])], 96).Errors).IsEmpty();
        await Assert.That(DeliveryEngine.DecideJob(job,
            [new(new("release-1"), TrustZone.ProductionRelease, 20, true,
                [RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.ProductionDeploy])], 96)
            .Errors.Single().Code).IsEqualTo(DeliveryErrorCode.TrustZoneDenied);
    }

    [Test]
    public async Task DevelopToMainCreatesSignedCandidateWithoutProductionDeployAuthority()
    {
        var plan = ForgejoCiTriggerPlanner.Plan(PullRequest("develop", "main", Repository));
        var job = plan.CreateJobRequest(Resolved(), 8, 10, 100);

        await Assert.That(plan.Reason).IsEqualTo(ForgejoCiTriggerReason.TrustedArtifactBuild);
        await Assert.That(plan.JobKind).IsEqualTo(JobKind.TrustedBuild);
        await Assert.That(plan.TrustZone).IsEqualTo(TrustZone.TrustedBuild);
        await Assert.That(plan.Capabilities).IsEquivalentTo([
            RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]);
        await Assert.That(plan.Capabilities).DoesNotContain(RunnerCapability.ProductionDeploy);
        await Assert.That(plan.MayPublishArtifacts).IsTrue();
        await Assert.That(job.RetryAuthorized).IsFalse();
        await Assert.That(() => plan.CreateJobRequest(Resolved(signatureVerified: false), 8, 10, 100))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ForkOrArbitraryBranchCannotCreateMainCandidate()
    {
        var fork = ForgejoCiTriggerPlanner.Plan(PullRequest(
            "develop",
            "main",
            "contributor/TerraScale.Orchestrator"));
        var branch = ForgejoCiTriggerPlanner.Plan(PullRequest("release-lookalike", "main", Repository));

        await Assert.That(fork.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(branch.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(() => fork.CreateJobRequest(Resolved(), 1, 1, 2)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task MainPushIsHeldForNativeDelivery()
    {
        var plan = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/main"));

        await Assert.That(plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(plan.JobKind).IsEqualTo(JobKind.Unspecified);
        await Assert.That(plan.TrustZone).IsEqualTo(TrustZone.Unspecified);
        await Assert.That(plan.Capabilities).IsEmpty();
        await Assert.That(plan.MayPublishArtifacts).IsFalse();
        await Assert.That(() => plan.CreateJobRequest(Resolved(), 9, 10, 100))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DevelopPushValidatesWithoutSigningOrProductionCredentials()
    {
        var plan = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/develop"));

        await Assert.That(plan.Reason).IsEqualTo(ForgejoCiTriggerReason.DevelopValidation);
        await Assert.That(plan.JobKind).IsEqualTo(JobKind.ProductValidation);
        await Assert.That(plan.Capabilities).IsEquivalentTo([RunnerCapability.Compile, RunnerCapability.Test]);
        await Assert.That(plan.Capabilities).DoesNotContain(RunnerCapability.Sign);
    }

    [Test]
    public async Task MetadataUnsupportedRefsAndProtectedDeletionDoNotDispatch()
    {
        var metadata = ForgejoCiTriggerPlanner.Plan(PullRequest("feature", "develop", Repository, "edited"));
        var tag = ForgejoCiTriggerPlanner.Plan(Push("refs/tags/v1.0.0"));
        var deletion = ForgejoCiTriggerPlanner.Plan(Push(
            "refs/heads/main",
            revision: new string('0', 40)));

        await Assert.That(metadata.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Ignored);
        await Assert.That(tag.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Ignored);
        await Assert.That(deletion.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(deletion.Reason).IsEqualTo(ForgejoCiTriggerReason.ProtectedReferenceDeleted);
    }

    [Test]
    public async Task JobIdentityIsSignedPayloadStableAndRequiresExactResolvedGitObjects()
    {
        var payload = PushPayload("refs/heads/develop", Commit);
        var first = ForgejoCiTriggerPlanner.Plan(Verify(payload, "f6266f16-1bf3-46a5-9ea4-602e06ead473"));
        var second = ForgejoCiTriggerPlanner.Plan(Verify(payload, "7c42695c-8540-4476-9ee3-6c2725647656"));
        var firstJob = first.CreateJobRequest(Resolved(), 11, 10, 100);
        var secondJob = second.CreateJobRequest(new(
            Repository,
            Commit.ToUpperInvariant(),
            Tree.ToUpperInvariant(),
            true), 11, 10, 100);

        await Assert.That(firstJob.Idempotency).IsEqualTo(secondJob.Idempotency);
        await Assert.That(firstJob.Job).IsEqualTo(secondJob.Job);
        await Assert.That(firstJob.Tree.Value).IsEqualTo(Tree);
        await Assert.That(() => first.CreateJobRequest(Resolved(commit: new string('a', 40)), 11, 10, 100))
            .Throws<ArgumentException>();
        await Assert.That(() => first.CreateJobRequest(Resolved(tree: "tree-name"), 11, 10, 100))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task ClosedForgejoMatrixNeverWidensTrustOrCapabilities()
    {
        var actions = new[]
        {
            "opened", "closed", "reopened", "edited", "assigned", "unassigned", "label_updated",
            "label_cleared", "synchronized", "milestoned", "demilestoned", "reviewed",
            "review_requested", "review_request_removed",
        };
        foreach (var action in actions)
        foreach (var sourceRef in new[] { "feature", "develop" })
        foreach (var targetRef in new[] { "develop", "main", "other" })
        foreach (var sourceRepository in new[] { Repository, "contributor/TerraScale.Orchestrator" })
        {
            var plan = ForgejoCiTriggerPlanner.Plan(PullRequest(
                sourceRef,
                targetRef,
                sourceRepository,
                action));
            var triggers = action is "opened" or "reopened" or "synchronized";
            var expected = !triggers
                ? ForgejoCiTriggerDisposition.Ignored
                : targetRef == "develop"
                    ? ForgejoCiTriggerDisposition.Dispatch
                    : targetRef == "main" && sourceRef == "develop" && sourceRepository == Repository
                        ? ForgejoCiTriggerDisposition.Dispatch
                        : targetRef == "main"
                            ? ForgejoCiTriggerDisposition.Held
                            : ForgejoCiTriggerDisposition.Ignored;
            await Assert.That(plan.Disposition).IsEqualTo(expected);
            AssertClosedAuthority(plan);
        }

        foreach (var reference in new[] { "refs/heads/develop", "refs/heads/main", "refs/heads/feature", "refs/tags/v1" })
        foreach (var deleted in new[] { false, true })
        {
            var plan = ForgejoCiTriggerPlanner.Plan(Push(
                reference,
                deleted ? new string('0', 40) : Commit));
            AssertClosedAuthority(plan);
            if (deleted && reference is "refs/heads/develop" or "refs/heads/main")
                await Assert.That(plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        }
    }

    private static void AssertClosedAuthority(ForgejoCiTriggerPlan plan)
    {
        switch (plan.JobKind)
        {
            case JobKind.Unspecified:
                if (plan.Capabilities.Count != 0 || plan.TrustZone != TrustZone.Unspecified)
                    throw new InvalidOperationException("Non-dispatch trigger retained authority.");
                break;
            case JobKind.ProductValidation:
                if (plan.TrustZone != TrustZone.UntrustedProduct ||
                    !plan.Capabilities.SequenceEqual([RunnerCapability.Compile, RunnerCapability.Test]))
                    throw new InvalidOperationException("Product validation authority widened.");
                break;
            case JobKind.TrustedBuild:
                if (plan.TrustZone != TrustZone.TrustedBuild ||
                    !plan.Capabilities.SequenceEqual([
                        RunnerCapability.Compile, RunnerCapability.Test, RunnerCapability.Sign]))
                    throw new InvalidOperationException("Trusted build authority widened.");
                break;
            default:
                throw new InvalidOperationException("Unexpected Forgejo CI job kind.");
        }
    }

    private static ForgejoWebhookEnvelope Push(string reference, string revision = Commit) =>
        Verify(PushPayload(reference, revision), Guid.NewGuid().ToString("D"));

    private static ForgejoResolvedRevision Resolved(
        string repository = Repository,
        string commit = Commit,
        string tree = Tree,
        bool signatureVerified = true) => new(repository, commit, tree, signatureVerified);

    private static byte[] PushPayload(string reference, string revision) => Encoding.UTF8.GetBytes($$$"""
        {"ref":"{{{reference}}}","before":"affe000000000000000000000000000000000001","after":"{{{revision}}}","repository":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
        """);

    private static ForgejoWebhookEnvelope PullRequest(
        string sourceRef,
        string targetRef,
        string sourceRepository,
        string action = "synchronized")
    {
        var payload = Encoding.UTF8.GetBytes($$$"""
            {
              "action":"{{{action}}}",
              "number":42,
              "repository":{"full_name":"TerraScale/TerraScale.Orchestrator"},
              "pull_request":{
                "head":{"ref":"{{{sourceRef}}}","sha":"{{{Commit}}}","repo":{"full_name":"{{{sourceRepository}}}"}},
                "base":{"ref":"{{{targetRef}}}","sha":"affe000000000000000000000000000000000001","repo":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
              }
            }
            """);
        return Verify(payload, Guid.NewGuid().ToString("D"), "pull_request");
    }

    private static ForgejoWebhookEnvelope Verify(byte[] payload, string delivery, string eventName = "push") =>
        ForgejoWebhookVerifier.Verify(
            payload,
            Secret,
            Repository,
            "application/json",
            Convert.ToHexStringLower(HMACSHA256.HashData(Secret, payload)),
            delivery,
            eventName).Envelope!;
}
