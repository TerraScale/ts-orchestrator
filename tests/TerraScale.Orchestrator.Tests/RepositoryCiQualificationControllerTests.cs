using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiQualificationControllerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string MainCommit = "cffe000000000000000000000000000000000003";

    [Test]
    public async Task ExactQualificationPublishesSuccessBeforeAcknowledgement()
    {
        var trigger = QualificationTrigger();
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        var coordinated = new List<string>();
        var statuses = new List<string>();
        var controller = new RepositoryCiQualificationController(
            (key, epoch, sequence, stillValid, _) =>
            {
                coordinated.Add($"{key}:{epoch}:{sequence}:{stillValid()}");
                return Task.FromResult(new RepositoryCiQualificationCoordinationReceipt(
                    RepositoryCiQualificationCoordinationDisposition.Recorded,
                    qualified));
            },
            static () => Authority(7, 11),
            (commit, state, _) =>
            {
                statuses.Add($"{commit}:{state}");
                return Task.CompletedTask;
            });

        var handled = await controller.RunToCompletionAsync(trigger, CancellationToken.None);

        await Assert.That(handled).IsTrue();
        await Assert.That(coordinated).IsEquivalentTo(
            [$"{trigger.Envelope.DedupeKey}:7:11:True"]);
        await Assert.That(statuses).IsEquivalentTo([$"{MainCommit}:Success"]);
    }

    [Test]
    public async Task MissingCandidateKeepsDeliveryPendingWithoutStatus()
    {
        var statuses = 0;
        var controller = new RepositoryCiQualificationController(
            (_, _, _, _, _) => Task.FromResult(new RepositoryCiQualificationCoordinationReceipt(
                RepositoryCiQualificationCoordinationDisposition.CandidateMissing,
                null)),
            static () => Authority(7, 11),
            (_, _, _) =>
            {
                statuses++;
                return Task.CompletedTask;
            });

        var handled = await controller.RunToCompletionAsync(QualificationTrigger(), CancellationToken.None);

        await Assert.That(handled).IsFalse();
        await Assert.That(statuses).IsEqualTo(0);
    }

    [Test]
    public async Task FollowerNeverAttemptsQualification()
    {
        var calls = 0;
        var controller = new RepositoryCiQualificationController(
            (_, _, _, _, _) =>
            {
                calls++;
                throw new InvalidOperationException();
            },
            static () => Authority(7, 11, leader: false),
            (_, _, _) => Task.CompletedTask);

        var handled = await controller.RunToCompletionAsync(QualificationTrigger(), CancellationToken.None);

        await Assert.That(handled).IsFalse();
        await Assert.That(calls).IsEqualTo(0);
    }

    [Test]
    public async Task NonQualificationTriggerIsRejectedBeforeCoordination()
    {
        var calls = 0;
        var controller = new RepositoryCiQualificationController(
            (_, _, _, _, _) =>
            {
                calls++;
                throw new InvalidOperationException();
            },
            static () => Authority(7, 11),
            (_, _, _) => Task.CompletedTask);
        var develop = ForgejoCiTriggerPlanner.Plan(new(
            Guid.NewGuid(),
            ForgejoWebhookKind.Push,
            "push",
            Repository,
            Repository,
            new string('c', 40),
            new string('d', 40),
            "refs/heads/develop",
            null,
            null,
            false,
            new string('b', 64)));

        await Assert.That(async () => await controller.RunToCompletionAsync(
                develop,
                CancellationToken.None))
            .Throws<ArgumentException>();
        await Assert.That(calls).IsEqualTo(0);
    }

    [Test]
    public async Task DispatchIncludingQualificationRequiresConsumerProcessing()
    {
        var qualification = QualificationTrigger();
        var ignored = ForgejoCiTriggerPlanner.Plan(new(
            Guid.NewGuid(),
            ForgejoWebhookKind.Push,
            "push",
            Repository,
            Repository,
            new string('c', 40),
            new string('d', 40),
            "refs/heads/other",
            null,
            null,
            false,
            new string('b', 64)));

        await Assert.That(ForgejoCiEventConsumer.RequiresProcessing(qualification)).IsTrue();
        await Assert.That(ForgejoCiEventConsumer.RequiresProcessing(ignored)).IsFalse();
    }

    private static ForgejoCiTriggerPlan QualificationTrigger() => ForgejoCiTriggerPlanner.Plan(new(
        Guid.NewGuid(),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        new string('d', 40),
        MainCommit,
        "refs/heads/main",
        null,
        null,
        false,
        new string('a', 64)));

    private static RegionalAuthoritySnapshot Authority(
        long epoch,
        long revision,
        bool leader = true)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            leader ? "leader" : "follower",
            leader,
            epoch,
            revision,
            now.AddSeconds(10),
            now,
            null);
    }
}
