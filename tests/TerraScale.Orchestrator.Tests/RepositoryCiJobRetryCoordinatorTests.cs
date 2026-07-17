using System.Globalization;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobRetryCoordinatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task AuthorizedTransientFailureWaitsAndOpensOneFencedAttempt()
    {
        var fixture = await Fixture.CreateAsync(RepositoryCiJobFailureKind.RunnerLost);

        var scheduled = await fixture.CoordinateAsync();
        var waiting = await fixture.CoordinateAsync();
        fixture.Clock.Advance(TimeSpan.FromSeconds(5));
        var opened = await fixture.CoordinateAsync();
        var duplicate = await fixture.CoordinateAsync();

        await Assert.That(scheduled.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.Scheduled);
        await Assert.That(scheduled.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.RetryWaiting);
        await Assert.That(waiting.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.Waiting);
        await Assert.That(opened.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.Opened);
        await Assert.That(opened.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Pending);
        await Assert.That(opened.Job.Attempt).IsEqualTo(2);
        await Assert.That(opened.Job.Job.Request.RetryAuthorized).IsTrue();
        await Assert.That(duplicate.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.Duplicate);
        await Assert.That(fixture.AuthorizationReads).IsEqualTo(1);
    }

    [Test]
    public async Task PermanentFailureNeverRequestsRetryAuthorization()
    {
        var fixture = await Fixture.CreateAsync(RepositoryCiJobFailureKind.WorkloadFailed);

        var receipt = await fixture.CoordinateAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.NotRetryable);
        await Assert.That(fixture.AuthorizationReads).IsEqualTo(0);
        await Assert.That(receipt.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Failed);
    }

    [Test]
    public async Task MissingAuthorizationLeavesTransientFailureTerminal()
    {
        var fixture = await Fixture.CreateAsync(
            RepositoryCiJobFailureKind.InfrastructureTransient,
            authorizationAvailable: false);

        var receipt = await fixture.CoordinateAsync();

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.AuthorizationMissing);
        await Assert.That(receipt.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Failed);
        await Assert.That(fixture.AuthorizationReads).IsEqualTo(1);
    }

    [Test]
    public async Task LostAuthorityCannotReadAuthorizationOrScheduleRetry()
    {
        var fixture = await Fixture.CreateAsync(RepositoryCiJobFailureKind.RunnerLost);

        var receipt = await fixture.CoordinateAsync(static () => false);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobRetryCoordinationDisposition.AuthorityLost);
        await Assert.That(fixture.AuthorizationReads).IsEqualTo(0);
        await Assert.That(receipt.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Failed);
    }

    private sealed class Fixture
    {
        private readonly RepositoryCiJobRetryCoordinator coordinator;

        private Fixture(
            RepositoryCiPipelinePlan pipeline,
            RepositoryCiPipelineJob job,
            AdjustableTimeProvider clock,
            RepositoryCiJobRetryCoordinator coordinator)
        {
            Pipeline = pipeline;
            Job = job;
            Clock = clock;
            this.coordinator = coordinator;
        }

        internal RepositoryCiPipelinePlan Pipeline { get; }
        internal RepositoryCiPipelineJob Job { get; }
        internal AdjustableTimeProvider Clock { get; }
        internal int AuthorizationReads { get; private set; }

        internal static async Task<Fixture> CreateAsync(
            RepositoryCiJobFailureKind failure,
            bool authorizationAvailable = true)
        {
            var clock = new AdjustableTimeProvider(Now);
            var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
            var jobs = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger(), clock);
            await jobs.InitializeAsync(pipeline, 5, 9, static () => true);
            var job = (await jobs.ReadAsync(pipeline)).Ready[0];
            var prepared = await RepositoryCiJobJournalTests.PrepareAsync(jobs, pipeline, job);
            var dispatched = await jobs.AdvanceAsync(
                prepared.Job!,
                RepositoryCiJobPhase.Dispatched,
                Digest(1),
                0,
                RepositoryCiJobFailureKind.Unspecified,
                41,
                static () => true);
            var running = await jobs.AdvanceAsync(
                dispatched.Job!,
                RepositoryCiJobPhase.Running,
                Digest(2),
                0,
                RepositoryCiJobFailureKind.Unspecified,
                0,
                static () => true);
            await jobs.AdvanceAsync(
                running.Job!,
                RepositoryCiJobPhase.Failed,
                Digest(3),
                0,
                failure,
                0,
                static () => true);
            Fixture? fixture = null;
            var selectedAuthorization = authorizationAvailable
                ? new RepositoryCiJobRetryAuthorization("retry-authority-1", Digest(9))
                : null;
            var coordinator = new RepositoryCiJobRetryCoordinator(
                jobs,
                (_, cancellationToken) =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    fixture!.AuthorizationReads++;
                    return Task.FromResult(selectedAuthorization);
                });
            fixture = new(pipeline, job, clock, coordinator);
            return fixture;
        }

        internal Task<RepositoryCiJobRetryCoordinationReceipt> CoordinateAsync(
            Func<bool>? authorityStillValid = null) => coordinator.CoordinateAsync(
                Pipeline,
                Job.Request.Job,
                "gru-controller-1",
                5,
                authorityStillValid ?? (() => true));
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);

    internal sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset now = now;
        public override DateTimeOffset GetUtcNow() => now;
        internal void Advance(TimeSpan duration) => now = now.Add(duration);
    }
}
