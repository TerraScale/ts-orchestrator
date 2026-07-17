using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobResultReconcilerTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task RunningAndTerminalRunnerCheckpointsAdvanceTheAuthoritativeJobExactlyOnce()
    {
        var fixture = await Fixture.CreateAsync();
        var runnerLease = await fixture.Executions.AcquireAsync(
            fixture.Accepted,
            fixture.Accepted.Command.Operation,
            Now.AddSeconds(1),
            TimeSpan.FromMinutes(5));

        var running = await fixture.ReconcileAsync();
        var runnerCompleted = await fixture.Executions.CompleteAsync(
            runnerLease.Execution!,
            true,
            Digest('a'),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            Now.AddSeconds(2));
        var completed = await fixture.ReconcileAsync();
        var duplicate = await fixture.ReconcileAsync();
        var run = await fixture.Jobs.ReadAsync(fixture.Pipeline);
        var result = run.Results.Single(value => value.Job == fixture.JobId);

        await Assert.That(runnerLease.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Acquired);
        await Assert.That(running.Disposition).IsEqualTo(RepositoryCiJobResultReconcileDisposition.Running);
        await Assert.That(running.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Running);
        await Assert.That(runnerCompleted.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Completed);
        await Assert.That(completed.Disposition).IsEqualTo(RepositoryCiJobResultReconcileDisposition.Completed);
        await Assert.That(duplicate.Disposition).IsEqualTo(RepositoryCiJobResultReconcileDisposition.Duplicate);
        await Assert.That(result.Succeeded).IsTrue();
        await Assert.That(result.EvidenceDigest).IsEqualTo(Digest('a'));
    }

    [Test]
    public async Task TerminalRunnerFailurePreservesItsExactClassification()
    {
        var fixture = await Fixture.CreateAsync();
        var runnerLease = await fixture.Executions.AcquireAsync(
            fixture.Accepted,
            fixture.Accepted.Command.Operation,
            Now.AddSeconds(1),
            TimeSpan.FromMinutes(5));
        await fixture.Executions.CompleteAsync(
            runnerLease.Execution!,
            false,
            Digest('b'),
            0,
            RepositoryCiJobFailureKind.WorkloadFailed,
            Now.AddSeconds(2));

        var completed = await fixture.ReconcileAsync();

        await Assert.That(completed.Disposition).IsEqualTo(RepositoryCiJobResultReconcileDisposition.Completed);
        await Assert.That(completed.Job!.Phase).IsEqualTo(RepositoryCiJobPhase.Failed);
        await Assert.That(completed.Job.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        await Assert.That(completed.Job.EvidenceDigest).IsEqualTo(Digest('b'));
    }

    [Test]
    public async Task ARunnerResultFromAnotherDispatchSequenceFailsClosed()
    {
        var fixture = await Fixture.CreateAsync(dispatchStreamSequence: 102);

        var receipt = await fixture.ReconcileAsync();
        var job = (await fixture.Jobs.ReadAsync(fixture.Pipeline)).Jobs
            .Single(value => value.Job.Request.Job == fixture.JobId);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobResultReconcileDisposition.IdentityConflict);
        await Assert.That(job.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
    }

    [Test]
    public async Task UnverifiedTerminalEvidenceCannotAdvanceControllerState()
    {
        var fixture = await Fixture.CreateAsync();
        var runnerLease = await fixture.Executions.AcquireAsync(
            fixture.Accepted,
            fixture.Accepted.Command.Operation,
            Now.AddSeconds(1),
            TimeSpan.FromMinutes(5));
        await fixture.Executions.CompleteAsync(
            runnerLease.Execution!,
            true,
            Digest('c'),
            0,
            RepositoryCiJobFailureKind.Unspecified,
            Now.AddSeconds(2));
        var reconciler = new RepositoryCiJobResultReconciler(
            fixture.Jobs,
            fixture.Executions,
            new TestEvidenceVerifier(false));

        var receipt = await reconciler.ReconcileAsync(
            fixture.Pipeline,
            fixture.JobId,
            "gru-controller-1",
            5,
            static () => true);
        var current = (await fixture.Jobs.ReadAsync(fixture.Pipeline)).Jobs
            .Single(value => value.Job.Request.Job == fixture.JobId);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobResultReconcileDisposition.EvidenceConflict);
        await Assert.That(current.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
    }

    [Test]
    public async Task AReadyExecutionForAnotherSignedOperationFailsClosed()
    {
        var (_, takeover) = await RepositoryCiJobInboxTests.AcceptedTakeoverAsync();
        var fixture = await Fixture.CreateAsync(execution: takeover with { StreamSequence = 101 });

        var receipt = await fixture.ReconcileAsync();
        var job = (await fixture.Jobs.ReadAsync(fixture.Pipeline)).Jobs
            .Single(value => value.Job.Request.Job == fixture.JobId);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobResultReconcileDisposition.IdentityConflict);
        await Assert.That(job.Phase).IsEqualTo(RepositoryCiJobPhase.Dispatched);
    }

    [Test]
    public async Task PendingJobCannotAddressTheRunnerJournal()
    {
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        var jobs = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger());
        await jobs.InitializeAsync(pipeline, 5, 9, static () => true);
        var job = (await jobs.ReadAsync(pipeline)).Ready[0];
        var reconciler = new RepositoryCiJobResultReconciler(
            jobs,
            new(new ForgejoWebhookJournalTests.TestLedger()),
            new TestEvidenceVerifier());

        var receipt = await reconciler.ReconcileAsync(
            pipeline,
            job.Request.Job,
            "gru-controller-1",
            5,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiJobResultReconcileDisposition.NotDispatchable);
        await Assert.That(receipt.Execution).IsNull();
    }

    private static string Digest(char value) => new(value, 64);

    private sealed record Fixture(
        RepositoryCiAcceptedJob Accepted,
        RepositoryCiPipelinePlan Pipeline,
        JobId JobId,
        RepositoryCiJobJournal Jobs,
        RepositoryCiJobExecutionJournal Executions,
        RepositoryCiJobResultReconciler Reconciler)
    {
        internal static async Task<Fixture> CreateAsync(
            ulong dispatchStreamSequence = 101,
            RepositoryCiAcceptedJob? execution = null)
        {
            var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
            var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
            var jobs = new RepositoryCiJobJournal(
                new ForgejoWebhookJournalTests.TestLedger(),
                new FixedTimeProvider());
            await jobs.InitializeAsync(pipeline, 5, 9, static () => true);
            var job = (await jobs.ReadAsync(pipeline)).Ready
                .Single(value => value.Request.Job.Value == accepted.Command.Job);
            var prepared = await RepositoryCiJobJournalTests.PrepareAsync(jobs, pipeline, job);
            await Assert.That(prepared.Job!.OperationId).IsEqualTo(accepted.Command.Operation);
            var dispatched = await jobs.AdvanceAsync(
                prepared.Job,
                RepositoryCiJobPhase.Dispatched,
                accepted.PayloadDigest,
                0,
                RepositoryCiJobFailureKind.Unspecified,
                dispatchStreamSequence,
                static () => true);
            var executions = new RepositoryCiJobExecutionJournal(
                new ForgejoWebhookJournalTests.TestLedger());
            await executions.PrepareAsync(execution ?? accepted, Now);
            return new(
                accepted,
                pipeline,
                job.Request.Job,
                jobs,
                executions,
                new(jobs, executions, new TestEvidenceVerifier()));
        }

        internal Task<RepositoryCiJobResultReconcileReceipt> ReconcileAsync() => Reconciler.ReconcileAsync(
            Pipeline,
            JobId,
            "gru-controller-1",
            5,
            static () => true);
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    internal sealed class TestEvidenceVerifier(bool valid = true) : IRepositoryCiJobResultEvidenceVerifier
    {
        public Task<bool> VerifyAsync(
            RepositoryCiJobExecutionSnapshot execution,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(execution);
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(valid);
        }
    }
}
