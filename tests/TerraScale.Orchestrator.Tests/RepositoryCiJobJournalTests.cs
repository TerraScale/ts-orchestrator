using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobJournalTests
{
    [Test]
    public async Task InitializationIsIdempotentAndExposesOnlyDependencyReadyJobs()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiJobJournal(ledger);
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();

        var recorded = await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var duplicate = await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var run = await journal.ReadAsync(pipeline);

        await Assert.That(recorded).IsEqualTo(RepositoryCiJobJournalDisposition.Recorded);
        await Assert.That(duplicate).IsEqualTo(RepositoryCiJobJournalDisposition.Duplicate);
        await Assert.That(run.State).IsEqualTo(RepositoryCiPipelineRunState.Active);
        await Assert.That(run.Jobs.Count).IsEqualTo(pipeline.Jobs.Count);
        await Assert.That(run.Ready.Count).IsEqualTo(2);
        await Assert.That(run.Ready.All(static job => job.DependsOn.Count == 0)).IsTrue();
        await Assert.That(run.Results).IsEmpty();
        await Assert.That(ledger.Mutations).IsEqualTo(pipeline.Jobs.Count);
    }

    [Test]
    public async Task DispatchRequiresDependenciesAndExactCgroupIsolation()
    {
        var journal = await InitializedAsync();
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        var blocked = pipeline.Jobs.First(static job => job.DependsOn.Count > 0);
        var root = pipeline.Jobs.First(static job => job.DependsOn.Count == 0);

        var notReady = await PrepareAsync(journal, pipeline, blocked);
        var denied = await journal.PrepareDispatchAsync(
            pipeline,
            root.Request.Job,
            Runner(root),
            Isolation(root) with { CgroupV2 = false },
            "gru-controller-1",
            5,
            $"dispatch-{root.Request.Job.Value}",
            static () => true);
        var prepared = await PrepareAsync(journal, pipeline, root);
        var duplicate = await PrepareAsync(journal, pipeline, root);
        var staleReplay = await PrepareAsync(journal, pipeline, root, static () => false);

        await Assert.That(notReady.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.NotReady);
        await Assert.That(denied.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.RunnerDenied);
        await Assert.That(prepared.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.Prepared);
        await Assert.That(duplicate.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.Duplicate);
        await Assert.That(staleReplay.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.StaleAuthority);
        await Assert.That(prepared.Job!.FencingToken).IsEqualTo(1);
        await Assert.That(prepared.Job.Phase).IsEqualTo(RepositoryCiJobPhase.DispatchPrepared);
    }

    [Test]
    public async Task CompletedJobsUnlockTheDagAndProduceExactResults()
    {
        var journal = await InitializedAsync();
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        var run = await journal.ReadAsync(pipeline);
        var evidence = 1;

        while (run.State == RepositoryCiPipelineRunState.Active)
        {
            await Assert.That(run.Ready).IsNotEmpty();
            foreach (var job in run.Ready)
                await CompleteAsync(journal, pipeline, job, evidence++);
            run = await journal.ReadAsync(pipeline);
        }

        await Assert.That(run.State).IsEqualTo(RepositoryCiPipelineRunState.Succeeded);
        await Assert.That(run.Ready).IsEmpty();
        await Assert.That(run.Results.Count).IsEqualTo(pipeline.Jobs.Count);
        await Assert.That(run.Results.All(static result => result.Succeeded && result.Attempt == 1)).IsTrue();
    }

    [Test]
    public async Task OneFailedJobStopsNewDispatch()
    {
        var journal = await InitializedAsync();
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        var root = (await journal.ReadAsync(pipeline)).Ready[0];
        var prepared = await PrepareAsync(journal, pipeline, root);
        var dispatched = await AdvanceAsync(journal, prepared.Job!, RepositoryCiJobPhase.Dispatched, 1);
        var running = await AdvanceAsync(journal, dispatched.Job!, RepositoryCiJobPhase.Running, 2);
        await AdvanceAsync(journal, running.Job!, RepositoryCiJobPhase.Failed, 3);

        var run = await journal.ReadAsync(pipeline);
        var other = pipeline.Jobs.Single(job => job.Request.Job != root.Request.Job && job.DependsOn.Count == 0);
        var stopped = await PrepareAsync(journal, pipeline, other);

        await Assert.That(run.State).IsEqualTo(RepositoryCiPipelineRunState.Failed);
        await Assert.That(run.Ready).IsEmpty();
        await Assert.That(stopped.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.PipelineFailed);
        await Assert.That(run.Results).HasSingleItem();
        await Assert.That(run.Results[0].Succeeded).IsFalse();
    }

    [Test]
    public async Task HigherAuthorityTakesOverAndFencesTheOldController()
    {
        var journal = await InitializedAsync();
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        var root = (await journal.ReadAsync(pipeline)).Ready[0];
        var prepared = await PrepareAsync(journal, pipeline, root);

        var takeover = await journal.AcquireAsync(
            pipeline,
            root.Request.Job,
            "gru-controller-2",
            6,
            static () => true);
        var stale = await AdvanceAsync(journal, prepared.Job!, RepositoryCiJobPhase.Dispatched, 1);
        var advanced = await AdvanceAsync(journal, takeover.Job!, RepositoryCiJobPhase.Dispatched, 1);

        await Assert.That(takeover.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.TakenOver);
        await Assert.That(takeover.Job!.FencingToken).IsEqualTo(2);
        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.StaleLease);
        await Assert.That(advanced.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.Advanced);
    }

    [Test]
    public async Task ConcurrentPreparationConvergesAndCorruptStateFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiJobJournal(ledger);
        var pipeline = RepositoryCiPipelineJournalTests.Pipeline();
        await journal.InitializeAsync(pipeline, 5, 9, static () => true);
        var root = (await journal.ReadAsync(pipeline)).Ready[0];

        var receipts = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            PrepareAsync(journal, pipeline, root)));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiJobJournalDisposition.Prepared)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiJobJournalDisposition.Duplicate)).IsEqualTo(11);

        ledger.CorruptFirst();
        await Assert.That(async () => await journal.ReadAsync(pipeline)).Throws<InvalidDataException>();
    }

    private static async Task<RepositoryCiJobJournal> InitializedAsync()
    {
        var journal = new RepositoryCiJobJournal(new ForgejoWebhookJournalTests.TestLedger());
        await journal.InitializeAsync(
            RepositoryCiPipelineJournalTests.Pipeline(),
            5,
            9,
            static () => true);
        return journal;
    }

    private static Task<RepositoryCiJobJournalReceipt> PrepareAsync(
        RepositoryCiJobJournal journal,
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob job,
        Func<bool>? authorityStillValid = null) => journal.PrepareDispatchAsync(
            pipeline,
            job.Request.Job,
            Runner(job),
            Isolation(job),
            "gru-controller-1",
            5,
            $"dispatch-{job.Request.Job.Value}",
            authorityStillValid ?? (() => true));

    private static async Task CompleteAsync(
        RepositoryCiJobJournal journal,
        RepositoryCiPipelinePlan pipeline,
        RepositoryCiPipelineJob job,
        int evidence)
    {
        var prepared = await PrepareAsync(journal, pipeline, job);
        var dispatched = await AdvanceAsync(journal, prepared.Job!, RepositoryCiJobPhase.Dispatched, evidence);
        var running = await AdvanceAsync(journal, dispatched.Job!, RepositoryCiJobPhase.Running, evidence + 100);
        var completed = await AdvanceAsync(journal, running.Job!, RepositoryCiJobPhase.Succeeded, evidence + 200);
        await Assert.That(completed.Disposition).IsEqualTo(RepositoryCiJobJournalDisposition.Advanced);
    }

    private static Task<RepositoryCiJobJournalReceipt> AdvanceAsync(
        RepositoryCiJobJournal journal,
        RepositoryCiJobSnapshot lease,
        RepositoryCiJobPhase phase,
        int evidence) => journal.AdvanceAsync(
            lease,
            phase,
            Digest(evidence),
            0,
            static () => true);

    private static RunnerEvidence Runner(RepositoryCiPipelineJob job) => new(
        new($"runner-{job.Plan.Node.Id}"),
        TrustZone.UntrustedProduct,
        20,
        true,
        job.Request.RequiredCapabilities);

    private static CiRunnerIsolationEvidence Isolation(RepositoryCiPipelineJob job) => new(
        job.Request.Job,
        Runner(job).Runner,
        20,
        TrustZone.UntrustedProduct,
        CiRunnerNodeClass.UntrustedProduct,
        CiRunnerNetworkScope.PublicDependenciesOnly,
        CiRunnerCredentialProfile.None,
        CiRunnerCacheScope.UntrustedIsolated,
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        true,
        true,
        true,
        true,
        true,
        1_000,
        512L * 1024 * 1024,
        1024L * 1024 * 1024,
        128,
        16L * 1024 * 1024);

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);
}
