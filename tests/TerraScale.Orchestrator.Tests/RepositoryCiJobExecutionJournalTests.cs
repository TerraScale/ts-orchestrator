using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiJobExecutionJournalTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task ExactAcceptedCommandIsPreparedLeasedRenewedAndCompletedOnce()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiJobExecutionJournal(ledger);

        var prepared = await journal.PrepareAsync(accepted, Now);
        var duplicatePrepare = await journal.PrepareAsync(accepted, Now.AddSeconds(1));
        var acquired = await journal.AcquireAsync(
            accepted,
            "runner-operation-1",
            Now.AddSeconds(2),
            TimeSpan.FromMinutes(2));
        var renewed = await journal.RenewAsync(
            acquired.Execution!,
            Now.AddMinutes(1),
            TimeSpan.FromMinutes(2));
        var completed = await journal.CompleteAsync(
            renewed.Execution!,
            succeeded: true,
            Digest('a'),
            requiredTestSkips: 0,
            RepositoryCiJobFailureKind.Unspecified,
            Now.AddMinutes(2));
        var replay = await journal.CompleteAsync(
            renewed.Execution!,
            succeeded: true,
            Digest('a'),
            requiredTestSkips: 0,
            RepositoryCiJobFailureKind.Unspecified,
            Now.AddMinutes(2));
        var recovered = await journal.ReadAsync(
            accepted.Command.Runner,
            accepted.Command.PipelineDigest,
            accepted.Command.Job);

        await Assert.That(prepared.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Prepared);
        await Assert.That(prepared.CanAcknowledge).IsTrue();
        await Assert.That(duplicatePrepare.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Duplicate);
        await Assert.That(acquired.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Acquired);
        await Assert.That(acquired.Execution!.LeaseSequence).IsEqualTo(1);
        await Assert.That(renewed.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Renewed);
        await Assert.That(completed.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Completed);
        await Assert.That(completed.Execution!.Phase).IsEqualTo(RepositoryCiJobExecutionPhase.Succeeded);
        await Assert.That(replay.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Duplicate);
        await Assert.That(recovered!.EvidenceDigest).IsEqualTo(Digest('a'));
        await Assert.That(recovered.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.Unspecified);
    }

    [Test]
    public async Task ActiveLeaseBlocksAnotherWorkerAndExpiredLeaseFencesTheOldWorker()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var journal = new RepositoryCiJobExecutionJournal(new ForgejoWebhookJournalTests.TestLedger());
        await journal.PrepareAsync(accepted, Now);
        var first = await journal.AcquireAsync(
            accepted,
            "runner-operation-1",
            Now,
            TimeSpan.FromMinutes(1));

        var held = await journal.AcquireAsync(
            accepted,
            "runner-operation-2",
            Now.AddSeconds(30),
            TimeSpan.FromMinutes(1));
        var takeover = await journal.AcquireAsync(
            accepted,
            "runner-operation-2",
            Now.AddSeconds(61),
            TimeSpan.FromMinutes(1));
        var staleRenewal = await journal.RenewAsync(
            first.Execution!,
            Now.AddSeconds(62),
            TimeSpan.FromMinutes(1));
        var staleCompletion = await journal.CompleteAsync(
            first.Execution!,
            succeeded: false,
            Digest('b'),
            requiredTestSkips: 0,
            RepositoryCiJobFailureKind.RunnerLost,
            Now.AddSeconds(62));

        await Assert.That(held.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.LeaseHeld);
        await Assert.That(takeover.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.TakenOver);
        await Assert.That(takeover.Execution!.LeaseSequence).IsEqualTo(2);
        await Assert.That(staleRenewal.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.StaleLease);
        await Assert.That(staleCompletion.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.StaleLease);
    }

    [Test]
    public async Task HigherAuthorityAcceptanceSupersedesAndFencesAnActiveExecution()
    {
        var (original, takeover) = await RepositoryCiJobInboxTests.AcceptedTakeoverAsync();
        var journal = new RepositoryCiJobExecutionJournal(new ForgejoWebhookJournalTests.TestLedger());
        await journal.PrepareAsync(original, Now);
        var active = await journal.AcquireAsync(
            original,
            "runner-operation-1",
            Now,
            TimeSpan.FromMinutes(2));

        var superseded = await journal.PrepareAsync(takeover, Now.AddSeconds(1));
        var stale = await journal.CompleteAsync(
            active.Execution!,
            succeeded: false,
            Digest('c'),
            requiredTestSkips: 0,
            RepositoryCiJobFailureKind.RunnerLost,
            Now.AddSeconds(2));
        var stalePrepare = await journal.PrepareAsync(original, Now.AddSeconds(2));
        var reacquired = await journal.AcquireAsync(
            takeover,
            "runner-operation-2",
            Now.AddSeconds(2),
            TimeSpan.FromMinutes(2));

        await Assert.That(superseded.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Superseded);
        await Assert.That(superseded.CanAcknowledge).IsTrue();
        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.StaleLease);
        await Assert.That(stalePrepare.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.StaleAcceptance);
        await Assert.That(reacquired.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.Acquired);
        await Assert.That(reacquired.Execution!.Document.AuthorityEpoch)
            .IsEqualTo(takeover.Command.AuthorityEpoch);
    }

    [Test]
    public async Task MissingPreparationInvalidLeaseAndInventedAcceptanceFailClosed()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var journal = new RepositoryCiJobExecutionJournal(new ForgejoWebhookJournalTests.TestLedger());

        var missing = await journal.AcquireAsync(
            accepted,
            "runner-operation-1",
            Now,
            TimeSpan.FromMinutes(1));

        await Assert.That(missing.Disposition).IsEqualTo(RepositoryCiJobExecutionDisposition.NotPrepared);
        await Assert.That(async () => await journal.PrepareAsync(
                accepted with { PayloadDigest = Digest('d') },
                Now))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await journal.AcquireAsync(
                accepted,
                "runner-operation-1",
                Now,
                TimeSpan.FromSeconds(29)))
            .Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task CorruptExecutionRecordFailsClosedOnRecovery()
    {
        var accepted = await RepositoryCiJobInboxTests.AcceptedAsync();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiJobExecutionJournal(ledger);
        await journal.PrepareAsync(accepted, Now);
        ledger.CorruptFirst();

        await Assert.That(async () => await journal.ReadAsync(
                accepted.Command.Runner,
                accepted.Command.PipelineDigest,
                accepted.Command.Job))
            .Throws<InvalidDataException>();
    }

    private static string Digest(char value) => new(value, 64);
}
