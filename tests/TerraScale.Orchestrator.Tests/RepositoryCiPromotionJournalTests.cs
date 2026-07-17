using System.Globalization;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPromotionJournalTests
{
    [Test]
    public async Task ExactAuthorizationAcquiresAndResumesOneLease()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var authorization = Authorization();

        var acquired = await journal.AcquireAsync(authorization, "gru-controller-1", 7);
        var resumed = await journal.AcquireAsync(authorization, "gru-controller-1", 7);

        await Assert.That(acquired.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Acquired);
        await Assert.That(resumed.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Resumed);
        await Assert.That(resumed.CanContinue).IsTrue();
        await Assert.That(resumed.Lease.FencingToken).IsEqualTo(1);
        await Assert.That(resumed.Lease.Phase).IsEqualTo(RepositoryCiPromotionPhase.Authorized);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task HigherAuthorityTakesOverAndFencesTheOldWriter()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var authorization = Authorization();
        var oldLease = (await journal.AcquireAsync(authorization, "gru-controller-1", 7)).Lease;

        var takeover = await journal.AcquireAsync(authorization, "gru-controller-2", 8);
        var stale = await journal.AdvanceAsync(
            oldLease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20));

        await Assert.That(takeover.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.TakenOver);
        await Assert.That(takeover.Lease.FencingToken).IsEqualTo(2);
        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.StaleLease);
        await Assert.That(stale.Lease.Phase).IsEqualTo(RepositoryCiPromotionPhase.Authorized);
    }

    [Test]
    public async Task StaleAndSameEpochAuthoritiesCannotReplaceTheLease()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var authorization = Authorization();
        await journal.AcquireAsync(authorization, "gru-controller-1", 7);

        var stale = await journal.AcquireAsync(authorization, "gru-controller-old", 6);
        var held = await journal.AcquireAsync(authorization, "gru-controller-2", 7);

        await Assert.That(stale.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.StaleAuthority);
        await Assert.That(held.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.LeaseHeld);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task AQualifiedReleaseSetCannotSwitchAuthorizationAfterAcquisition()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        await journal.AcquireAsync(Authorization(), "gru-controller-1", 7);

        var conflict = await journal.AcquireAsync(Authorization(2), "gru-controller-2", 8);

        await Assert.That(conflict.Disposition)
            .IsEqualTo(RepositoryCiPromotionJournalDisposition.AuthorizationConflict);
        await Assert.That(conflict.CanContinue).IsFalse();
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task PhaseUpdatesAreStrictAndExactlyIdempotent()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var lease = (await journal.AcquireAsync(Authorization(), "gru-controller-1", 7)).Lease;

        var advanced = await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20));
        var duplicate = await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20));
        var conflictingReplay = await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-2",
            Digest(20));
        var skipped = await journal.AdvanceAsync(
            advanced.Lease,
            RepositoryCiPromotionPhase.SfoDeploymentStarted,
            "deploy-sfo-1",
            Digest(21));

        await Assert.That(advanced.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
        await Assert.That(duplicate.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Duplicate);
        await Assert.That(conflictingReplay.Disposition)
            .IsEqualTo(RepositoryCiPromotionJournalDisposition.PhaseConflict);
        await Assert.That(skipped.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.PhaseConflict);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task ForwardPromotionMustVerifySfoThenFraThenGru()
    {
        var journal = new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger());
        var lease = (await journal.AcquireAsync(Authorization(), "gru-controller-1", 7)).Lease;
        var phases = new[]
        {
            RepositoryCiPromotionPhase.PublishStarted,
            RepositoryCiPromotionPhase.Published,
            RepositoryCiPromotionPhase.SfoDeploymentStarted,
            RepositoryCiPromotionPhase.SfoVerified,
            RepositoryCiPromotionPhase.FraDeploymentStarted,
            RepositoryCiPromotionPhase.FraVerified,
            RepositoryCiPromotionPhase.GruDeploymentStarted,
            RepositoryCiPromotionPhase.GruVerified,
            RepositoryCiPromotionPhase.Completed,
        };

        for (var index = 0; index < phases.Length; index++)
        {
            var receipt = await journal.AdvanceAsync(
                lease,
                phases[index],
                $"phase-{index + 1}",
                Digest(30 + index));
            await Assert.That(receipt.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
            lease = receipt.Lease;
        }

        await Assert.That(lease.Phase).IsEqualTo(RepositoryCiPromotionPhase.Completed);
        await Assert.That(lease.PhaseSequence).IsEqualTo(9);
    }

    [Test]
    public async Task StartedWorkCanOnlyEndThroughTheClosedRollbackPath()
    {
        var journal = new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger());
        var lease = (await journal.AcquireAsync(Authorization(), "gru-controller-1", 7)).Lease;
        lease = (await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20))).Lease;
        lease = (await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.Published,
            "published-1",
            Digest(21))).Lease;

        var rollback = await journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.RollbackStarted,
            "rollback-1",
            Digest(22));
        var forward = await journal.AdvanceAsync(
            rollback.Lease,
            RepositoryCiPromotionPhase.SfoDeploymentStarted,
            "deploy-sfo-1",
            Digest(23));
        var rolledBack = await journal.AdvanceAsync(
            rollback.Lease,
            RepositoryCiPromotionPhase.RolledBack,
            "rolled-back-1",
            Digest(24));

        await Assert.That(rollback.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
        await Assert.That(forward.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.PhaseConflict);
        await Assert.That(rolledBack.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
    }

    [Test]
    public async Task RegionalRollbackRunsGruThenFraThenSfo()
    {
        var journal = new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger());
        var lease = (await journal.AcquireAsync(Authorization(), "gru-controller-1", 7)).Lease;
        var forward = new[]
        {
            RepositoryCiPromotionPhase.PublishStarted,
            RepositoryCiPromotionPhase.Published,
            RepositoryCiPromotionPhase.SfoDeploymentStarted,
            RepositoryCiPromotionPhase.SfoVerified,
            RepositoryCiPromotionPhase.FraDeploymentStarted,
            RepositoryCiPromotionPhase.FraVerified,
            RepositoryCiPromotionPhase.GruDeploymentStarted,
            RepositoryCiPromotionPhase.GruVerified,
        };
        foreach (var phase in forward)
            lease = (await journal.AdvanceAsync(lease, phase, $"forward-{phase}", Digest(30))).Lease;

        var reverse = new[]
        {
            RepositoryCiPromotionPhase.RollbackGruStarted,
            RepositoryCiPromotionPhase.GruRolledBack,
            RepositoryCiPromotionPhase.RollbackFraStarted,
            RepositoryCiPromotionPhase.FraRolledBack,
            RepositoryCiPromotionPhase.RollbackSfoStarted,
            RepositoryCiPromotionPhase.SfoRolledBack,
            RepositoryCiPromotionPhase.RolledBack,
        };
        foreach (var phase in reverse)
        {
            var receipt = await journal.AdvanceAsync(lease, phase, $"reverse-{phase}", Digest(31));
            await Assert.That(receipt.Disposition).IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
            lease = receipt.Lease;
        }

        await Assert.That(lease.Phase).IsEqualTo(RepositoryCiPromotionPhase.RolledBack);
    }

    [Test]
    public async Task ConcurrentExactPhaseUpdatesConvergeOnOneMutation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var lease = (await journal.AcquireAsync(Authorization(), "gru-controller-1", 7)).Lease;

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => journal.AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20))));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiPromotionJournalDisposition.Advanced)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == RepositoryCiPromotionJournalDisposition.Duplicate)).IsEqualTo(15);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task InterruptedMutationsResumeWithoutChangingIdentityOrOrder()
    {
        var authorization = Authorization();
        var createLedger = new ForgejoWebhookJournalTests.TestLedger(1);
        await Assert.That(async () =>
                await new RepositoryCiPromotionJournal(createLedger)
                    .AcquireAsync(authorization, "gru-controller-1", 7))
            .Throws<IOException>();
        var recoveredCreate = await new RepositoryCiPromotionJournal(createLedger)
            .AcquireAsync(authorization, "gru-controller-1", 7);

        var advanceLedger = new ForgejoWebhookJournalTests.TestLedger(2);
        var advanceJournal = new RepositoryCiPromotionJournal(advanceLedger);
        var lease = (await advanceJournal.AcquireAsync(authorization, "gru-controller-1", 7)).Lease;
        await Assert.That(async () => await advanceJournal.AdvanceAsync(
                lease,
                RepositoryCiPromotionPhase.PublishStarted,
                "publish-1",
                Digest(20)))
            .Throws<IOException>();
        var recoveredAdvance = await new RepositoryCiPromotionJournal(advanceLedger).AdvanceAsync(
            lease,
            RepositoryCiPromotionPhase.PublishStarted,
            "publish-1",
            Digest(20));

        await Assert.That(recoveredCreate.Disposition)
            .IsEqualTo(RepositoryCiPromotionJournalDisposition.Acquired);
        await Assert.That(recoveredAdvance.Disposition)
            .IsEqualTo(RepositoryCiPromotionJournalDisposition.Advanced);
    }

    [Test]
    public async Task CorruptDurableStateFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new RepositoryCiPromotionJournal(ledger);
        var authorization = Authorization();
        await journal.AcquireAsync(authorization, "gru-controller-1", 7);
        ledger.CorruptFirst();

        await Assert.That(async () =>
                await journal.AcquireAsync(authorization, "gru-controller-1", 7))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task DurableDocumentRejectsAnInventedPhaseEdge()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        await new RepositoryCiPromotionJournal(ledger)
            .AcquireAsync(Authorization(), "gru-controller-1", 7);
        var document = JsonSerializer.Deserialize(
            ledger.Values.Single(),
            RepositoryCiPromotionJournalJsonContext.Default.RepositoryCiPromotionJournalDocument)!;

        var invented = document with
        {
            PreviousPhase = RepositoryCiPromotionPhase.Authorized,
            Phase = RepositoryCiPromotionPhase.GruVerified,
            PhaseSequence = 1,
        };

        await Assert.That(invented.Validate).Throws<InvalidDataException>();
    }

    private static RepositoryCiPromotionAuthorization Authorization(int approval = 1)
    {
        var qualified = RepositoryCiCandidateResolverTests.QualifiedCandidate();
        return RepositoryCiPromotionAuthorizer.Authorize(
            qualified,
            new(
                qualified.Digest,
                qualified.Candidate.Digest,
                Digest(1),
                Digest(2),
                Digest(3),
                Digest(4),
                Digest(5),
                new SigningIdentityId("deployment-evidence-signer"),
                new SignatureId("deployment-evidence-signature"),
                new ApprovalId($"operator-approval-{approval}"),
                new(
                    new AttestationId(Digest(6)),
                    new AttestationId(Digest(7)),
                    new AttestationId(Digest(8)),
                    true,
                    true,
                    true),
                true,
                true,
                true,
                true),
            9,
            10,
            100);
    }

    private static string Digest(int value) => value.ToString("x64", CultureInfo.InvariantCulture);
}
