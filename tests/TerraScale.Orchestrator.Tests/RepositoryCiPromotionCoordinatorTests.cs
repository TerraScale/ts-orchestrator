using System.Globalization;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiPromotionCoordinatorTests
{
    [Test]
    public async Task PromotionRunsPublishThenSfoFraGruAndExactReplayDoesNothing()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var authorization = Authorization();
        var actuator = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(ledger),
            actuator);

        var completed = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-1",
            7,
            static () => true);
        var replay = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(completed.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.Completed);
        await Assert.That(completed.Lease!.Phase).IsEqualTo(RepositoryCiPromotionPhase.Completed);
        await Assert.That(completed.Lease.PhaseSequence).IsEqualTo(9);
        await Assert.That(replay.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.AlreadyCompleted);
        await Assert.That(actuator.Calls.Select(static call => call.Operation).SequenceEqual(new[]
        {
            RepositoryCiPromotionOperation.Publish,
            RepositoryCiPromotionOperation.DeploySfo,
            RepositoryCiPromotionOperation.DeployFra,
            RepositoryCiPromotionOperation.DeployGru,
        })).IsTrue();
        await Assert.That(actuator.Calls.Select(static call => call.FencingToken).Distinct().Single())
            .IsEqualTo(1);
        await Assert.That(actuator.Calls.Select(static call => call.OperationId).Distinct().Count())
            .IsEqualTo(4);
        await Assert.That(ledger.Mutations).IsEqualTo(10);
    }

    [Test]
    public async Task PublicationFailureRollsBackWithoutTouchingARegion()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var actuator = new TestActuator(static (operation, _) =>
            operation != RepositoryCiPromotionOperation.Publish);
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(ledger),
            actuator);

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RolledBack);
        await Assert.That(receipt.FailedOperation)
            .IsEqualTo(RepositoryCiPromotionOperation.Publish);
        await Assert.That(actuator.Calls.Select(static call => call.Operation).SequenceEqual(new[]
        {
            RepositoryCiPromotionOperation.Publish,
            RepositoryCiPromotionOperation.RollbackPublication,
        })).IsTrue();
        await Assert.That(receipt.Lease!.Phase).IsEqualTo(RepositoryCiPromotionPhase.RolledBack);
    }

    [Test]
    public async Task CrashAfterPublishReplaysTheSameOperationIdentity()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 3);
        var authorization = Authorization();
        var actuator = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(ledger),
            actuator);

        await Assert.That(async () => await coordinator.CoordinateAsync(
                authorization,
                "gru-controller-1",
                7,
                static () => true))
            .Throws<IOException>();
        var recovered = await new RepositoryCiPromotionCoordinator(
                new RepositoryCiPromotionJournal(ledger),
                actuator)
            .CoordinateAsync(
                authorization,
                "gru-controller-1",
                7,
                static () => true);

        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.Completed);
        await Assert.That(actuator.Calls.Count).IsEqualTo(5);
        await Assert.That(actuator.Calls[0].Operation).IsEqualTo(RepositoryCiPromotionOperation.Publish);
        await Assert.That(actuator.Calls[1].Operation).IsEqualTo(RepositoryCiPromotionOperation.Publish);
        await Assert.That(actuator.Calls[0].OperationId).IsEqualTo(actuator.Calls[1].OperationId);
        await Assert.That(actuator.Calls[0].FencingToken).IsEqualTo(actuator.Calls[1].FencingToken);
    }

    [Test]
    public async Task FraFailureRollsBackFraThenSfoAndResumesFailedRollback()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var authorization = Authorization();
        var actuator = new TestActuator(static (operation, attempt) => operation switch
        {
            RepositoryCiPromotionOperation.DeployFra => false,
            RepositoryCiPromotionOperation.RollbackFra => attempt > 1,
            _ => true,
        });
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(ledger),
            actuator);

        var failed = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-1",
            7,
            static () => true);
        var recovered = await new RepositoryCiPromotionCoordinator(
                new RepositoryCiPromotionJournal(ledger),
                actuator)
            .CoordinateAsync(
                authorization,
                "gru-controller-1",
                7,
                static () => true);

        await Assert.That(failed.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RollbackFailed);
        await Assert.That(failed.FailedOperation)
            .IsEqualTo(RepositoryCiPromotionOperation.RollbackFra);
        await Assert.That(failed.Lease!.Phase)
            .IsEqualTo(RepositoryCiPromotionPhase.RollbackFraStarted);
        await Assert.That(recovered.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RolledBack);
        await Assert.That(recovered.Lease!.Phase).IsEqualTo(RepositoryCiPromotionPhase.RolledBack);
        await Assert.That(actuator.Calls.Select(static call => call.Operation).SequenceEqual(new[]
        {
            RepositoryCiPromotionOperation.Publish,
            RepositoryCiPromotionOperation.DeploySfo,
            RepositoryCiPromotionOperation.DeployFra,
            RepositoryCiPromotionOperation.RollbackFra,
            RepositoryCiPromotionOperation.RollbackFra,
            RepositoryCiPromotionOperation.RollbackSfo,
        })).IsTrue();
        await Assert.That(actuator.Calls[3].OperationId).IsEqualTo(actuator.Calls[4].OperationId);
    }

    [Test]
    public async Task AuthorityLossLeavesStartedIntentAndHigherEpochTakeoverUsesNewFence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var authorization = Authorization();
        var actuator = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(ledger),
            actuator);
        var checks = 0;

        var lost = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-1",
            7,
            () => ++checks <= 2);
        var held = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-2",
            7,
            static () => true);
        var takeover = await coordinator.CoordinateAsync(
            authorization,
            "gru-controller-2",
            8,
            static () => true);

        await Assert.That(lost.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.AuthorityLost);
        await Assert.That(lost.Lease!.Phase).IsEqualTo(RepositoryCiPromotionPhase.PublishStarted);
        await Assert.That(held.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.LeaseRejected);
        await Assert.That(held.JournalDisposition)
            .IsEqualTo(RepositoryCiPromotionJournalDisposition.LeaseHeld);
        await Assert.That(takeover.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.Completed);
        await Assert.That(takeover.Lease!.FencingToken).IsEqualTo(2);
        await Assert.That(actuator.Calls.Count).IsEqualTo(4);
        await Assert.That(actuator.Calls.All(static call => call.FencingToken == 2)).IsTrue();
    }

    [Test]
    public async Task ActuatorRechecksAuthorityAtTheExternalSideEffectBoundary()
    {
        var authority = true;
        var actuator = new BoundaryActuator(() => authority = false);
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            actuator);

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            () => authority);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.AuthorityLost);
        await Assert.That(receipt.Lease!.Phase).IsEqualTo(RepositoryCiPromotionPhase.PublishStarted);
        await Assert.That(actuator.ExternalMutations).IsEqualTo(0);
    }

    [Test]
    public async Task ForgejoPublicationComposesBeforeRegionalRollout()
    {
        var publications = new TestPackagePublications(RepositoryCiPackagePublicationDisposition.Published);
        var regions = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            new RepositoryCiForgejoPromotionActuator(publications, regions));

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.Completed);
        await Assert.That(publications.Calls).IsEqualTo(1);
        await Assert.That(regions.Calls.Select(static call => call.Operation).SequenceEqual(new[]
        {
            RepositoryCiPromotionOperation.DeploySfo,
            RepositoryCiPromotionOperation.DeployFra,
            RepositoryCiPromotionOperation.DeployGru,
        })).IsTrue();
    }

    [Test]
    public async Task FailedForgejoPublicationRollsBackWithoutDeletingImmutableArchive()
    {
        var publications = new TestPackagePublications(
            RepositoryCiPackagePublicationDisposition.IdentityConflict);
        var regions = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            new RepositoryCiForgejoPromotionActuator(publications, regions));

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RolledBack);
        await Assert.That(receipt.FailedOperation).IsEqualTo(RepositoryCiPromotionOperation.Publish);
        await Assert.That(publications.Calls).IsEqualTo(1);
        await Assert.That(regions.Calls).IsEmpty();
    }

    [Test]
    public async Task PackageAndOciPublicationBothCompleteBeforeRegionalRollout()
    {
        var publications = new TestPackagePublications(RepositoryCiPackagePublicationDisposition.NotApplicable);
        var oci = new TestOciPublications(RepositoryCiOciImagePublicationDisposition.Published);
        var regions = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            new RepositoryCiForgejoPromotionActuator(publications, regions, oci));

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.Completed);
        await Assert.That(publications.Calls).IsEqualTo(1);
        await Assert.That(oci.Calls).IsEqualTo(1);
        await Assert.That(regions.Calls.Select(static call => call.Operation).SequenceEqual(new[]
        {
            RepositoryCiPromotionOperation.DeploySfo,
            RepositoryCiPromotionOperation.DeployFra,
            RepositoryCiPromotionOperation.DeployGru,
        })).IsTrue();
    }

    [Test]
    public async Task FailedOciPublicationRollsBackWithoutRegionalCalls()
    {
        var publications = new TestPackagePublications(RepositoryCiPackagePublicationDisposition.NotApplicable);
        var oci = new TestOciPublications(RepositoryCiOciImagePublicationDisposition.IdentityConflict);
        var regions = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            new RepositoryCiForgejoPromotionActuator(publications, regions, oci));

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RolledBack);
        await Assert.That(regions.Calls).IsEmpty();
    }

    [Test]
    public async Task NoApplicablePublisherRollsBackWithoutRegionalCalls()
    {
        var publications = new TestPackagePublications(RepositoryCiPackagePublicationDisposition.NotApplicable);
        var oci = new TestOciPublications(RepositoryCiOciImagePublicationDisposition.NotApplicable);
        var regions = new TestActuator();
        var coordinator = new RepositoryCiPromotionCoordinator(
            new RepositoryCiPromotionJournal(new ForgejoWebhookJournalTests.TestLedger()),
            new RepositoryCiForgejoPromotionActuator(publications, regions, oci));

        var receipt = await coordinator.CoordinateAsync(
            Authorization(),
            "gru-controller-1",
            7,
            static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiPromotionCoordinationDisposition.RolledBack);
        await Assert.That(regions.Calls).IsEmpty();
    }

    private static RepositoryCiPromotionAuthorization Authorization()
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
                new ApprovalId("operator-approval-1"),
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

    private sealed class TestActuator(
        Func<RepositoryCiPromotionOperation, int, bool>? succeeds = null)
        : IRepositoryCiPromotionActuator
    {
        private readonly Dictionary<RepositoryCiPromotionOperation, int> attempts = [];

        internal List<ActuatorCall> Calls { get; } = [];

        public Task<RepositoryCiPromotionOperationReceipt> ExecuteAsync(
            RepositoryCiPromotionOperation operation,
            RepositoryCiPromotionAuthorization authorization,
            RepositoryCiPromotionLease lease,
            string operationId,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var attempt = attempts.GetValueOrDefault(operation) + 1;
            attempts[operation] = attempt;
            var succeeded = succeeds?.Invoke(operation, attempt) ?? true;
            Calls.Add(new(operation, operationId, lease.FencingToken, succeeded));
            return Task.FromResult(new RepositoryCiPromotionOperationReceipt(
                succeeded,
                Digest(100 + Calls.Count)));
        }
    }

    private sealed record ActuatorCall(
        RepositoryCiPromotionOperation Operation,
        string OperationId,
        long FencingToken,
        bool Succeeded);

    private sealed class BoundaryActuator(Action beforeBoundary) : IRepositoryCiPromotionActuator
    {
        internal int ExternalMutations { get; private set; }

        public Task<RepositoryCiPromotionOperationReceipt> ExecuteAsync(
            RepositoryCiPromotionOperation operation,
            RepositoryCiPromotionAuthorization authorization,
            RepositoryCiPromotionLease lease,
            string operationId,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            beforeBoundary();
            if (authorityStillValid()) ExternalMutations++;
            return Task.FromResult(new RepositoryCiPromotionOperationReceipt(
                authorityStillValid(),
                Digest(999)));
        }
    }

    private sealed class TestPackagePublications(RepositoryCiPackagePublicationDisposition disposition)
        : IRepositoryCiPackagePublicationCoordinator
    {
        internal int Calls { get; private set; }

        public Task<RepositoryCiPackagePublicationReceipt> PublishAsync(
            RepositoryCiQualifiedCandidate qualified,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(new RepositoryCiPackagePublicationReceipt(
                disposition,
                disposition is RepositoryCiPackagePublicationDisposition.Published or
                    RepositoryCiPackagePublicationDisposition.Duplicate
                        ? Digest(998)
                        : string.Empty,
                []));
        }
    }

    private sealed class TestOciPublications(RepositoryCiOciImagePublicationDisposition disposition)
        : IRepositoryCiOciImagePublicationCoordinator
    {
        internal int Calls { get; private set; }

        public Task<RepositoryCiOciImagePublicationReceipt> PublishAsync(
            RepositoryCiQualifiedCandidate qualified,
            Func<bool> authorityStillValid,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return Task.FromResult(new RepositoryCiOciImagePublicationReceipt(
                disposition,
                disposition is RepositoryCiOciImagePublicationDisposition.Published or
                    RepositoryCiOciImagePublicationDisposition.Duplicate
                        ? Digest(997)
                        : string.Empty,
                []));
        }
    }
}
