using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

/// <summary>
/// Issue #7 operator status surface: a bounded, redacted, read-only projection of one durable
/// direct-delivery journal record — current operation, region progress, health, rollback state,
/// and the actionable failure — with no customer content and no request material.
/// </summary>
public sealed class DirectDeliveryOperatorStatusTests
{
    [Test]
    public async Task AnInFlightRecordReportsOperationRegionsAndUnknownHealthWithoutAction()
    {
        var status = DirectDeliveryOperatorStatusProjection.Project(InFlight());

        await Assert.That(status.Exists).IsTrue();
        await Assert.That(status.Operation).IsEqualTo(DeliveryJournalState.Applying);
        await Assert.That(status.OperationId).IsEqualTo("operation-1");
        await Assert.That(status.ArtifactDigest).IsEqualTo(ArtifactDigest);
        await Assert.That(status.RegionProgress.Select(static region => (region.Region, region.State)))
            .IsEquivalentTo(new[] { ("gru", "applied"), ("sfo", "applying") });
        await Assert.That(status.Health!.State).IsEqualTo(DirectDeliveryOperatorHealth.Unknown);
        await Assert.That(status.Rollback!.State).IsEqualTo(DirectDeliveryOperatorRollback.None);
        await Assert.That(status.Failure).IsNull();
        await Assert.That(status.RequiresOperatorAction).IsFalse();
    }

    [Test]
    public async Task ASucceededRecordReportsHealthRollbackAndNoAction()
    {
        var status = DirectDeliveryOperatorStatusProjection.Project(Succeeded());

        await Assert.That(status.Operation).IsEqualTo(DeliveryJournalState.Succeeded);
        await Assert.That(status.Health!.State).IsEqualTo(DirectDeliveryOperatorHealth.Passed);
        await Assert.That(status.Health.Converged).IsTrue();
        await Assert.That(status.Health.Checks.Select(static check => (check.Name, check.Status)))
            .IsEquivalentTo(new[] { ("gru-health", DeliveryHealthStatus.Passed) });
        await Assert.That(status.Rollback!.State).IsEqualTo(DeliveryRollbackStatus.NotRequired);
        await Assert.That(status.RequiresOperatorAction).IsFalse();
    }

    [Test]
    public async Task AFailedRollbackReportsTheRecoveryAnchorAndTheActionableFailure()
    {
        var status = DirectDeliveryOperatorStatusProjection.Project(FailedRollback());

        await Assert.That(status.Operation).IsEqualTo(DeliveryJournalState.Failed);
        await Assert.That(status.Rollback!.State).IsEqualTo(DeliveryRollbackStatus.Failed);
        await Assert.That(status.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(status.Failure!.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(status.Failure.Remediation)
            .Contains("Restore the recorded target artifact digest");
        await Assert.That(status.RequiresOperatorAction).IsTrue();
    }

    [Test]
    public async Task AReceiptlessFailureWithRollbackDebtRequiresOperatorAction()
    {
        var record = InFlight() with
        {
            State = DeliveryJournalState.Failed,
            Regions = new[]
            {
                new DeliveryRegionProgress("gru", "rollback_pending", PreviousDigest),
                new DeliveryRegionProgress("sfo", "failed", null, DirectDeliveryErrorCode.MutationFailed),
            },
        };

        var status = DirectDeliveryOperatorStatusProjection.Project(record);

        await Assert.That(status.Operation).IsEqualTo(DeliveryJournalState.Failed);
        await Assert.That(status.Rollback!.State).IsEqualTo(DirectDeliveryOperatorRollback.Pending);
        await Assert.That(status.RequiresOperatorAction).IsTrue();
        await Assert.That(status.Health!.State).IsEqualTo(DirectDeliveryOperatorHealth.Unknown);
    }

    [Test]
    public async Task AnUnjournaledOperationIsAReportableUnknownState()
    {
        var status = DirectDeliveryOperatorStatusProjection.Project(null);

        await Assert.That(status.Exists).IsFalse();
        await Assert.That(status.Operation)
            .IsEqualTo(DirectDeliveryOperatorStatus.UnknownOperation);
        await Assert.That(status.RequiresOperatorAction).IsFalse();
        await Assert.That(status.RegionProgress).IsEmpty();
    }

    [Test]
    public async Task TheProjectionDropsEveryHostileRecordFieldItMustNotProject()
    {
        // A hostile durable record is the tripwire input: the strings below really occur in
        // the record being projected, so their absence from the serialized status is a
        // passing guard that would fail on a real leak. They live only in fields the
        // projection must never emit — the request fingerprint (which hashes the request
        // text "direct customer change" and the actor), the audit identity, and the receipt's
        // source block. Health-check names and region identities ARE projected by design:
        // they are the receipt's already-redacted, bounded contract surface (AC-5).
        const string hostileFingerprint =
            "fingerprint-of-request-reason=direct customer change;requestedBy=actor-1;" +
            "secret=-----BEGIN PRIVATE KEY-----;token=ghp_leak";
        const string hostileAuditId = "audit-actor-1-secret-token";
        var record = FailedRollback() with
        {
            RequestFingerprint = hostileFingerprint,
            Receipt = FailedRollback().Receipt! with
            {
                AuditId = hostileAuditId,
                Source = new DeliverySource(
                    "TerraScale/TerraScale.Orchestrator?token=ghp_leak",
                    new string('f', 40),
                    "sha256:" + new string('e', 64)),
            },
        };

        var status = DirectDeliveryOperatorStatusProjection.Project(record);
        var json = DirectDeliveryOperatorStatusProjection.Serialize(status);

        await Assert.That(json).DoesNotContain("direct customer change");
        await Assert.That(json).DoesNotContain("actor-1");
        await Assert.That(json).DoesNotContain("BEGIN PRIVATE KEY");
        await Assert.That(json).DoesNotContain("ghp_leak");
        await Assert.That(json).DoesNotContain(hostileAuditId);
        await Assert.That(json).DoesNotContain("fingerprint");
        await Assert.That(json).DoesNotContain("reason");
        await Assert.That(json).DoesNotContain("requestedBy");
        await Assert.That(json).DoesNotContain("audit");
        await Assert.That(json).DoesNotContain("secret");
        await Assert.That(json).DoesNotContain("token");
        // The projected fields that DO appear are the bounded operator surface: operation
        // state, digests, region progress, and the receipt's error code.
        await Assert.That(json).Contains(DeliveryJournalState.Failed);
        await Assert.That(json).Contains(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(json.Contains('\n')).IsFalse();
        using var document = JsonDocument.Parse(json);
        await Assert.That(document.RootElement.GetProperty("operation").GetString())
            .IsEqualTo(DeliveryJournalState.Failed);
    }

    private static DeliveryJournalRecord InFlight() => new(
        "operation-1",
        "fingerprint-1",
        DeliveryJournalState.Applying,
        null,
        ArtifactDigest,
        new[]
        {
            new DeliveryRegionProgress("gru", "applied", PreviousDigest),
            new DeliveryRegionProgress("sfo", "applying", PreviousDigest),
        },
        AuthorityGeneration: 3,
        WriterEpoch: 2,
        Attempt: 1);

    private static DeliveryJournalRecord Succeeded() => new(
        "operation-1",
        "fingerprint-1",
        DeliveryJournalState.Succeeded,
        new(
            DeliveryRequest.CurrentSchemaVersion,
            "operation-1",
            DeliveryReceiptStatus.Succeeded,
            null,
            ArtifactDigest,
            new("authentication", "development", ["gru"]),
            new(true, ValidDigest, null),
            new([new("gru-health", DeliveryHealthStatus.Passed)], true),
            new(false, null, DeliveryRollbackStatus.NotRequired),
            "audit-test",
            new(null, null, null)),
        ArtifactDigest,
        [new DeliveryRegionProgress("gru", "healthy", PreviousDigest)]);

    private static DeliveryJournalRecord FailedRollback() => new(
        "operation-1",
        "fingerprint-1",
        DeliveryJournalState.Failed,
        new(
            DeliveryRequest.CurrentSchemaVersion,
            "operation-1",
            DeliveryReceiptStatus.Failed,
            null,
            ArtifactDigest,
            new("authentication", "development", ["gru", "sfo"]),
            new(true, ValidDigest, null),
            new([new("gru-health", DeliveryHealthStatus.Failed)], false),
            new(true, PreviousDigest, DeliveryRollbackStatus.Failed, PreviousDigest),
            "audit-test",
            new(
                DirectDeliveryErrorCode.RollbackFailed,
                "Automatic rollback did not complete.",
                "Restore the recorded target artifact digest and inspect the target before retrying.")),
        ArtifactDigest,
        new[]
        {
            new DeliveryRegionProgress("gru", "rollback_failed", PreviousDigest),
            new DeliveryRegionProgress("sfo", "failed", null, DirectDeliveryErrorCode.HealthFailed),
        });

    private const string ValidDigest =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ArtifactDigest =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string PreviousDigest = ValidDigest;
}

