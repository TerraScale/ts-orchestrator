using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TUnit.Assertions;
using TUnit.Assertions.Extensions;
using TUnit.Core;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.ControlPlane.Tests;

public sealed class DirectDeliveryTests
{
    [Test]
    public async Task Wire_request_round_trips_with_normative_names_and_redacted_receipt()
    {
        var request = Request();
        var json = DeliveryWireCodec.SerializeRequest(request);
        var roundTrip = DeliveryWireCodec.DeserializeRequest(json);

        await Assert.That(json).Contains("\"schemaVersion\":1");
        await Assert.That(json).Contains("\"configurationRevision\":\"sha256:");
        await Assert.That(roundTrip.SchemaVersion).IsEqualTo(request.SchemaVersion);
        await Assert.That(roundTrip.OperationId).IsEqualTo(request.OperationId);
        await Assert.That(roundTrip.Source).IsEqualTo(request.Source);
        await Assert.That(roundTrip.Artifact).IsEqualTo(request.Artifact);
        await Assert.That(roundTrip.Target!.Regions!).IsEquivalentTo(request.Target!.Regions!);
        await Assert.That(DeliveryWireCodec.SerializeReceipt(SuccessReceipt())).DoesNotContain("secret");
    }

    [Test]
    public async Task Direct_delivery_authorizes_orders_checks_converges_and_journals()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal);

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo("observe:gru|apply:gru|health:gru|observe:sfo|apply:sfo|health:sfo|converge");
        await Assert.That(journal.Records[^1].State).IsEqualTo(DeliveryJournalState.Succeeded);
        await Assert.That(string.Join('|', journal.Records.Select(record => record.State))).IsEqualTo(
            "accepted|applying|applied|healthy|applying|applied|healthy|succeeded");
        await Assert.That(journal.Records[^1].Regions!.Select(region => region.State))
            .IsEquivalentTo(["healthy", "healthy"]);
        await Assert.That(receipt.Provenance.Verified).IsTrue();
        await Assert.That(receipt.Health.Converged).IsTrue();
    }

    [Test]
    public async Task Fresh_progress_indexes_each_region_even_when_the_first_mutation_is_a_noop()
    {
        var target = new RecordingTarget();
        target.SeedCurrentArtifact("gru", ArtifactDigest, ValidDigest);
        target.SeedCurrentArtifact("sfo", PreviousDigest, PreviousManifestDigest);
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());
        var terminal = journal.Records[^1];
        var regions = terminal.Regions!;

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(regions.Select(region => region.Region))
            .IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(regions[0].State).IsEqualTo("healthy");
        await Assert.That(regions[0].PreviousArtifactDigest).IsNull();
        await Assert.That(regions[1].State).IsEqualTo("healthy");
        await Assert.That(regions[1].PreviousArtifactDigest).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Failed_health_attempts_reverse_exact_digest_rollback()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Rollback.Attempted).IsTrue();
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo(
            "observe:gru|apply:gru|health:gru|observe:sfo|apply:sfo|health:sfo|observe:sfo|rollback:sfo|rollback-health:sfo|observe:gru|rollback:gru|rollback-health:gru|rollback-converge");
    }

    [Test]
    public async Task Failed_health_rollback_preserves_a_distinct_previous_manifest_digest()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        target.SeedCurrentArtifact("gru", PreviousDigest, PreviousManifestDigest);
        target.SeedCurrentArtifact("sfo", PreviousDigest, PreviousManifestDigest);
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(receipt.Rollback.TargetManifestDigest).IsEqualTo(PreviousManifestDigest);
        await Assert.That(target.RollbackManifests).IsEquivalentTo([
            ("sfo", PreviousManifestDigest),
            ("gru", PreviousManifestDigest),
        ]);
    }

    [Test]
    public async Task Malformed_unauthorized_and_unknown_requests_fail_without_mutation()
    {
        var target = new RecordingTarget();
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal(), authorized: false);

        var unauthorized = await coordinator.DeliverAsync(Request());
        var malformed = await coordinator.DeliverAsync(Request() with { Artifact = new("sha256:nope", ValidDigest, "service") });
        var unsupported = await coordinator.DeliverAsync(Request() with { SchemaVersion = 2 });
        var missing = await coordinator.DeliverAsync(Request() with { Source = null, Artifact = null });
        var unbounded = await coordinator.DeliverAsync(Request() with { Reason = new string('x', DirectDeliveryCoordinator.MaximumTextLength + 1) });
        var stageField = await coordinator.DeliverJsonAsync(DeliveryWireCodec.SerializeRequest(Request())
            .Replace("\"reason\"", "\"candidateId\":\"candidate\",\"reason\"", StringComparison.Ordinal));

        await Assert.That(unauthorized.Error.Code).IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
        await Assert.That(malformed.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidDigest);
        await Assert.That(unsupported.Error.Code).IsEqualTo(DirectDeliveryErrorCode.UnsupportedSchema);
        await Assert.That(missing.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MissingSourceAndArtifact);
        await Assert.That(unbounded.Error.Code).IsEqualTo(DirectDeliveryErrorCode.UnboundedText);
        await Assert.That(stageField.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(target.Calls).IsEmpty();
    }

    [Test]
    public async Task Failed_rollback_remains_failed_and_redacts_adapter_details()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo", FailRollbackInRegion = "gru" };
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());
        var json = DeliveryWireCodec.SerializeReceipt(receipt);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(json).DoesNotContain("provider-detail");
        await Assert.That(json).DoesNotContain("secret");
    }

    [Test]
    public async Task Rollback_must_pass_health_and_convergence_before_rolled_back()
    {
        var target = new RecordingTarget
        {
            FailHealthInRegion = "sfo",
            FailRollbackHealthInRegion = "gru",
        };
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo(
            "observe:gru|apply:gru|health:gru|observe:sfo|apply:sfo|health:sfo|observe:sfo|rollback:sfo|rollback-health:sfo|observe:gru|rollback:gru|rollback-health:gru");
    }

    [Test]
    public async Task Retrying_a_failed_rollback_resumes_the_rollback_instead_of_replaying_terminal_receipt()
    {
        var journal = new InMemoryDeliveryJournal();
        var first = await Coordinator(
            new RecordingTarget { FailHealthInRegion = "sfo", FailRollbackInRegion = "gru" }, journal)
            .DeliverAsync(Request());

        var secondTarget = new RecordingTarget();
        var second = await Coordinator(secondTarget, journal).DeliverAsync(Request());

        await Assert.That(first.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(second.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(secondTarget.Calls).DoesNotContain("apply:gru");
        await Assert.That(secondTarget.Calls).DoesNotContain("apply:sfo");
        await Assert.That(string.Join('|', secondTarget.Calls)).IsEqualTo("observe:gru|rollback-health:gru|rollback-converge");
    }

    [Test]
    public async Task Built_artifact_digest_is_bound_to_operation_fingerprint()
    {
        var journal = new InMemoryDeliveryJournal();
        var first = Coordinator(new RecordingTarget(), journal, artifactBuilder: new ArtifactBuilder(ArtifactDigest));
        var second = Coordinator(new RecordingTarget(), journal, artifactBuilder: new ArtifactBuilder(OtherArtifactDigest));

        var initial = await first.DeliverAsync(Request() with { Artifact = null });
        var conflict = await second.DeliverAsync(Request() with { Artifact = null });

        await Assert.That(initial.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(conflict.Error.Code).IsEqualTo(DirectDeliveryErrorCode.OperationConflict);
    }

    [Test]
    public async Task Duplicate_delivery_replays_the_same_receipt_without_a_second_mutation()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal);

        var first = await coordinator.DeliverAsync(Request());
        var second = await coordinator.DeliverAsync(Request());

        await Assert.That(first.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(second.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(second.Health.Converged).IsTrue();
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo("observe:gru|apply:gru|health:gru|observe:sfo|apply:sfo|health:sfo|converge");
        await Assert.That(journal.Records.Count(static record => record.State == DeliveryJournalState.Accepted))
            .IsEqualTo(1);
    }

    [Test]
    public async Task Same_operation_id_with_a_different_target_fails_closed_without_mutation()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal);

        _ = await coordinator.DeliverAsync(Request());
        var conflict = await coordinator.DeliverAsync(Request() with
        {
            Target = new("authentication", "development", ["gru"]),
        });

        await Assert.That(conflict.Error.Code).IsEqualTo(DirectDeliveryErrorCode.OperationConflict);
        await Assert.That(target.Calls.Count(static value => value.StartsWith("apply:", StringComparison.Ordinal)))
            .IsEqualTo(2);
    }

    [Test]
    public async Task Stale_digests_and_unverified_provenance_fail_without_mutation()
    {
        var stale = Coordinator(new RecordingTarget(), new InMemoryDeliveryJournal(),
            provenance: new ProvenanceVerifier(stale: true));
        var unverified = Coordinator(new RecordingTarget(), new InMemoryDeliveryJournal(),
            provenance: new ProvenanceVerifier(verified: false));

        var staleReceipt = await stale.DeliverAsync(Request());
        var unverifiedReceipt = await unverified.DeliverAsync(Request());

        await Assert.That(staleReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.StaleDigest);
        await Assert.That(unverifiedReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.ProvenanceFailed);
        await Assert.That(staleReceipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(unverifiedReceipt.Provenance.Verified).IsFalse();
    }

    [Test]
    public async Task Unavailable_journal_fails_closed_with_a_retryable_error()
    {
        var coordinator = Coordinator(new RecordingTarget(), new ThrowingJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
    }

    [Test]
    public async Task Adapter_cancellation_reports_cancelled_without_mutation_success()
    {
        var target = new CancellingTarget();
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.Cancelled);
    }

    [Test]
    public async Task Health_evidence_that_is_empty_or_lying_never_reports_success()
    {
        var empty = Coordinator(new EmptyChecksTarget(), new InMemoryDeliveryJournal());
        var lying = Coordinator(new LyingHealthTarget(), new InMemoryDeliveryJournal());

        var emptyReceipt = await empty.DeliverAsync(Request());
        var lyingReceipt = await lying.DeliverAsync(Request());
        await Assert.That(emptyReceipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(emptyReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.HealthFailed);
        await Assert.That(emptyReceipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        await Assert.That(lyingReceipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(lyingReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.HealthFailed);
        await Assert.That(lyingReceipt.Health.Checks.Any(static check =>
            check.Status == DeliveryHealthStatus.Failed)).IsTrue();
    }

    [Test]
    public async Task Journal_unavailable_and_cancelled_receipts_replay_instead_of_poisoning()
    {
        foreach (var code in new[]
                 {
                     DirectDeliveryErrorCode.JournalUnavailable,
                     DirectDeliveryErrorCode.Cancelled,
                 })
        {
            var target = new RecordingTarget();
            var journal = new InMemoryDeliveryJournal();
            var request = Request();
            // A journaled terminal-looking receipt whose failure is recoverable in place.
            await journal.AppendAsync(new(
                request.OperationId!,
                DirectDeliveryCoordinator.RequestFingerprint(request),
                DeliveryJournalState.Failed,
                new(
                    DeliveryRequest.CurrentSchemaVersion,
                    request.OperationId!,
                    DeliveryReceiptStatus.Failed,
                    null,
                    ArtifactDigest,
                    null,
                    new DeliveryProvenance(false, null, null),
                    new DeliveryHealth([], false),
                    new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired),
                    "audit-stale",
                    new(code, null, null)),
                ArtifactDigest,
                [new("gru", "healthy"), new("sfo", "healthy")]), default);

            var receipt = await Coordinator(target, journal).DeliverAsync(request);

            await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
            await Assert.That(string.Join('|', target.Calls)).IsEqualTo("converge");
        }
    }

    [Test]
    public async Task Production_targets_fail_closed_without_a_production_provenance_binding()
    {
        var coordinator = Coordinator(new RecordingTarget(), new InMemoryDeliveryJournal(),
            provenance: new DirectDeliveryDevelopmentProvenance());

        var receipt = await coordinator.DeliverAsync(Request() with
        {
            Target = new("authentication", "production", ["gru"]),
        });

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.ProvenanceFailed);
        await Assert.That(receipt.Provenance.Verified).IsFalse();
    }

    [Test]
    public async Task Unreachable_boundaries_report_transient_codes_distinct_from_denials()
    {
        var authorizationUnavailable = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            authorizer: new ThrowingAuthorizer(new IOException("boundary unreachable"))).DeliverAsync(Request());
        var provenanceUnavailable = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            provenance: new ThrowingProvenance(new IOException("evidence source unreachable")))
            .DeliverAsync(Request());
        var authorizationDenied = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            authorizer: new ThrowingAuthorizer(new InvalidDataException("denied"))).DeliverAsync(Request());

        await Assert.That(authorizationUnavailable.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.AuthorizationUnavailable);
        await Assert.That(provenanceUnavailable.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.ProvenanceUnavailable);
        await Assert.That(authorizationDenied.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
    }

    [Test]
    public async Task JournalFailureAfterAHealthyDeploymentNeverRollsItBack()
    {
        var target = new RecordingTarget();
        var flaky = new StateFilteredJournal(DeliveryJournalState.Succeeded);
        var first = await Coordinator(target, flaky).DeliverAsync(Request());

        await Assert.That(first.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(first.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        // The deployment is applied, healthy, and converged: no rollback may run.
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("rollback", StringComparison.Ordinal))).IsFalse();
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(ArtifactDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(ArtifactDigest);

        // Replay with a healthy journal converges from durable progress and appends the terminal
        // record without re-applying either region.
        var healthy = new InMemoryDeliveryJournal();
        foreach (var record in flaky.Records) await healthy.AppendAsync(record, default);
        var second = await Coordinator(target, healthy).DeliverAsync(Request());

        await Assert.That(second.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(string.Join('|', target.Calls[^1..])).IsEqualTo("converge");
    }

    [Test]
    public async Task JournalFailureMidApplyIsAReplayableFailureWithoutRollback()
    {
        var target = new RecordingTarget();
        var flaky = new StateFilteredJournal(DeliveryJournalState.Applying);

        var receipt = await Coordinator(target, flaky).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("rollback", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task UnpersistableFailureReceiptsSurfaceTheJournalDownState()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var flaky = new ReceiptFilteredJournal();

        var receipt = await Coordinator(target, flaky).DeliverAsync(Request());

        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.HealthFailed);
        await Assert.That(receipt.Error.Remediation).Contains("journal currently unavailable");
    }

    [Test]
    public async Task CrashBetweenApplyAndAppliedPersistKeepsTheTrueRollbackDigest()
    {
        var target = new RecordingTarget { FailHealthInRegion = "gru" };
        var flaky = new StateFilteredJournal("applied");

        // The apply succeeded (region mutated) but the 'applied' persist crashed the process:
        // the durable journal holds 'applying' plus the write-ahead previous digest.
        var crashed = await Coordinator(target, flaky).DeliverAsync(Request());
        await Assert.That(crashed.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(crashed.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);

        // Replay with a healthy journal: the region re-applies as a no-op (it already runs the
        // requested digest), health fails, and rollback restores the TRUE previous digest —
        // not the requested one this delivery installed.
        var healthy = new InMemoryDeliveryJournal();
        foreach (var record in flaky.Records) await healthy.AppendAsync(record, default);
        var replayTarget = new RecordingTarget { FailHealthInRegion = "gru" };
        replayTarget.SeedCurrentDigest("gru", ArtifactDigest);
        replayTarget.SeedCurrentDigest("sfo", PreviousDigest);

        var replay = await Coordinator(replayTarget, healthy).DeliverAsync(Request());

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(replay.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(replayTarget.RollbackDigests).Contains(("gru", PreviousDigest));
    }

    [Test]
    public async Task AdmissionRaceLoserReceivesOperationConflictNotJournalUnavailable()
    {
        var coordinator = Coordinator(
            new RecordingTarget(),
            new ConflictOnFirstAppendJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.OperationConflict);
    }

    [Test]
    public async Task FirstDeploymentIntoAPristineRegionCannotRollBackAndSaysSo()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        target.SeedCurrentArtifact("gru", PreviousDigest, PreviousDigest);
        target.SeedCurrentArtifact("sfo", null, null); // pristine: first-ever deployment
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        // gru (with a prior artifact) rolls back; sfo (pristine) cannot be and stays deployed.
        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        await Assert.That(target.RollbackDigests.Select(static digest => digest.Region))
            .IsEquivalentTo(["gru"]);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(ArtifactDigest);
        await Assert.That(receipt.Error.Remediation).Contains("bootstrap expectation");
    }

    [Test]
    public async Task JournalUnavailableReceiptNamesARetentionCapOverflowCause()
    {
        // The final Succeeded append overflows the retention cap: the receipt must point the
        // operator at the cap, not at generic journal-health restoration.
        var journal = new OverflowOnSucceededJournal();
        var receipt = await Coordinator(new RecordingTarget(), journal).DeliverAsync(Request());

        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        await Assert.That(receipt.Error.Message).Contains("retention cap");
        await Assert.That(receipt.Error.Remediation).Contains("Raise the retention cap");
    }

    private sealed class ConflictOnFirstAppendJournal : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();
        private bool thrown;

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken)
        {
            if (!thrown)
            {
                thrown = true;
                return ValueTask.FromException(new DirectDeliveryJournalConflictException());
            }
            return inner.AppendAsync(record, cancellationToken);
        }
    }

    private sealed class OverflowOnSucceededJournal : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.State == DeliveryJournalState.Succeeded
                ? ValueTask.FromException(
                    new TerraScale.Orchestrator.Delivery.JournalRetentionOverflowException("cap exceeded"))
                : inner.AppendAsync(record, cancellationToken);
    }

    /// <summary>Fails appends whose record state matches the filter; everything else persists.</summary>    /// <summary>Fails appends whose record state matches the filter; everything else persists.</summary>
    private sealed class StateFilteredJournal(string failingState) : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public IReadOnlyList<DeliveryJournalRecord> Records => inner.Records;

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.State == failingState
                ? ValueTask.FromException(new IOException("journal degraded"))
                : inner.AppendAsync(record, cancellationToken);
    }

    /// <summary>Fails appends that carry a receipt (the terminal-receipt path).</summary>
    private sealed class ReceiptFilteredJournal : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.Receipt is not null
                ? ValueTask.FromException(new IOException("journal degraded"))
                : inner.AppendAsync(record, cancellationToken);
    }

    private sealed class ThrowingAuthorizer(Exception exception) : IDeliveryAuthorizer
    {
        public ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(
            DeliveryRequest request,
            CancellationToken cancellationToken) =>
            throw exception;
    }

    private sealed class ThrowingProvenance(Exception exception) : IDeliveryProvenanceVerifier
    {
        public ValueTask<DeliveryProvenanceResult> VerifyAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            CancellationToken cancellationToken) =>
            throw exception;
    }

    private static DirectDeliveryCoordinator Coordinator(IDeliveryTarget target, IDeliveryJournal journal,
        bool authorized = true, IDeliveryArtifactBuilder? artifactBuilder = null,
        IDeliveryProvenanceVerifier? provenance = null, IDeliveryAuthorizer? authorizer = null) => new(
        authorizer ?? new Authorizer(authorized),
        provenance ?? new ProvenanceVerifier(),
        new TargetResolver(target),
        journal,
        artifactBuilder,
        auditIdFactory: static () => "audit-test");

    private static DeliveryRequest Request() => new(
        1,
        "operation-1",
        new("TerraScale/TerraScale.Orchestrator", Commit, ValidDigest),
        new(ArtifactDigest, ValidDigest, "service"),
        new("authentication", "development", ["gru", "sfo"]),
        ValidDigest,
        null,
        "actor-1",
        "direct customer change");

    private static DeliveryReceipt SuccessReceipt() => new(
        1, "operation-1", DeliveryReceiptStatus.Succeeded, null, ArtifactDigest, null,
        new(true, ValidDigest, null), new([], true), new(false, null, DeliveryRollbackStatus.NotRequired),
        "audit-test", new(null, null, null));

    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private const string ValidDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string OtherArtifactDigest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private const string PreviousDigest = ValidDigest;
    private const string PreviousManifestDigest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    private sealed class Authorizer(bool authorized) : IDeliveryAuthorizer
    {
        public ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(DeliveryRequest request, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryAuthorizationResult(authorized));
    }

    private sealed class ProvenanceVerifier(bool verified = true, bool stale = false) : IDeliveryProvenanceVerifier
    {
        public ValueTask<DeliveryProvenanceResult> VerifyAsync(DeliveryRequest request, DeliveryArtifact artifact, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryProvenanceResult(verified, stale, request.ConfigurationRevision, request.MigrationRevision));
    }

    private sealed class ThrowingJournal : IDeliveryJournal
    {
        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            throw new IOException("The durable delivery journal is unavailable.");

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            throw new IOException("The durable delivery journal is unavailable.");
    }

    private sealed class CancellingTarget : IDeliveryTarget
    {
        public ValueTask<string?> ObserveCurrentDigestAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<string?>(PreviousDigest);

        public ValueTask<DeliveryMutationResult> ApplyAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            string region,
            CancellationToken cancellationToken) =>
            ValueTask.FromCanceled<DeliveryMutationResult>(Canceled(region, cancellationToken));

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            string region,
            CancellationToken cancellationToken) =>
            ValueTask.FromCanceled<DeliveryHealthResult>(Canceled(region, cancellationToken));

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            IReadOnlyList<string> orderedRegions,
            CancellationToken cancellationToken) =>
            ValueTask.FromCanceled<DeliveryConvergenceResult>(Canceled("converge", cancellationToken));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request,
            string region,
            string targetArtifactDigest,
            CancellationToken cancellationToken) =>
            ValueTask.FromCanceled<DeliveryRollbackResult>(Canceled(region, cancellationToken));

        private static CancellationToken Canceled(string region, CancellationToken cancellationToken)
        {
            var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            source.Cancel();
            return source.Token;
        }
    }

    private sealed class EmptyChecksTarget : IDeliveryTarget
    {
        private string currentDigest = PreviousDigest;

        public ValueTask<string?> ObserveCurrentDigestAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<string?>(currentDigest);

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<DeliveryArtifact?>(new(currentDigest, ValidDigest, "service"));

        public ValueTask<DeliveryMutationResult> ApplyAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Mutate(artifact));

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            // Empty forward evidence fails closed; the exact rollback digest is still checkable.
            Health(artifact, region);

        private ValueTask<DeliveryHealthResult> Health(DeliveryArtifact artifact, string region)
        {
            return ValueTask.FromResult(artifact.Digest == PreviousDigest
                ? new DeliveryHealthResult(true, [new($"{region}-health", DeliveryHealthStatus.Passed)])
                : new DeliveryHealthResult(true, []));
        }

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
            DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> orderedRegions, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryConvergenceResult(true));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request, string region, string targetArtifactDigest, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Restore(targetArtifactDigest));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request,
            string region,
            string targetArtifactDigest,
            string? targetManifestDigest,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Restore(targetArtifactDigest));

        private DeliveryMutationResult Mutate(DeliveryArtifact artifact)
        {
            var previous = currentDigest;
            currentDigest = artifact.Digest!;
            return new(true, true, previous, PreviousManifestDigest: ValidDigest);
        }

        private DeliveryRollbackResult Restore(string targetArtifactDigest)
        {
            currentDigest = targetArtifactDigest;
            return new(true, targetArtifactDigest, new(targetArtifactDigest, ValidDigest, "service"));
        }
    }

    private sealed class LyingHealthTarget : IDeliveryTarget
    {
        private string currentDigest = PreviousDigest;

        public ValueTask<string?> ObserveCurrentDigestAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<string?>(currentDigest);

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult<DeliveryArtifact?>(new(currentDigest, ValidDigest, "service"));

        public ValueTask<DeliveryMutationResult> ApplyAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Mutate(artifact));

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            // Forward evidence lies (Passed=true with a failed check) and must fail closed; the
            // exact rollback digest reports honestly so the rollback can still complete.
            Health(artifact, region);

        private ValueTask<DeliveryHealthResult> Health(DeliveryArtifact artifact, string region)
        {
            return ValueTask.FromResult(artifact.Digest == PreviousDigest
                ? new DeliveryHealthResult(true,
                    [new($"{region}-health", DeliveryHealthStatus.Passed)])
                : new DeliveryHealthResult(true,
                    [new($"{region}-health", DeliveryHealthStatus.Failed)]));
        }

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
            DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> orderedRegions, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryConvergenceResult(true));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request, string region, string targetArtifactDigest, CancellationToken cancellationToken) =>
            ValueTask.FromResult(Restore(targetArtifactDigest));

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request,
            string region,
            string targetArtifactDigest,
            string? targetManifestDigest,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Restore(targetArtifactDigest));

        private DeliveryMutationResult Mutate(DeliveryArtifact artifact)
        {
            var previous = currentDigest;
            currentDigest = artifact.Digest!;
            return new(true, true, previous, PreviousManifestDigest: ValidDigest);
        }

        private DeliveryRollbackResult Restore(string targetArtifactDigest)
        {
            currentDigest = targetArtifactDigest;
            return new(true, targetArtifactDigest, new(targetArtifactDigest, ValidDigest, "service"));
        }
    }

    private sealed class TargetResolver : IDeliveryTargetResolver
    {
        private readonly IDeliveryTarget _target;

        public TargetResolver(IDeliveryTarget target) => _target = target;

        public ValueTask<IDeliveryTarget?> ResolveAsync(DeliveryTarget target, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IDeliveryTarget?>(_target);
    }

    private sealed class ArtifactBuilder(string digest) : IDeliveryArtifactBuilder
    {
        public ValueTask<DeliveryArtifact?> BuildAsync(DeliveryRequest request, DeliverySource source,
            CancellationToken cancellationToken) => ValueTask.FromResult<DeliveryArtifact?>(
                new(digest, ValidDigest, "service"));
    }

    private sealed class RecordingTarget : IDeliveryTarget
    {
        public List<string> Calls { get; } = [];
        public string? FailHealthInRegion { get; init; }
        public string? FailRollbackInRegion { get; init; }
        public string? FailRollbackHealthInRegion { get; init; }
        private readonly Dictionary<string, string?> currentDigests = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string?> currentManifests = new(StringComparer.Ordinal);
        /// <summary>When set, ApplyAsync throws after mutating (crash-window simulation).</summary>
        public bool CrashAfterApply { get; set; }

        /// <summary>Seeds one region's pre-delivery digest (defaults to the previous digest).</summary>
        public void SeedCurrentDigest(string region, string? digest) =>
            currentDigests[region] = digest;

        public void SeedCurrentArtifact(string region, string? digest, string? manifestDigest)
        {
            currentDigests[region] = digest;
            currentManifests[region] = manifestDigest;
        }

        /// <summary>Reads one region's current digest (its post-apply value after delivery).</summary>
        public string? CurrentDigestOf(string region) =>
            currentDigests.TryGetValue(region, out var digest) ? digest : null;

        /// <summary>The exact digests RollbackAsync was asked to restore, per region.</summary>
        public List<(string Region, string Digest)> RollbackDigests { get; } = [];

        public List<(string Region, string ManifestDigest)> RollbackManifests { get; } = [];

        /// <summary>The recorded calls joined for assertions (test helper).</summary>
        public string CallsIfAny() => string.Join('|', Calls);

        private string? CurrentOf(string region) =>
            currentDigests.TryGetValue(region, out var digest) ? digest : PreviousDigest;

        private string? CurrentManifestOf(string region) =>
            currentManifests.TryGetValue(region, out var manifest) ? manifest : PreviousDigest;

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken)
        {
            Calls.Add($"observe:{region}");
            // Adapter contract: null means the region has no deployed artifact yet (pristine).
            var digest = CurrentOf(region);
            return ValueTask.FromResult<DeliveryArtifact?>(digest is null
                ? null
                : new DeliveryArtifact(digest, CurrentManifestOf(region), "service"));
        }

        public ValueTask<string?> ObserveCurrentDigestAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken)
        {
            Calls.Add($"observe:{region}");
            return ValueTask.FromResult(CurrentOf(region));
        }

        public ValueTask<DeliveryMutationResult> ApplyAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken)
        {
            Calls.Add($"apply:{region}");
            var previous = CurrentOf(region);
            currentDigests[region] = artifact.Digest;
            currentManifests[region] = artifact.ManifestDigest;
            if (CrashAfterApply)
                throw new IOException("simulated crash between apply and applied-persist");
            return ValueTask.FromResult(previous is not null &&
                string.Equals(previous, artifact.Digest, StringComparison.OrdinalIgnoreCase)
                    ? new DeliveryMutationResult(true, false, null)
                    : new DeliveryMutationResult(true, true, previous));
        }

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken)
        {
            var rollback = artifact.Digest == PreviousDigest;
            Calls.Add(rollback ? $"rollback-health:{region}" : $"health:{region}");
            var failed = rollback ? region == FailRollbackHealthInRegion : region == FailHealthInRegion;
            return ValueTask.FromResult(new DeliveryHealthResult(!failed,
                [new($"{region}-health", failed ? DeliveryHealthStatus.Failed : DeliveryHealthStatus.Passed)]));
        }

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> orderedRegions, CancellationToken cancellationToken)
        {
            Calls.Add(artifact.Digest == PreviousDigest ? "rollback-converge" : "converge");
            return ValueTask.FromResult(new DeliveryConvergenceResult(true));
        }

        public ValueTask<DeliveryRollbackResult> RollbackAsync(DeliveryRequest request, string region, string targetArtifactDigest, CancellationToken cancellationToken)
        {
            return RollbackAsync(request, region, targetArtifactDigest, null, cancellationToken);
        }

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request,
            string region,
            string targetArtifactDigest,
            string? targetManifestDigest,
            CancellationToken cancellationToken)
        {
            Calls.Add($"rollback:{region}");
            RollbackDigests.Add((region, targetArtifactDigest));
            RollbackManifests.Add((region, targetManifestDigest ?? targetArtifactDigest));
            currentDigests[region] = targetArtifactDigest;
            currentManifests[region] = targetManifestDigest ?? targetArtifactDigest;
            return ValueTask.FromResult(new DeliveryRollbackResult(
                region != FailRollbackInRegion,
                targetArtifactDigest,
                new(targetArtifactDigest, targetManifestDigest ?? targetArtifactDigest, "service")));
        }
    }
}
