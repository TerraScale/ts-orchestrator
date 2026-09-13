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
        // The receipt names BOTH artifact identities of the exact delivered artifact (AC1): the
        // digest alone cannot prove which manifest-bearing artifact ran.
        var receiptJson = DeliveryWireCodec.SerializeReceipt(SuccessReceipt());
        await Assert.That(receiptJson).Contains("\"artifactDigest\":");
        await Assert.That(receiptJson).Contains("\"artifactManifestDigest\":");
        await Assert.That(SuccessReceipt().ArtifactManifestDigest).IsEqualTo(ValidDigest);
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
        await Assert.That(receipt.SchemaVersion).IsEqualTo(1);
        await Assert.That(receipt.ArtifactDigest).IsEqualTo(ArtifactDigest);
        await Assert.That(receipt.ArtifactManifestDigest).IsEqualTo(ValidDigest);
        await Assert.That(receipt.AuditId).IsEqualTo("audit-test");
        await Assert.That(receipt.Provenance.ConfigurationRevision).IsEqualTo(ValidDigest);
        await Assert.That(journal.Records[^1].Receipt).IsEqualTo(receipt);
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
    public async Task Duplicate_json_properties_fail_before_authorization_or_mutation()
    {
        var target = new RecordingTarget();
        var coordinator = Coordinator(target, new InMemoryDeliveryJournal(), authorized: false);
        var duplicate = DeliveryWireCodec.SerializeRequest(Request())
            .Replace("\"operationId\":\"operation-1\"", "\"operationId\":\"operation-1\",\"operationId\":\"operation-1\"", StringComparison.Ordinal);

        var receipt = await coordinator.DeliverJsonAsync(duplicate);

        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
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
        // AC4: even a failed rollback names the exact digest (and manifest identity) the
        // operator must restore, with bounded remediation text.
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(receipt.Rollback.TargetManifestDigest).IsEqualTo(PreviousDigest);
        await Assert.That(receipt.Error.Remediation).Contains("Restore the recorded target artifact digest");
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
    public async Task Same_operation_id_with_a_different_configuration_or_migration_revision_fails_closed()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal);

        _ = await coordinator.DeliverAsync(Request());
        var configurationConflict = await coordinator.DeliverAsync(Request() with
        {
            ConfigurationRevision = OtherArtifactDigest,
        });
        var migrationConflict = await coordinator.DeliverAsync(Request() with
        {
            MigrationRevision = OtherArtifactDigest,
        });

        // The configuration and migration revisions are part of the canonical request
        // fingerprint: an operationId admitted for one configuration can never be replayed
        // against another (AC3), even though every other field is identical.
        await Assert.That(configurationConflict.Error.Code).IsEqualTo(DirectDeliveryErrorCode.OperationConflict);
        await Assert.That(configurationConflict.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(migrationConflict.Error.Code).IsEqualTo(DirectDeliveryErrorCode.OperationConflict);
        await Assert.That(migrationConflict.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
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
        // M2: a post-build denial still names the full artifact identity pair, exactly like the
        // pre-change receipts named the digest — the pair rule never silently drops it.
        await Assert.That(staleReceipt.ArtifactDigest).IsEqualTo(ArtifactDigest);
        await Assert.That(staleReceipt.ArtifactManifestDigest).IsEqualTo(ValidDigest);
        await Assert.That(unverifiedReceipt.ArtifactDigest).IsEqualTo(ArtifactDigest);
        await Assert.That(unverifiedReceipt.ArtifactManifestDigest).IsEqualTo(ValidDigest);
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
    public async Task A_corrupt_journal_record_fails_closed_as_unavailability_without_mutation()
    {
        var target = new RecordingTarget();
        var coordinator = Coordinator(target, new CorruptJournal());

        var receipt = await coordinator.DeliverAsync(Request());

        // Corruption is an operational condition of the durable boundary, not a verdict on the
        // request: it surfaces as the bounded, actionable journal_unavailable failure with a
        // stable catalog code, and the target is never mutated on its way out.
        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        await Assert.That(target.Calls).IsEmpty();
        // A record this build's codec cannot round-trip is NOT a journal-health problem: the
        // remediation must say the record predates the codec and cannot be replayed — never
        // "restore journal health and retry", which can never succeed against these bytes.
        await Assert.That(receipt.Error.Remediation).Contains("predates the current record codec");
        await Assert.That(receipt.Error.Remediation).Contains("clear or drain");
        await Assert.That(receipt.Error.Remediation).DoesNotContain("replays its durable progress");
        // M2: the post-build failure receipt still names the full artifact identity pair.
        await Assert.That(receipt.ArtifactDigest).IsEqualTo(ArtifactDigest);
        await Assert.That(receipt.ArtifactManifestDigest).IsEqualTo(ValidDigest);
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
            // The journal claims both regions are already healthy with this artifact, so the
            // target is seeded to actually run it: the replayed convergence must verify it.
            target.SeedCurrentDigest("gru", ArtifactDigest);
            target.SeedCurrentDigest("sfo", ArtifactDigest);
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
            provenance: new ProvenanceVerifier(verified: false));

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
    public async Task ExpiredCredentialsAndProviderTimeoutsReportDistinctOperatorActions()
    {
        // Expired credential drill: an authentication-class boundary failure is a denial with a
        // bounded remediation, never a transient retry code an operator would wait out.
        var expiredAuthorization = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            authorizer: new ThrowingAuthorizer(new UnauthorizedAccessException("provider token expired")))
            .DeliverAsync(Request());
        var expiredProvenance = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            provenance: new ThrowingProvenance(new UnauthorizedAccessException("evidence token expired")))
            .DeliverAsync(Request());

        // Provider timeout drill: a timed-out boundary is transient infrastructure, reported as
        // retryable and distinct from both the denial above and a target failure.
        var timedOutAuthorization = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            authorizer: new ThrowingAuthorizer(new TimeoutException("authorization boundary timed out")))
            .DeliverAsync(Request());
        var timedOutProvenance = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            provenance: new ThrowingProvenance(new TimeoutException("evidence source timed out")))
            .DeliverAsync(Request());

        await Assert.That(expiredAuthorization.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.UnauthorizedActor);
        await Assert.That(expiredProvenance.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.ProvenanceFailed);
        await Assert.That(timedOutAuthorization.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.AuthorizationUnavailable);
        await Assert.That(timedOutProvenance.Error.Code)
            .IsEqualTo(DirectDeliveryErrorCode.ProvenanceUnavailable);
    }

    [Test]
    public async Task AProviderPartitionOnALaterRegionRollsBackTheEarlierRegionsAndJournalsIt()
    {
        // Partition drill at the provider boundary: the journal stays reachable while one
        // region's target adapter is unreachable mid-apply. The write-ahead was durably
        // recorded, so the region carries rollback debt, the earlier mutated region is rolled
        // back to its recorded previous digests, and the failure is the typed mutation failure.
        var target = new RecordingTarget { PartitionApplyInRegion = "sfo" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        await Assert.That(receipt.Rollback.Attempted).IsTrue();
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        // The healthy region was restored; the partitioned region was never mutated — the
        // adapter recorded no write for it (its durable write-ahead target was never spent).
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsNull();
        await Assert.That(target.Calls.Any(static call => call.StartsWith("rollback:", StringComparison.Ordinal)))
            .IsTrue();
        var record = await journal.ReadAsync("operation-1", CancellationToken.None);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
        await Assert.That(record.Receipt!.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        await Assert.That(record.Regions!.Select(static region => (region.Region, region.State)))
            .IsEquivalentTo(new[] { ("gru", "rollback_succeeded"), ("sfo", "rollback_succeeded") });
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

    [Test]
    public async Task Rollback_convergence_verifies_each_region_against_its_own_recorded_previous_digest()
    {
        // M5: regions can legitimately hold DISTINCT previous digests; convergence after
        // rollback must verify each region against its own write-ahead digest, not one digest
        // across every region.
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        target.SeedCurrentArtifact("gru", AltPreviousDigest, AltPreviousManifestDigest);
        target.SeedCurrentArtifact("sfo", PreviousDigest, PreviousManifestDigest);
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        // The receipt's single rollback target names the first reverse-order region's digest.
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(receipt.Rollback.TargetManifestDigest).IsEqualTo(PreviousManifestDigest);
        await Assert.That(target.RollbackDigests).IsEquivalentTo([
            ("gru", AltPreviousDigest),
            ("sfo", PreviousDigest),
        ]);
        await Assert.That(target.ConvergenceCalls).IsEquivalentTo([
            (new[] { "gru" }, AltPreviousDigest),
            (new[] { "sfo" }, PreviousDigest),
        ]);
    }

    [Test]
    public async Task Rollback_convergence_keeps_the_shared_fast_path_when_every_region_shares_one_previous_digest()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.ConvergenceCalls.Count).IsEqualTo(1);
        await Assert.That(target.ConvergenceCalls[0].Regions).IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(target.ConvergenceCalls[0].Digest).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Failed_rollback_convergence_demotes_completed_regions_and_reports_failed()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo", FailRollbackConvergence = true };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Failed);
        // Both mutations really rolled back, but convergence is part of the rollback gate: the
        // durable progress must not claim rollback_succeeded.
        await Assert.That(journal.Records[^1].Regions!.Select(static region => region.State))
            .IsEquivalentTo(["rollback_failed", "rollback_failed"]);
    }

    [Test]
    public async Task A_throwing_or_cancelled_rollback_convergence_is_contained_as_a_rollback_failure()
    {
        foreach (var (throwing, cancelling) in new[] { (true, false), (false, true) })
        {
            var target = new RecordingTarget
            {
                FailHealthInRegion = "sfo",
                ThrowRollbackConvergence = throwing,
                CancelRollbackConvergence = cancelling,
            };
            var journal = new InMemoryDeliveryJournal();

            var receipt = await Coordinator(target, journal).DeliverAsync(Request());

            await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
            await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
            await Assert.That(journal.Records[^1].Regions!.Select(static region => region.State))
                .IsEquivalentTo(["rollback_failed", "rollback_failed"]);
        }
    }

    [Test]
    public async Task A_concurrent_mutation_racing_the_fence_is_not_applied_not_rolled_back_and_typed()
    {
        // E11: a concurrent writer mutates sfo between the write-ahead observation and the
        // fenced apply. The adapter must refuse the mutation, the region must keep the
        // concurrent writer's digest, only genuinely mutated regions roll back, and the
        // receipt must carry the typed mutation-race code with bounded remediation.
        var target = new RecordingTarget { ConcurrentMutationInRegion = "sfo" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationRace);
        await Assert.That(receipt.Error.Remediation).Contains("new delivery request");
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Succeeded);
        await Assert.That(target.RollbackDigests.Select(static digest => digest.Region))
            .IsEquivalentTo(["gru"]);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(OtherArtifactDigest);
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "sfo").State)
            .IsEqualTo(DeliveryJournalState.Failed);
        await Assert.That(regions.Single(static region => region.Region == "sfo").ErrorCode)
            .IsEqualTo(DirectDeliveryErrorCode.MutationRace);
        await Assert.That(regions.Single(static region => region.Region == "gru").State)
            .IsEqualTo("rollback_succeeded");
    }

    [Test]
    public async Task A_mutation_race_on_the_first_region_fails_without_any_rollback()
    {
        var target = new RecordingTarget { ConcurrentMutationInRegion = "gru" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationRace);
        await Assert.That(receipt.Rollback.Attempted).IsFalse();
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.NotRequired);
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("rollback", StringComparison.Ordinal))).IsFalse();
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(OtherArtifactDigest);
    }

    [Test]
    public async Task A_fenced_apply_treats_a_region_already_at_the_requested_digest_as_a_noop()
    {
        // The crash-replay shape: the region already runs the requested artifact, so the fence
        // must converge instead of reporting a race, and no rollback target is recorded.
        var target = new RecordingTarget();
        target.SeedCurrentArtifact("gru", ArtifactDigest, ValidDigest);
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "gru").PreviousArtifactDigest)
            .IsNull();
        await Assert.That(regions.Single(static region => region.Region == "sfo").PreviousArtifactDigest)
            .IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task An_adapter_previous_digest_disagreeing_with_the_write_ahead_never_rewrites_it()
    {
        // An unfenced adapter whose reported previous digest disagrees with the durable
        // write-ahead (it raced) must not overwrite the durable rollback material.
        var target = new RecordingTarget { ReportRacedPrevious = true };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(journal.Records[^1].Regions!.Select(static region => region.PreviousArtifactDigest!))
            .IsEquivalentTo([PreviousDigest, PreviousDigest]);
    }

    [Test]
    public async Task Mid_rollback_journal_failure_completes_the_rollback_and_surfaces_the_degraded_state()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var flaky = new RollbackProgressFilteredJournal();

        var receipt = await Coordinator(target, flaky).DeliverAsync(Request());

        // The degraded journal never aborts the in-progress rollback: both regions are really
        // restored, and the receipt says the record is not durable yet.
        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Remediation).Contains("journal currently unavailable");
        await Assert.That(target.RollbackDigests.Select(static digest => digest.Region))
            .IsEquivalentTo(["gru", "sfo"]);
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(PreviousDigest);

        // Replay against a recovered journal converges from the durable progress.
        var healthy = new InMemoryDeliveryJournal();
        foreach (var record in flaky.Records) await healthy.AppendAsync(record, default);
        var replayTarget = new RecordingTarget { FailHealthInRegion = "sfo" };
        replayTarget.SeedCurrentDigest("gru", PreviousDigest);
        replayTarget.SeedCurrentDigest("sfo", PreviousDigest);

        var replay = await Coordinator(replayTarget, healthy).DeliverAsync(Request());

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(replayTarget.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        await Assert.That(replayTarget.CurrentDigestOf("sfo")).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task A_completed_rollback_whose_receipt_never_persisted_converges_on_replay_without_reapplying()
    {
        // The terminal rolled-back receipt append fails: the receipt is still returned, and a
        // replay must converge to rolled_back through recovery — re-applying the artifact over
        // a finished rollback would destroy the recovery the journal owes.
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var flaky = new ReceiptFilteredJournal();

        var receipt = await Coordinator(target, flaky).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Remediation).Contains("journal currently unavailable");
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(PreviousDigest);

        var healthy = new InMemoryDeliveryJournal();
        foreach (var record in flaky.Records) await healthy.AppendAsync(record, default);
        var replayTarget = new RecordingTarget();
        replayTarget.SeedCurrentDigest("gru", PreviousDigest);
        replayTarget.SeedCurrentDigest("sfo", PreviousDigest);

        var replay = await Coordinator(replayTarget, healthy).DeliverAsync(Request());

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(string.Join('|', replayTarget.Calls)).IsEqualTo("rollback-converge");
    }

    [Test]
    public async Task Cancellation_during_rollback_bookkeeping_returns_the_receipt_and_keeps_the_target()
    {
        // Cancellation-shaped journal failures mid-rollback must degrade to best-effort
        // bookkeeping: the rollback finishes, the receipt is returned (never thrown), and the
        // durable write-ahead keeps the recovery target.
        var target = new RecordingTarget { FailHealthInRegion = "sfo" };
        var journal = new CancelledRollbackJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Remediation).Contains("journal currently unavailable");
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Adapter_cancellation_at_the_rollback_point_is_durable_and_resumes_to_rolled_back()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo", CancelRollback = true };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        // Every rollback attempt failed, and the receipt still names the exact digest to
        // restore from the durable write-ahead record.
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousDigest);
        await Assert.That(receipt.Rollback.TargetManifestDigest).IsEqualTo(PreviousDigest);
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Select(static region => region.ErrorCode!))
            .IsEquivalentTo([DirectDeliveryErrorCode.Cancelled, DirectDeliveryErrorCode.Cancelled]);

        // Recovery after the dependency returns: the same operationId resumes the rollback.
        var replayTarget = new RecordingTarget();
        replayTarget.SeedCurrentDigest("gru", ArtifactDigest);
        replayTarget.SeedCurrentDigest("sfo", ArtifactDigest);

        var replay = await Coordinator(replayTarget, journal).DeliverAsync(Request());

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(replayTarget.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task Boundary_cancellation_before_any_mutation_reports_cancelled()
    {
        var authorization = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            authorizer: new ThrowingAuthorizer(new OperationCanceledException()))
            .DeliverAsync(Request());
        var provenance = await Coordinator(
            new RecordingTarget(),
            new InMemoryDeliveryJournal(),
            provenance: new ThrowingProvenance(new OperationCanceledException()))
            .DeliverAsync(Request());

        await Assert.That(authorization.Error.Code).IsEqualTo(DirectDeliveryErrorCode.Cancelled);
        await Assert.That(provenance.Error.Code).IsEqualTo(DirectDeliveryErrorCode.Cancelled);
    }

    [Test]
    public async Task Malformed_mutation_results_fail_closed()
    {
        var nulled = await Coordinator(
            new RecordingTarget { ApplyNullResult = true }, new InMemoryDeliveryJournal()).DeliverAsync(Request());
        var failed = await Coordinator(
            new RecordingTarget { ApplyFailedResult = true }, new InMemoryDeliveryJournal()).DeliverAsync(Request());
        var invalidPrevious = await Coordinator(
            new RecordingTarget { ApplyInvalidPrevious = true }, new InMemoryDeliveryJournal()).DeliverAsync(Request());
        var throwingObserve = await Coordinator(
            new RecordingTarget { ThrowObserveInRegion = "gru" }, new InMemoryDeliveryJournal()).DeliverAsync(Request());
        var invalidObserve = await Coordinator(
            new RecordingTarget { ObserveInvalidDigests = true }, new InMemoryDeliveryJournal()).DeliverAsync(Request());

        await Assert.That(nulled.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        await Assert.That(failed.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        // An unprovable previous digest makes the mutation unsafe to leave unrecoverable.
        await Assert.That(invalidPrevious.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(throwingObserve.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        await Assert.That(invalidObserve.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
    }

    [Test]
    public async Task An_apply_that_throws_after_mutating_still_rolls_back_to_the_write_ahead_digest()
    {
        var target = new RecordingTarget
        {
            CrashAfterApply = true,
            ApplyException = new IOException("provider-detail Bearer sekrit-token-123"),
        };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.MutationFailed);
        await Assert.That(target.RollbackDigests).IsEquivalentTo([("gru", PreviousDigest)]);
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Health_check_exceptions_are_health_failures_with_rollback()
    {
        var forward = new RecordingTarget { ThrowHealthInRegion = "sfo" };
        var forwardReceipt = await Coordinator(forward, new InMemoryDeliveryJournal()).DeliverAsync(Request());
        var rollback = new RecordingTarget { FailHealthInRegion = "sfo", ThrowRollbackHealthInRegion = "gru" };
        var rollbackReceipt = await Coordinator(rollback, new InMemoryDeliveryJournal()).DeliverAsync(Request());

        await Assert.That(forwardReceipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(forwardReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.HealthFailed);
        await Assert.That(rollbackReceipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(rollbackReceipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
    }

    [Test]
    public async Task A_rollback_observing_a_foreign_digest_fails_without_mutating_the_region()
    {
        // An external writer replaced sfo after its failed health check: the rollback
        // observation sees neither the requested nor the recorded previous digest, so the
        // region is left to its new owner instead of being clobbered by our rollback.
        var target = new RecordingTarget { FailHealthInRegion = "sfo", ForeignDigestAtRollbackRegion = "sfo" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(target.RollbackDigests.Select(static digest => digest.Region))
            .IsEquivalentTo(["gru"]);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(OtherArtifactDigest);
    }

    [Test]
    public async Task A_rollback_result_that_does_not_match_the_requested_digest_fails_closed()
    {
        var target = new RecordingTarget { FailHealthInRegion = "sfo", CorruptRollbackResultRegion = "gru" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.RollbackFailed);
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Failed);
        await Assert.That(journal.Records[^1].Regions!.Single(static region => region.Region == "gru").State)
            .IsEqualTo("rollback_failed");
    }

    [Test]
    public async Task Restart_mid_rollback_resumes_from_durable_progress_without_reapplying()
    {
        var journal = new InMemoryDeliveryJournal();
        var request = Request();
        await journal.AppendAsync(new(
            request.OperationId!,
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.RollingBack,
            null,
            ArtifactDigest,
            [
                new DeliveryRegionProgress("gru", "rollback_succeeded", AltPreviousDigest, null, AltPreviousManifestDigest),
                new DeliveryRegionProgress("sfo", "rollback_failed", PreviousDigest, null, PreviousManifestDigest),
            ]), default);
        var target = new RecordingTarget();
        target.SeedCurrentArtifact("gru", AltPreviousDigest, AltPreviousManifestDigest);
        target.SeedCurrentArtifact("sfo", ArtifactDigest, ValidDigest);

        var receipt = await Coordinator(target, journal).DeliverAsync(request);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
        await Assert.That(target.RollbackDigests).IsEquivalentTo([("sfo", PreviousDigest)]);
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(AltPreviousDigest);
        await Assert.That(target.CurrentDigestOf("sfo")).IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Adapter_secret_material_never_reaches_receipts()
    {
        const string token = "sekrit-token-123";
        const string customer = "customer-acct-99";
        const string raw = "raw-provider-response-body";
        var receipts = new List<DeliveryReceipt>
        {
            await Coordinator(
                    new RecordingTarget(),
                    new InMemoryDeliveryJournal(),
                    authorizer: new ThrowingAuthorizer(new IOException($"Bearer {token}")))
                .DeliverAsync(Request()),
            await Coordinator(
                    new RecordingTarget(),
                    new InMemoryDeliveryJournal(),
                    provenance: new ThrowingProvenance(new IOException($"{customer} {raw}")))
                .DeliverAsync(Request()),
            await Coordinator(new RecordingTarget(), new ThrowingJournal()).DeliverAsync(Request()),
            await Coordinator(
                    new RecordingTarget
                    {
                        CrashAfterApply = true,
                        ApplyException = new IOException($"Bearer {token} {customer}"),
                    },
                    new InMemoryDeliveryJournal())
                .DeliverAsync(Request()),
            await Coordinator(
                    new RecordingTarget { FailHealthInRegion = "sfo", ThrowRollbackHealthInRegion = "gru" },
                    new InMemoryDeliveryJournal())
                .DeliverAsync(Request()),
        };

        foreach (var receipt in receipts)
        {
            var json = DeliveryWireCodec.SerializeReceipt(receipt);
            await Assert.That(json).DoesNotContain(token);
            await Assert.That(json).DoesNotContain(customer);
            await Assert.That(json).DoesNotContain(raw);
            await Assert.That(json).DoesNotContain("Bearer");
            await Assert.That(json).DoesNotContain("provider-detail");
        }
    }

    [Test]
    public async Task Cancellation_after_a_landed_mutation_collects_its_write_ahead_debt()
    {
        // The mutation landed, then a cancel-shaped failure hit before the 'applied' persist:
        // the write-ahead debt must drive a rollback (the region is restored), never a silent
        // unhealth-checked deployment.
        var target = new RecordingTarget { CrashAfterApply = true, ApplyException = new OperationCanceledException() };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.RollbackDigests).IsEquivalentTo([("gru", PreviousDigest)]);
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "gru").State)
            .IsEqualTo("rollback_succeeded");
        await Assert.That(regions.Single(static region => region.Region == "gru").PreviousArtifactDigest)
            .IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task Cancelled_rollback_after_a_landed_mutation_keeps_the_cancelled_code_and_debt()
    {
        // The mutation landed, a cancel-shaped failure followed, and the rollback was also
        // cancelled: the receipt keeps the replayable 'cancelled' code (the rollback failed
        // only because everything was cancelled), the debt is durable as rollback progress,
        // and a retry resumes the rollback — never a re-apply.
        var target = new RecordingTarget
        {
            CrashAfterApply = true,
            ApplyException = new OperationCanceledException(),
            CancelRollback = true,
        };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.Cancelled);
        var regions = journal.Records[^1].Regions!;
        var gru = regions.Single(static region => region.Region == "gru");
        await Assert.That(gru.State).IsEqualTo("rollback_failed");
        await Assert.That(gru.ErrorCode).IsEqualTo(DirectDeliveryErrorCode.Cancelled);
        await Assert.That(gru.PreviousArtifactDigest).IsEqualTo(PreviousDigest);

        // Recovery: the same operationId resumes and completes the rollback.
        var replayTarget = new RecordingTarget();
        replayTarget.SeedCurrentDigest("gru", ArtifactDigest);
        replayTarget.SeedCurrentDigest("sfo", PreviousDigest);
        var replay = await Coordinator(replayTarget, journal).DeliverAsync(Request());

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(replayTarget.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task A_cancelled_apply_that_never_landed_collects_its_debt_idempotently()
    {
        // The apply was cancelled before mutating, but its write-ahead was already durable:
        // recording the debt is safe because collection is idempotent — the rollback observes
        // the region already at its previous digest and converges without a second mutation.
        var target = new RecordingTarget { CancelApplyInRegion = "gru" };
        var journal = new InMemoryDeliveryJournal();

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.RollbackDigests).IsEmpty();
        // The region was never mutated: no digest was ever recorded for it.
        await Assert.That(target.CurrentDigestOf("gru")).IsNull();
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "gru").State)
            .IsEqualTo("rollback_succeeded");
    }

    [Test]
    public async Task Cancellation_escaping_a_progress_persist_still_returns_a_receipt_with_debt()
    {
        // The 'applied' progress persist itself is cancelled after the mutation landed: the
        // escaped cancellation is contained into the failure path (debt, best-effort durable
        // progress, terminal receipt) instead of throwing out of the coordinator.
        var target = new RecordingTarget();
        var journal = new CancelOnStateJournal("applied");

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.CurrentDigestOf("gru")).IsEqualTo(PreviousDigest);
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "gru").State)
            .IsEqualTo("rollback_succeeded");
        await Assert.That(regions.Single(static region => region.Region == "gru").PreviousArtifactDigest)
            .IsEqualTo(PreviousDigest);
    }

    [Test]
    public async Task A_continuity_conflict_surfaces_a_distinct_remediation_not_journal_repair()
    {
        var target = new RecordingTarget();
        var journal = new ConflictOnStateJournal("applied");

        var receipt = await Coordinator(target, journal).DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        await Assert.That(receipt.Error.Message).Contains("conflicting progress append");
        await Assert.That(receipt.Error.Remediation).Contains("Reconcile the region state");
        await Assert.That(receipt.Error.Remediation).DoesNotContain("Restore journal health");
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

    /// <summary>Fails appends whose record state matches the filter; everything else persists.</summary>
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

        public IReadOnlyList<DeliveryJournalRecord> Records => inner.Records;

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.Receipt is not null
                ? ValueTask.FromException(new IOException("journal degraded"))
                : inner.AppendAsync(record, cancellationToken);
    }

    /// <summary>
    /// Fails every append whose regions entered a rollback phase: the failure record persists,
    /// then all rollback bookkeeping (and the rollback receipt) hits a degraded journal.
    /// </summary>
    private sealed class RollbackProgressFilteredJournal : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public IReadOnlyList<DeliveryJournalRecord> Records => inner.Records;

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            IsRollback(record)
                ? ValueTask.FromException(new IOException("journal degraded during rollback"))
                : inner.AppendAsync(record, cancellationToken);

        internal static bool IsRollback(DeliveryJournalRecord record) =>
            record.Regions?.Any(static region =>
                region.State is "rolling_back" or "rollback_failed" or "rollback_succeeded" or "rollback_pending") == true;
    }

    /// <summary>
    /// Cancels every append whose regions entered a rollback phase: cancellation-shaped journal
    /// failures mid-rollback must degrade to best-effort bookkeeping, never abort the rollback.
    /// </summary>
    private sealed class CancelledRollbackJournal : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            RollbackProgressFilteredJournal.IsRollback(record)
                ? ValueTask.FromException(new OperationCanceledException())
                : inner.AppendAsync(record, cancellationToken);
    }

    /// <summary>
    /// Cancels the append whose record state matches the filter: a cancelled progress persist
    /// after a landed mutation must be contained, never escape the coordinator.
    /// </summary>
    private sealed class CancelOnStateJournal(string failingState) : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public IReadOnlyList<DeliveryJournalRecord> Records => inner.Records;

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.State == failingState
                ? ValueTask.FromException(new OperationCanceledException())
                : inner.AppendAsync(record, cancellationToken);
    }

    /// <summary>Throws the typed continuity conflict on the append whose record state matches.</summary>
    private sealed class ConflictOnStateJournal(string failingState) : IDeliveryJournal
    {
        private readonly InMemoryDeliveryJournal inner = new();

        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            inner.ReadAsync(operationId, cancellationToken);

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            record.State == failingState
                ? ValueTask.FromException(new DirectDeliveryJournalConflictException())
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

    [Test]
    public async Task A_delivery_touches_only_its_selected_regions()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal);

        // The resolver serves both regions, but this request selects gru only: no observe,
        // mutation, health, or convergence interaction may reach an unselected region, and the
        // durable progress must not index it.
        var receipt = await coordinator.DeliverAsync(Request() with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru"]),
        });

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo("observe:gru|apply:gru|health:gru|converge");
        await Assert.That(journal.Records[^1].Regions!.Select(static region => region.Region))
            .IsEquivalentTo(["gru"]);
        await Assert.That(receipt.Target!.Regions).IsEquivalentTo(["gru"]);
    }

    [Test]
    public async Task A_stale_authority_is_fenced_before_any_mutation_or_journal_admission()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal,
            authorityIsCurrent: static _ => false);

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.AuthorityFenced);
        await Assert.That(target.Calls).IsEmpty();
        await Assert.That(journal.Records).IsEmpty();
    }

    [Test]
    public async Task Authority_lost_mid_apply_fences_the_remaining_regions_and_the_rollback()
    {
        var target = new RecordingTarget();
        var journal = new InMemoryDeliveryJournal();
        var coordinator = Coordinator(target, journal,
            // Current until the first region's mutation begins, then lost for the rest of the
            // operation: the fence must stop further mutation and, with authority gone, block
            // the rollback of the already-mutated region instead of mutating without authority.
            authorityIsCurrent: _ => !target.Calls.Contains("apply:gru"));

        var receipt = await coordinator.DeliverAsync(Request());

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Rollback.Attempted).IsTrue();
        await Assert.That(receipt.Rollback.Status).IsEqualTo(DeliveryRollbackStatus.Failed);
        await Assert.That(string.Join('|', target.Calls)).DoesNotContain("apply:sfo");
        var regions = journal.Records[^1].Regions!;
        await Assert.That(regions.Single(static region => region.Region == "gru").ErrorCode)
            .IsEqualTo(DirectDeliveryErrorCode.AuthorityFenced);
        // The unmutated region keeps exactly its write-ahead 'applying' record: the durable
        // rollback material was persisted before the fence, and no mutation ever followed it.
        await Assert.That(regions.Single(static region => region.Region == "sfo").State)
            .IsEqualTo(DeliveryJournalState.Applying);
        await Assert.That(regions.Single(static region => region.Region == "sfo").PreviousArtifactDigest)
            .IsEqualTo(PreviousDigest);
    }

    private static DirectDeliveryCoordinator Coordinator(IDeliveryTarget target, IDeliveryJournal journal,
        bool authorized = true, IDeliveryArtifactBuilder? artifactBuilder = null,
        IDeliveryProvenanceVerifier? provenance = null, IDeliveryAuthorizer? authorizer = null,
        Func<DeliveryRequest, bool>? authorityIsCurrent = null) => new(
        authorizer ?? new Authorizer(authorized),
        provenance ?? new ProvenanceVerifier(),
        new TargetResolver(target),
        journal,
        artifactBuilder,
        auditIdFactory: static () => "audit-test",
        authorityIsCurrent: authorityIsCurrent);

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
        "audit-test", new(null, null, null), ValidDigest);

    private const string Commit = "0123456789abcdef0123456789abcdef01234567";
    private const string ValidDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string OtherArtifactDigest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private const string PreviousDigest = ValidDigest;
    private const string PreviousManifestDigest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private const string AltPreviousDigest = "sha256:1032457689abcdef1032457689abcdef1032457689abcdef1032457689abcdef";
    private const string AltPreviousManifestDigest = "sha256:89abcdef89abcdef89abcdef89abcdef89abcdef89abcdef89abcdef89abcdef";

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

    /// <summary>
    /// A journal whose durable bytes are corrupt: the read fails before any record shape is
    /// available, exactly like an unreadable NATS KV entry (InvalidDataException from
    /// NatsDirectDeliveryJournal.ReadAsync).
    /// </summary>
    private sealed class CorruptJournal : IDeliveryJournal
    {
        public ValueTask<DeliveryJournalRecord?> ReadAsync(string operationId, CancellationToken cancellationToken) =>
            throw new InvalidDataException("A direct delivery journal record is invalid.");

        public ValueTask AppendAsync(DeliveryJournalRecord record, CancellationToken cancellationToken) =>
            throw new InvalidDataException("A direct delivery journal record is invalid.");
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
        /// <summary>When set, a concurrent writer mutates this region inside the observe→apply window (mutation-race simulation).</summary>
        public string? ConcurrentMutationInRegion { get; init; }
        /// <summary>
        /// When set, the fenced apply for this region throws an infrastructure failure BEFORE
        /// mutating (provider partition/timeout drill): the journal stays reachable while one
        /// region's provider boundary cannot be reached.
        /// </summary>
        public string? PartitionApplyInRegion { get; init; }
        /// <summary>When set, the fenced/unfenced apply for this region is cancelled before mutating.</summary>
        public string? CancelApplyInRegion { get; init; }
        /// <summary>When set, the fenced/unfenced apply reports a raced previous digest that disagrees with the durable write-ahead.</summary>
        public bool ReportRacedPrevious { get; init; }
        /// <summary>When set, rollback convergence reports non-convergence.</summary>
        public bool FailRollbackConvergence { get; init; }
        /// <summary>When set, rollback convergence throws an infrastructure failure.</summary>
        public bool ThrowRollbackConvergence { get; init; }
        /// <summary>When set, rollback convergence is cancelled.</summary>
        public bool CancelRollbackConvergence { get; init; }
        /// <summary>When set, an external writer replaces this region's digest right after its forward health check fails.</summary>
        public string? ForeignDigestAtRollbackRegion { get; init; }
        /// <summary>When set, RollbackAsync reports success with a different artifact than the requested rollback target.</summary>
        public string? CorruptRollbackResultRegion { get; init; }
        /// <summary>When set, ObserveCurrentArtifactAsync throws for the matching region.</summary>
        public string? ThrowObserveInRegion { get; init; }
        /// <summary>When set, observation reports digest shapes that are not valid digests.</summary>
        public bool ObserveInvalidDigests { get; init; }
        /// <summary>When set, the forward health check throws for the matching region.</summary>
        public string? ThrowHealthInRegion { get; init; }
        /// <summary>When set, the rollback health check throws for the matching region.</summary>
        public string? ThrowRollbackHealthInRegion { get; init; }
        /// <summary>When set, ApplyAsync returns null (an adapter that lost its result).</summary>
        public bool ApplyNullResult { get; init; }
        /// <summary>When set, ApplyAsync reports an unsuccessful mutation.</summary>
        public bool ApplyFailedResult { get; init; }
        /// <summary>When set, ApplyAsync reports a mutated result with an invalid previous digest.</summary>
        public bool ApplyInvalidPrevious { get; init; }
        /// <summary>When set, every rollback mutation is cancelled.</summary>
        public bool CancelRollback { get; init; }
        /// <summary>The exception ApplyAsync throws after mutating, when <see cref="CrashAfterApply"/> is set.</summary>
        public Exception? ApplyException { get; init; }
        private readonly Dictionary<string, string?> currentDigests = new(StringComparer.Ordinal);
        private readonly Dictionary<string, string?> currentManifests = new(StringComparer.Ordinal);
        /// <summary>When set, ApplyAsync throws after mutating (crash-window simulation).</summary>
        public bool CrashAfterApply { get; set; }

        /// <summary>Every convergence invocation: the ordered regions it covered and the digest it verified.</summary>
        public List<(string[] Regions, string Digest)> ConvergenceCalls { get; } = [];

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
            if (region == ThrowObserveInRegion)
                return ValueTask.FromException<DeliveryArtifact?>(new IOException("provider-detail observe failed"));
            if (ObserveInvalidDigests)
                return ValueTask.FromResult<DeliveryArtifact?>(new DeliveryArtifact("sha256:nope", "sha256:nope", "service"));
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
            return ValueTask.FromResult(Mutate(artifact, region));
        }

        public ValueTask<DeliveryMutationResult> ApplyFencedAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            string region,
            string? expectedPreviousArtifactDigest,
            CancellationToken cancellationToken)
        {
            Calls.Add($"apply:{region}");
            if (region == CancelApplyInRegion)
            {
                var cancelled = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cancelled.Cancel();
                return ValueTask.FromCanceled<DeliveryMutationResult>(cancelled.Token);
            }
            if (region == PartitionApplyInRegion)
                return ValueTask.FromException<DeliveryMutationResult>(
                    new NATS.Client.Core.NatsException("provider boundary unreachable"));
            var previous = CurrentOf(region);
            if (region == ConcurrentMutationInRegion)
            {
                // The interleave under test: a concurrent writer mutates the region between the
                // coordinator's write-ahead observation and this mutation.
                currentDigests[region] = OtherArtifactDigest;
                currentManifests[region] = OtherArtifactDigest;
                previous = OtherArtifactDigest;
            }
            if (previous is not null && string.Equals(previous, artifact.Digest, StringComparison.OrdinalIgnoreCase))
                return ValueTask.FromResult(new DeliveryMutationResult(true, false, null));
            if (!string.Equals(previous, expectedPreviousArtifactDigest, StringComparison.OrdinalIgnoreCase))
                return ValueTask.FromResult(new DeliveryMutationResult(
                    false, false, previous, DirectDeliveryErrorCode.MutationRace));
            return ValueTask.FromResult(Mutate(artifact, region));
        }

        private DeliveryMutationResult Mutate(DeliveryArtifact artifact, string region)
        {
            var previous = CurrentOf(region);
            currentDigests[region] = artifact.Digest;
            currentManifests[region] = artifact.ManifestDigest;
            if (ApplyNullResult)
                return null!;
            if (ApplyFailedResult)
                return new(false, false, previous);
            if (ApplyInvalidPrevious)
                return new(true, true, "sha256:not-a-digest", PreviousManifestDigest: null);
            if (CrashAfterApply)
                throw ApplyException ?? new IOException("simulated crash between apply and applied-persist");
            if (ReportRacedPrevious && previous is not null)
                return new(true, true, OtherArtifactDigest, PreviousManifestDigest: OtherArtifactDigest);
            return previous is not null &&
                string.Equals(previous, artifact.Digest, StringComparison.OrdinalIgnoreCase)
                    ? new DeliveryMutationResult(true, false, null)
                    : new DeliveryMutationResult(true, true, previous);
        }

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken)
        {
            var rollback = artifact.Digest == PreviousDigest || artifact.Digest == AltPreviousDigest;
            Calls.Add(rollback ? $"rollback-health:{region}" : $"health:{region}");
            if (!rollback && region == ForeignDigestAtRollbackRegion)
            {
                // The drift under test: an external writer replaces the region right after its
                // forward health check failed, so the rollback observation sees a foreign digest.
                currentDigests[region] = OtherArtifactDigest;
                currentManifests[region] = OtherArtifactDigest;
            }
            if (!rollback && region == ThrowHealthInRegion)
                return ValueTask.FromException<DeliveryHealthResult>(new IOException("provider-detail health failed"));
            if (rollback && region == ThrowRollbackHealthInRegion)
                return ValueTask.FromException<DeliveryHealthResult>(new IOException("provider-detail rollback health failed"));
            var failed = rollback ? region == FailRollbackHealthInRegion : region == FailHealthInRegion;
            return ValueTask.FromResult(new DeliveryHealthResult(!failed,
                [new($"{region}-health", failed ? DeliveryHealthStatus.Failed : DeliveryHealthStatus.Passed)]));
        }

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> orderedRegions, CancellationToken cancellationToken)
        {
            var rollback = artifact.Digest == PreviousDigest || artifact.Digest == AltPreviousDigest;
            Calls.Add(rollback ? "rollback-converge" : "converge");
            ConvergenceCalls.Add((orderedRegions.ToArray(), artifact.Digest!));
            if (rollback && ThrowRollbackConvergence)
                return ValueTask.FromException<DeliveryConvergenceResult>(new IOException("provider-detail convergence failed"));
            if (rollback && CancelRollbackConvergence)
            {
                var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                source.Cancel();
                return ValueTask.FromCanceled<DeliveryConvergenceResult>(source.Token);
            }
            if (rollback && FailRollbackConvergence)
                return ValueTask.FromResult(new DeliveryConvergenceResult(false));
            // Honest convergence: every covered region must currently hold the verified digest.
            var converged = orderedRegions.All(region =>
                string.Equals(CurrentOf(region), artifact.Digest, StringComparison.OrdinalIgnoreCase));
            return ValueTask.FromResult(new DeliveryConvergenceResult(converged));
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
            if (CancelRollback)
            {
                var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                source.Cancel();
                return ValueTask.FromCanceled<DeliveryRollbackResult>(source.Token);
            }
            if (region == CorruptRollbackResultRegion)
                return ValueTask.FromResult(new DeliveryRollbackResult(
                    true, OtherArtifactDigest, new DeliveryArtifact(OtherArtifactDigest, OtherArtifactDigest, "service")));
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
