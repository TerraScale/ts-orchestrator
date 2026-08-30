using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Delivery.DeployHandoff;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Production direct-delivery adapters: admitted targets from configuration, durable signed
/// artifact evidence, and the composition boundary that fails closed without them. The restart
/// and handoff tests run over the real durable adapters (journal, target, evidence) so the
/// idempotency and resume contracts are proven at the shape production composes.
/// </summary>
public sealed class DirectDeliveryProductionAdapterTests
{
    [Test]
    public async Task Admitted_targets_admit_only_the_configured_service_environment_and_regions()
    {
        var targets = DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,sfo"]);

        await Assert.That(targets.Admits(new("authentication", "development", ["gru"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["gru", "sfo"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["sfo", "gru"]))).IsTrue();
        await Assert.That(targets.Admits(new("authentication", "development", ["fra"]))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", "production", ["gru"]))).IsFalse();
        await Assert.That(targets.Admits(new("platform", "development", ["gru"]))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", "development", []))).IsFalse();
        await Assert.That(targets.Admits(new("authentication", null, ["gru"]))).IsFalse();
    }

    [Test]
    public async Task Admitted_targets_reject_malformed_configuration()
    {
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:staging:gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,gru"]))
            .Throws<ArgumentException>();
        await Assert.That(() => DirectDeliveryAdmittedTargets.Parse(["authentication:development:"]))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task Evidence_journal_keeps_the_first_durable_claim_per_artifact()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new DirectDeliveryArtifactEvidenceJournal(ledger);
        var signer = new HashSignature(1);

        var first = await journal.RecordAsync(Evidence(commit: CommitA), signer, default);
        var duplicate = await journal.RecordAsync(Evidence(commit: CommitA), signer, default);
        var conflict = await journal.RecordAsync(Evidence(commit: CommitB), signer, default);

        await Assert.That(first).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.Recorded);
        await Assert.That(duplicate).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.Duplicate);
        await Assert.That(conflict).IsEqualTo(DirectDeliveryArtifactEvidenceDisposition.IdentityConflict);
        await Assert.That(ledger.Values).HasSingleItem();
    }

    [Test]
    public async Task Production_provenance_verifies_only_durable_signed_evidence()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        var journal = new DirectDeliveryArtifactEvidenceJournal(ledger);
        await journal.RecordAsync(Evidence(commit: CommitA), trust, default);
        var provenance = new DirectDeliveryProductionProvenance(journal, trust);

        var verified = await provenance.VerifyAsync(
            Request(commit: CommitA), Artifact(), default);
        var wrongCommit = await provenance.VerifyAsync(
            Request(commit: CommitB), Artifact(), default);
        var wrongManifest = await provenance.VerifyAsync(
            Request(commit: CommitA), Artifact(manifest: OtherManifestDigest), default);
        var noEvidence = await provenance.VerifyAsync(
            Request(commit: CommitA, artifactDigest: UnrecordedArtifactDigest), Artifact(UnrecordedArtifactDigest), default);
        var untrusted = await new DirectDeliveryProductionProvenance(
                journal, new HashSignature(2))
            .VerifyAsync(Request(commit: CommitA), Artifact(), default);
        var sourceless = await provenance.VerifyAsync(
            Request(commit: CommitA) with { Source = null }, Artifact(), default);

        await Assert.That(verified.Verified).IsTrue();
        await Assert.That(wrongCommit.Verified).IsFalse();
        await Assert.That(wrongManifest.Verified).IsFalse();
        await Assert.That(noEvidence.Verified).IsFalse();
        await Assert.That(untrusted.Verified).IsFalse();
        await Assert.That(sourceless.Verified).IsFalse();
    }

    [Test]
    public async Task Adapter_composition_fails_closed_without_configuration()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);

        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                ledger,
                static () => true, static _ => true,
                admittedTargets: null, evidenceVerifier: trust))
            .Throws<InvalidOperationException>();
        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                ledger,
                static () => true, static _ => true,
                admittedTargets: Targets(), evidenceVerifier: null))
            .Throws<InvalidOperationException>();
        var composed = DirectDeliveryRuntimeAdapterSet.Create(
            ledger,
            static () => true, static _ => true, Targets(), trust);
        await Assert.That(composed.ArtifactBuilder).IsNull();
    }

    [Test]
    public async Task A_delivery_replays_its_terminal_receipt_after_a_runtime_restart()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var first = HandoffRuntime(ledger, trust);
        var receipt = await first.DeliverManifestAsync(Manifest("operation-restart-1"));
        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        var mutations = ledger.Mutations;
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);

        // Restart: a fresh runtime over the same durable state must not mutate anything to
        // answer the same operation, and must not admit a second journal record for it.
        var restarted = HandoffRuntime(ledger, trust);
        var replay = await restarted.DeliverManifestAsync(Manifest("operation-restart-1"));

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(replay.OperationId).IsEqualTo("operation-restart-1");
        await Assert.That(ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(1);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);
    }

    [Test]
    public async Task A_crash_between_apply_and_persist_resumes_to_success_with_rollback_material_intact()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        // A previous deployment leaves the region running the prior artifact.
        await RecordEvidence(ledger, trust, PreviousArtifactDigest, PreviousManifestDigest, CommitA);
        await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            Manifest("operation-crash-0", PreviousArtifactDigest, PreviousManifestDigest, CommitA));
        var mutations = ledger.Mutations;

        // The crashed run persisted its write-ahead 'applying' record and completed the target
        // mutation, but never persisted 'applied': exactly the durable state a restart sees.
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var request = DeployHandoffMapper.Map(Manifest("operation-crash-1")).Request!.Delivery;
        await new NatsDirectDeliveryTarget(new LedgerAdapter(ledger))
            .ApplyAsync(request, Artifact(), "gru", default);
        var journal = new NatsDirectDeliveryJournal(ledger);
        await journal.AppendAsync(new(
            "operation-crash-1",
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.Applying,
            null,
            ArtifactDigest,
            [new("gru", "applying", PreviousArtifactDigest, PreviousManifestDigest: PreviousManifestDigest)]), default);

        var restarted = HandoffRuntime(ledger, trust);
        var receipt = await restarted.DeliverManifestAsync(Manifest("operation-crash-1"));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        var record = await journal.ReadAsync("operation-crash-1", default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.Succeeded);
        // The pre-mutation identity of the crashed run is still the durable rollback target.
        await Assert.That(record.Regions!.Single(static region => region.Region == "gru")
            .PreviousArtifactDigest).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(ledger.Mutations).IsGreaterThan(mutations);
    }

    [Test]
    public async Task A_pre_codec_journal_record_reports_the_distinct_non_replayable_remediation()
    {
        // End-to-end for the codec-mismatch class: durable bytes written by the previous
        // record codec (current shape minus the receipt's manifest member) sit under the
        // requested operationId. The coordinator's read must fail closed as
        // journal_unavailable with the DISTINCT remediation — these bytes are not a
        // journal-health problem and can never be replayed by this build.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var request = Request(CommitA);
        var canonical = System.Text.Json.JsonSerializer.Serialize(new DeliveryJournalRecord(
            request.OperationId!,
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.Succeeded,
            new DeliveryReceipt(
                DeliveryRequest.CurrentSchemaVersion,
                request.OperationId!,
                DeliveryReceiptStatus.Succeeded,
                null,
                ArtifactDigest,
                null,
                new DeliveryProvenance(true, ConfigurationDigest, null),
                new DeliveryHealth([], true),
                new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired),
                "audit-legacy",
                new DeliveryErrorInfo(null, null, null),
                ManifestDigest) with { ArtifactManifestDigest = null },
            ArtifactDigest), DeliveryWireCodec.JsonOptions);
        var preCodec = canonical.Replace(",\"artifactManifestDigest\":null}", "}", StringComparison.Ordinal);
        await Assert.That(preCodec).IsNotEqualTo(canonical);
        await ledger.CreateAsync(
            $"direct.operation.{Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(request.OperationId!)))}",
            preCodec,
            default);
        var mutations = ledger.Mutations;
        var coordinator = new DirectDeliveryService(
            new AllowAuthorizer(),
            new AllowProvenance(),
            new FixedResolver(new FencedTarget()),
            new NatsDirectDeliveryJournal(new LedgerAdapter(ledger)),
            auditIdFactory: static () => "audit-test");

        var receipt = await coordinator.DeliverAsync(request);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.JournalUnavailable);
        await Assert.That(receipt.Error.Remediation).Contains("predates the current record codec");
        await Assert.That(receipt.Error.Remediation).Contains("clear or drain");
        await Assert.That(receipt.Error.Remediation).DoesNotContain("replays its durable progress");
        // Fail closed without mutation: only the injected record exists, nothing was applied.
        await Assert.That(ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
    }

    [Test]
    public async Task Multi_region_health_failure_rolls_back_and_journals_through_the_durable_journal()
    {
        // The durable journal must ACCEPT the full multi-region progress sequence — the
        // per-region write-ahead, the health failure, the reverse rollback, and the terminal
        // rolled_back record — or per-region rollback progress (and rollback itself) only
        // exists against the in-memory journal.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var target = new FencedTarget { FailHealthInRegion = "sfo" };
        target.Seed("gru", PreviousArtifactDigest, PreviousManifestDigest);
        target.Seed("sfo", PreviousArtifactDigest, PreviousManifestDigest);
        var coordinator = new DirectDeliveryService(
            new AllowAuthorizer(),
            new AllowProvenance(),
            new FixedResolver(target),
            new NatsDirectDeliveryJournal(new LedgerAdapter(ledger)),
            auditIdFactory: static () => "audit-test");

        var receipt = await coordinator.DeliverAsync(Request(CommitA) with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]),
        });

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Rollback.TargetArtifactDigest).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(target.DigestOf("gru")).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(target.DigestOf("sfo")).IsEqualTo(PreviousArtifactDigest);
        var record = await new NatsDirectDeliveryJournal(new LedgerAdapter(ledger))
            .ReadAsync("operation-provenance", default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
        await Assert.That(record.Regions!.Select(static region => region.State))
            .IsEquivalentTo(["rollback_succeeded", "rollback_succeeded"]);
        await Assert.That(record.Regions!.Select(static region => region.PreviousArtifactDigest!))
            .IsEquivalentTo([PreviousArtifactDigest, PreviousArtifactDigest]);
    }

    [Test]
    public async Task Fenced_apply_compare_and_swaps_the_observed_previous_digest()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var target = new NatsDirectDeliveryTarget(new LedgerAdapter(ledger));
        var request = Request(CommitA);
        var next = Artifact(UnrecordedArtifactDigest, OtherManifestDigest);

        // A pristine region satisfies a pristine expectation and applies.
        var applied = await target.ApplyFencedAsync(request, Artifact(), "gru", null, default);
        await Assert.That(applied.Succeeded).IsTrue();
        await Assert.That(applied.Mutated).IsTrue();
        await Assert.That(applied.PreviousArtifactDigest).IsNull();

        // A stale expectation — the write-ahead observed a pristine region while a concurrent
        // writer deployed — refuses the mutation with the typed race outcome and mutates
        // nothing: the concurrent owner keeps the region.
        var raced = await target.ApplyFencedAsync(request, next, "gru", null, default);
        await Assert.That(raced.Succeeded).IsFalse();
        await Assert.That(raced.Mutated).IsFalse();
        await Assert.That(raced.FailureCode).IsEqualTo(DirectDeliveryErrorCode.MutationRace);
        await Assert.That((await target.ObserveCurrentArtifactAsync(request, "gru", default))!.Digest)
            .IsEqualTo(ArtifactDigest);

        // The matching expectation applies and reports the exact replaced digest.
        var fenced = await target.ApplyFencedAsync(request, next, "gru", ArtifactDigest, default);
        await Assert.That(fenced.Succeeded).IsTrue();
        await Assert.That(fenced.Mutated).IsTrue();
        await Assert.That(fenced.PreviousArtifactDigest).IsEqualTo(ArtifactDigest);

        // A replay of the same artifact is an idempotent no-op, never a race.
        var replay = await target.ApplyFencedAsync(request, next, "gru", ArtifactDigest, default);
        await Assert.That(replay.Succeeded).IsTrue();
        await Assert.That(replay.Mutated).IsFalse();
        await Assert.That(replay.PreviousArtifactDigest).IsNull();
    }

    [Test]
    public async Task A_receipt_less_failure_with_forward_debt_resumes_rollback_through_the_durable_journal()
    {
        // B1 characterization against the REAL journal: the coordinator persisted Failed with
        // receipt null and regions still in forward phases carrying write-ahead debt (crash or
        // journal outage between the failure record and the terminal receipt). Replay must
        // resume the FAILURE path — rollback recovery — and must never come back as a
        // permanent journal_unavailable, and never re-apply the failed delivery.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(new LedgerAdapter(ledger));
        var request = Request(CommitA) with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]),
        };
        await journal.AppendAsync(new(
            request.OperationId!,
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.Failed,
            Receipt: null,
            ArtifactDigest,
            [
                new DeliveryRegionProgress("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest),
                new DeliveryRegionProgress("sfo", "health_failed", PreviousArtifactDigest, null, PreviousManifestDigest),
            ]), default);
        // The crashed run left both regions deployed with the requested artifact.
        var target = new FencedTarget();
        target.Seed("gru", ArtifactDigest, ManifestDigest);
        target.Seed("sfo", ArtifactDigest, ManifestDigest);

        var receipt = await CoordinatorOver(new LedgerAdapter(ledger), target).DeliverAsync(request);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(receipt.Error.Code).IsNull();
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
        await Assert.That(target.DigestOf("gru")).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(target.DigestOf("sfo")).IsEqualTo(PreviousArtifactDigest);
        var record = await journal.ReadAsync(request.OperationId!, default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
        await Assert.That(record.Regions!.Select(static region => region.State))
            .IsEquivalentTo(["rollback_succeeded", "rollback_succeeded"]);
    }

    [Test]
    public async Task A_receipt_less_failure_without_debt_replays_the_apply_path()
    {
        // The other B1 half: a receipt-less Failed record with NO write-ahead debt (the
        // mutation failed before anything was mutated) owes no rollback — replay re-enters the
        // apply path (the journal must accept lower-rank progress after a receipt-less
        // failure) and the delivery can succeed once the dependency recovered.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(new LedgerAdapter(ledger));
        var request = Request(CommitA);
        await journal.AppendAsync(new(
            request.OperationId!,
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.Failed,
            Receipt: null,
            ArtifactDigest,
            [new DeliveryRegionProgress("gru", "failed")]), default);
        var target = new FencedTarget();
        target.Seed("gru", PreviousArtifactDigest, PreviousManifestDigest);

        var receipt = await CoordinatorOver(new LedgerAdapter(ledger), target).DeliverAsync(request);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(target.Calls).Contains("apply:gru");
        var record = await journal.ReadAsync(request.OperationId!, default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.Succeeded);
    }

    [Test]
    public async Task Journal_state_ranks_accept_only_forward_phase_sequences()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(new LedgerAdapter(ledger));
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(Request(CommitA));

        // healthy → applying: region two's write-ahead after region one's health gate (the
        // multi-region interleave every delivery performs).
        await journal.AppendAsync(new("rank-1", fingerprint, "healthy", null, ArtifactDigest,
            [new("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest),
                new("sfo", "pending")]), default);
        await journal.AppendAsync(new("rank-1", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest,
            [new("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest),
                new("sfo", DeliveryJournalState.Applying, PreviousArtifactDigest, null, PreviousManifestDigest)]), default);

        // applied → rollback_pending: failure handling converts forward progress into debt.
        await journal.AppendAsync(new("rank-2", fingerprint, "applied", null, ArtifactDigest,
            [new("gru", "applied", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        await journal.AppendAsync(new("rank-2", fingerprint, DeliveryJournalState.Failed, null, ArtifactDigest,
            [new("gru", "rollback_pending", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);

        // rollback_pending → applied: debt may never be silently un-owed.
        await journal.AppendAsync(new("rank-3", fingerprint, DeliveryJournalState.Failed, null, ArtifactDigest,
            [new("gru", "rollback_pending", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        await Assert.That(await Rejects(() => journal.AppendAsync(new("rank-3", fingerprint, "applied", null,
            ArtifactDigest, [new("gru", "applied", PreviousArtifactDigest, null, PreviousManifestDigest)]), default)))
            .IsTrue();

        // failed WITHOUT a receipt → applying: a receipt-less failure is re-enterable (B1).
        await journal.AppendAsync(new("rank-4", fingerprint, DeliveryJournalState.Failed, null, ArtifactDigest,
            [new("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        await journal.AppendAsync(new("rank-4", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest,
            [new("gru", DeliveryJournalState.Applying, PreviousArtifactDigest, null, PreviousManifestDigest)]), default);

        // failed WITH a (non-replayable) receipt → applying: re-entering a decided failure is
        // rejected — the durable record owns the outcome.
        await journal.AppendAsync(new("rank-5", fingerprint, DeliveryJournalState.Failed,
            new(DeliveryRequest.CurrentSchemaVersion, "rank-5", DeliveryReceiptStatus.Failed, null, ArtifactDigest,
                null, new DeliveryProvenance(false, null, null), new DeliveryHealth([], false),
                new DeliveryRollback(false, null, DeliveryRollbackStatus.NotRequired), "audit-test",
                new(DirectDeliveryErrorCode.HealthFailed, null, null), ManifestDigest),
            ArtifactDigest,
            [new("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        await Assert.That(await Rejects(() => journal.AppendAsync(new("rank-5", fingerprint, DeliveryJournalState.Applying,
            null, ArtifactDigest,
            [new("gru", DeliveryJournalState.Applying, PreviousArtifactDigest, null, PreviousManifestDigest)]), default)))
            .IsTrue();
    }

    [Test]
    public async Task Degraded_rollback_bookkeeping_replays_recovery_through_the_durable_journal()
    {
        // The journal degrades exactly when rollback progress is written: the rollback itself
        // completes (best-effort bookkeeping never aborts it), the receipt says it is not
        // durable yet, and a replay against the recovered journal resumes from the durable
        // receipt-less failure record with forward debt (the B1 shape, produced for real).
        var ledger = new DegradeableLedger
        {
            FailWhenValue = value => value.Contains("rolling_back") || value.Contains("rollback_succeeded") ||
                value.Contains("rollback_failed") || value.Contains("rollback_pending"),
        };
        var target = new FencedTarget { FailHealthInRegion = "sfo" };
        target.Seed("gru", PreviousArtifactDigest, PreviousManifestDigest);
        target.Seed("sfo", PreviousArtifactDigest, PreviousManifestDigest);
        var request = Request(CommitA) with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]),
        };

        var first = await CoordinatorOver(ledger, target).DeliverAsync(request);

        await Assert.That(first.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(first.Error.Remediation).Contains("journal currently unavailable");
        await Assert.That(target.DigestOf("gru")).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(target.DigestOf("sfo")).IsEqualTo(PreviousArtifactDigest);
        var degraded = await new NatsDirectDeliveryJournal(ledger).ReadAsync(request.OperationId!, default);
        await Assert.That(degraded!.State).IsEqualTo(DeliveryJournalState.Failed);
        await Assert.That(degraded.Receipt).IsNull();
        await Assert.That(degraded.Regions!.Select(static region => region.State))
            .IsEquivalentTo(["healthy", "health_failed"]);

        // Recovery: the journal is repaired and the same operationId replays its durable debt.
        ledger.Repaired = true;
        target.Calls.Clear();
        var replay = await CoordinatorOver(ledger, target).DeliverAsync(request);

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
        var record = await new NatsDirectDeliveryJournal(ledger).ReadAsync(request.OperationId!, default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
        await Assert.That(record.Receipt!.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
    }

    [Test]
    public async Task A_lost_terminal_rollback_receipt_replays_to_rolled_back_without_new_mutations()
    {
        // The terminal rolled_back receipt persist fails (journal outage at the very end): the
        // receipt is still returned, the durable record holds rollback_succeeded progress, and
        // the replay converges through recovery alone — one convergence call, zero applies,
        // zero rollback mutations.
        var ledger = new DegradeableLedger { FailWhenValue = value => value.Contains("\"receipt\":{\"") };
        var target = new FencedTarget { FailHealthInRegion = "sfo" };
        target.Seed("gru", PreviousArtifactDigest, PreviousManifestDigest);
        target.Seed("sfo", PreviousArtifactDigest, PreviousManifestDigest);
        var request = Request(CommitA) with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]),
        };

        var first = await CoordinatorOver(ledger, target).DeliverAsync(request);

        await Assert.That(first.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(first.Error.Remediation).Contains("journal currently unavailable");

        ledger.Repaired = true;
        target.Calls.Clear();
        var replay = await CoordinatorOver(ledger, target).DeliverAsync(request);

        await Assert.That(replay.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(string.Join('|', target.Calls)).IsEqualTo("rollback-converge");
        var record = await new NatsDirectDeliveryJournal(ledger).ReadAsync(request.OperationId!, default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
    }

    [Test]
    public async Task Restart_mid_rollback_resumes_from_the_durable_rolling_back_record()
    {
        // A process restart while the rollback was between regions: the durable record is
        // RollingBack with one region restored and one still owing. Replay completes only the
        // owing region and never re-applies.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(new LedgerAdapter(ledger));
        var request = Request(CommitA) with
        {
            Target = new DeliveryTarget("authentication", "development", ["gru", "sfo"]),
        };
        await journal.AppendAsync(new(
            request.OperationId!,
            DirectDeliveryCoordinator.RequestFingerprint(request),
            DeliveryJournalState.RollingBack,
            Receipt: null,
            ArtifactDigest,
            [
                new DeliveryRegionProgress("gru", "rollback_succeeded", AltPreviousArtifactDigest, null, AltPreviousManifestDigest),
                new DeliveryRegionProgress("sfo", "rollback_failed", PreviousArtifactDigest, null, PreviousManifestDigest),
            ]), default);
        var target = new FencedTarget();
        target.Seed("gru", AltPreviousArtifactDigest, AltPreviousManifestDigest);
        target.Seed("sfo", ArtifactDigest, ManifestDigest);

        var receipt = await CoordinatorOver(new LedgerAdapter(ledger), target).DeliverAsync(request);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.RolledBack);
        await Assert.That(target.Calls.Any(static call =>
            call.StartsWith("apply:", StringComparison.Ordinal))).IsFalse();
        await Assert.That(target.Calls.Any(static call => call.StartsWith("rollback:gru"))).IsFalse();
        await Assert.That(target.Calls).Contains("rollback:sfo");
        await Assert.That(target.DigestOf("sfo")).IsEqualTo(PreviousArtifactDigest);
        await Assert.That(target.DigestOf("gru")).IsEqualTo(AltPreviousArtifactDigest);
        var record = await journal.ReadAsync(request.OperationId!, default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.RolledBack);
    }

    [Test]
    public async Task A_target_revision_cas_loss_reports_the_typed_mutation_race()
    {
        // The digest fence matched, but the ledger's revision compare-and-set lost to a
        // concurrent writer: the adapter must report the typed mutation race (not a generic
        // mutation failure) and leave the region to the concurrent owner.
        var ledger = new ConflictOnUpdateLedger();
        var target = new NatsDirectDeliveryTarget(ledger);
        var request = Request(CommitA);

        // Seed the region through the create path (updates are not armed yet).
        var seeded = await target.ApplyFencedAsync(request, Artifact(), "gru", null, default);
        await Assert.That(seeded.Succeeded).IsTrue();

        ledger.ConflictUpdates = true;
        var raced = await target.ApplyFencedAsync(
            request, Artifact(UnrecordedArtifactDigest, OtherManifestDigest), "gru", ArtifactDigest, default);

        await Assert.That(raced.Succeeded).IsFalse();
        await Assert.That(raced.Mutated).IsFalse();
        await Assert.That(raced.FailureCode).IsEqualTo(DirectDeliveryErrorCode.MutationRace);
        await Assert.That((await target.ObserveCurrentArtifactAsync(request, "gru", default))!.Digest)
            .IsEqualTo(ArtifactDigest);
    }

    [Test]
    public async Task A_concurrent_same_request_update_race_loses_to_the_winner_without_a_lost_update()
    {
        // Two same-request journal appends both read revision R; a competing writer commits
        // first. The loser gets the typed continuity conflict and the durable record keeps the
        // winner's value — a lost update would silently drop durable progress.
        var request = Request(CommitA);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(request);
        var competingValue = JsonSerializer.Serialize(
            new DeliveryJournalRecord(
                "operation-race", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest,
                [new DeliveryRegionProgress("gru", DeliveryJournalState.Applying, PreviousArtifactDigest, null, PreviousManifestDigest)]),
            DeliveryWireCodec.JsonOptions);
        ForgejoWebhookJournalTests.TestLedger? ledger = null;
        var interleaved = false;
        ledger = new ForgejoWebhookJournalTests.TestLedger(beforeUpdate: (key, token) =>
        {
            if (interleaved || ledger is null || !key.StartsWith("direct.operation.", StringComparison.Ordinal))
                return Task.CompletedTask;
            interleaved = true;
            var current = ledger.GetAsync(key, token).GetAwaiter().GetResult();
            return current is null
                ? Task.CompletedTask
                : ledger.UpdateAsync(key, competingValue, current.Revision, token);
        });
        var journal = new NatsDirectDeliveryJournal(new LedgerAdapter(ledger!));
        await journal.AppendAsync(new(
            "operation-race", fingerprint, DeliveryJournalState.Accepted, null, ArtifactDigest,
            [new DeliveryRegionProgress("gru", "pending")]), default);

        DirectDeliveryJournalConflictException? thrown = null;
        try
        {
            await journal.AppendAsync(new(
                "operation-race", fingerprint, "applied", null, ArtifactDigest,
                [new DeliveryRegionProgress("gru", "applied", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        }
        catch (DirectDeliveryJournalConflictException exception)
        {
            thrown = exception;
        }

        await Assert.That(thrown).IsNotNull();
        var durable = await journal.ReadAsync("operation-race", default);
        await Assert.That(durable!.State).IsEqualTo(DeliveryJournalState.Applying);
    }

    [Test]
    public async Task Retention_never_prunes_a_receipt_less_failure_that_owes_rollback_recovery()
    {
        // The B1 recovery shape (receipt-less Failed with forward-phase write-ahead debt) is
        // the only durable copy of the pre-mutation digests: under retention-cap pressure the
        // journal must fail closed (overflow) rather than delete it, or a retry would re-apply
        // over an owed rollback.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(Request(CommitA));

        await journal.AppendAsync(new("retain-1", fingerprint, DeliveryJournalState.Failed, Receipt: null,
            ArtifactDigest,
            [
                new DeliveryRegionProgress("gru", "healthy", PreviousArtifactDigest, null, PreviousManifestDigest),
                new DeliveryRegionProgress("sfo", "health_failed", PreviousArtifactDigest, null, PreviousManifestDigest),
            ]), default);

        var overflowed = false;
        try
        {
            await journal.AppendAsync(new("retain-2", fingerprint, DeliveryJournalState.Failed, Receipt: null,
                ArtifactDigest,
                [new DeliveryRegionProgress("gru", "applied", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        }
        catch (TerraScale.Orchestrator.Delivery.JournalRetentionOverflowException)
        {
            overflowed = true;
        }

        await Assert.That(overflowed).IsTrue();
        var owed = await journal.ReadAsync("retain-1", default);
        await Assert.That(owed).IsNotNull();
        await Assert.That(owed!.Regions!.Single(static region => region.Region == "gru").PreviousArtifactDigest)
            .IsEqualTo(PreviousArtifactDigest);
        await Assert.That(await journal.ReadAsync("retain-2", default)).IsNotNull();
    }

    [Test]
    public async Task Retention_never_prunes_a_receipt_less_completed_rollback()
    {
        // rollback_succeeded without a durable receipt still owes its terminal record: deleting
        // it would let replay re-apply the artifact over a finished rollback.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(Request(CommitA));

        await journal.AppendAsync(new("retain-done-1", fingerprint, DeliveryJournalState.Failed, Receipt: null,
            ArtifactDigest,
            [new DeliveryRegionProgress("gru", "rollback_succeeded", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);

        var overflowed = false;
        try
        {
            await journal.AppendAsync(new("retain-done-2", fingerprint, DeliveryJournalState.Failed, Receipt: null,
                ArtifactDigest,
                [new DeliveryRegionProgress("gru", "rollback_succeeded", PreviousArtifactDigest, null, PreviousManifestDigest)]), default);
        }
        catch (TerraScale.Orchestrator.Delivery.JournalRetentionOverflowException)
        {
            overflowed = true;
        }

        await Assert.That(overflowed).IsTrue();
        await Assert.That(await journal.ReadAsync("retain-done-1", default)).IsNotNull();
        await Assert.That(await journal.ReadAsync("retain-done-2", default)).IsNotNull();
    }

    [Test]
    public async Task Retention_still_prunes_recovered_failures_without_rollback_debt()
    {
        // Positive control: a receipt-less Failed record with NO write-ahead debt owes nothing
        // and stays prunable — the guard protects recovery material, not every failure.
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(Request(CommitA));

        await journal.AppendAsync(new("retain-free-1", fingerprint, DeliveryJournalState.Failed, Receipt: null,
            ArtifactDigest,
            [new DeliveryRegionProgress("gru", "failed")]), default);
        await journal.AppendAsync(new("retain-free-2", fingerprint, DeliveryJournalState.Succeeded, Receipt: null,
            ArtifactDigest,
            [new DeliveryRegionProgress("gru", "healthy")]), default);

        await Assert.That(await journal.ReadAsync("retain-free-1", default)).IsNull();
        await Assert.That(await journal.ReadAsync("retain-free-2", default)).IsNotNull();
    }

    [Test]
    public async Task Customer_content_never_moves_through_an_unselected_region()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        // The allow-list admits gru and sfo, but this delivery selects gru only.
        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            SingleRegionManifest("operation-single-region"));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Succeeded);
        await Assert.That(receipt.Target!.Regions).IsEquivalentTo(["gru"]);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(1);
        var record = await new NatsDirectDeliveryJournal(ledger)
            .ReadAsync("operation-single-region", default);
        await Assert.That(record!.Regions!.Select(static region => region.Region)).IsEquivalentTo(["gru"]);
    }

    [Test]
    public async Task An_unadmitted_production_target_fails_closed_without_mutation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var manifest = UnadmittedManifest("operation-unadmitted");

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(manifest);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.UnknownTarget);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
    }

    [Test]
    public async Task A_rejected_handoff_manifest_never_reaches_the_target_mutation_path()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var unknownField = Manifest("operation-rejected")
            .Replace("\"reason\":", "\"promotionStage\":\"x\",\"reason\":");

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(unknownField);

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(receipt.Error.Message).Contains("handoff_");
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(0);
    }

    [Test]
    public async Task A_transplanted_evidence_record_is_corruption_at_the_journal_boundary()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);

        // The attack: a KV writer copies the legitimately signed record for digest X under
        // digest Y's key. The journal must reject the key↔content mismatch as corruption.
        var original = await ledger.GetAsync(EvidenceKey(ArtifactDigest), default);
        await ledger.CreateAsync(EvidenceKey(UnrecordedArtifactDigest), original!.Value, default);

        await Assert.That(async () => await new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger))
                .ReadAsync(UnrecordedArtifactDigest, default))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task A_transplanted_evidence_record_cannot_admit_an_unattested_digest()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        // The signed record binds commit A and its digests for ArtifactDigest only; the request
        // below matches every recorded field EXCEPT that it deploys UnrecordedArtifactDigest,
        // for which no evidence was ever signed. Only the digest binding separates them.
        await RecordEvidence(ledger, trust, ArtifactDigest, ManifestDigest, CommitA);
        var original = await ledger.GetAsync(EvidenceKey(ArtifactDigest), default);
        await ledger.CreateAsync(EvidenceKey(UnrecordedArtifactDigest), original!.Value, default);

        var receipt = await HandoffRuntime(ledger, trust).DeliverManifestAsync(
            Manifest("operation-transplant", UnrecordedArtifactDigest, ManifestDigest, CommitA));

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.ProvenanceFailed);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
    }

    [Test]
    public async Task Evidence_verifies_with_real_ecdsa_keys_and_rejects_wrong_keys_and_other_domains()
    {
        using var identity = EcdsaIdentity.Create();
        using var other = EcdsaIdentity.Create();
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger));
        await journal.RecordAsync(Evidence(commit: CommitA), identity.Signer, default);
        var recorded = await journal.ReadAsync(ArtifactDigest, default);

        await Assert.That(recorded).IsNotNull();
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(recorded!, identity.Verifier)).IsTrue();
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(recorded!, other.Verifier)).IsFalse();

        // Cross-domain: a CI artifact-attestation signature over ci/* material must never
        // verify as delivery evidence over the delivery/* material, even from the same key.
        var subject = new RepositoryCiArtifactSubject(
            PlainDigest('a'),
            new("transplant-job"),
            new("TerraScale/TerraScale.Orchestrator"),
            RepositoryCiArchitecture.LinuxArm64,
            new(PlainDigest('b')),
            RepositoryCiArtifactAttestation.EntrypointsDigest(RepositoryCiArchitecture.LinuxArm64, ["app"]));
        var ciSignature = RepositoryCiArtifactAttestation.Sign(subject, identity.Signer).Signature;
        await Assert.That(DirectDeliveryArtifactEvidenceJournal.Verifies(
                new DirectDeliverySignedArtifactEvidence(Evidence(commit: CommitA), identity.Signer.Identity, ciSignature),
                identity.Verifier))
            .IsFalse();
    }

    [Test]
    public async Task Production_composition_refuses_an_empty_admitted_target_set()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var empty = DirectDeliveryAdmittedTargets.Parse([]);

        await Assert.That(empty.IsEmpty).IsTrue();
        await Assert.That(() => DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger),
                static () => true, static _ => true,
                empty, new HashSignature(1)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Composition_has_no_artifact_builder_and_refuses_source_only_requests()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var trust = new HashSignature(1);
        var (authorizer, provenance, targetResolver, journal, artifactBuilder) =
            DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger),
                static () => true,
                static _ => true,
                Targets(),
                trust);
        await Assert.That(artifactBuilder).IsNull();

        var service = new DirectDeliveryService(
            authorizer, provenance, targetResolver, journal, artifactBuilder,
            auditIdFactory: static () => "audit-test");
        var receipt = await service.DeliverAsync(Request(commit: CommitA) with { Artifact = null });

        await Assert.That(receipt.Status).IsEqualTo(DeliveryReceiptStatus.Failed);
        await Assert.That(receipt.Error.Code).IsEqualTo(DirectDeliveryErrorCode.InvalidInput);
        await Assert.That(await CountKeysAsync(ledger, "direct.target.>")).IsEqualTo(0);
        await Assert.That(await CountKeysAsync(ledger, "direct.operation.>")).IsEqualTo(0);
    }

    private static DeployHandoffDeliveryRuntime HandoffRuntime(
        ForgejoWebhookJournalTests.TestLedger ledger,
        HashSignature trust)
    {
        var (authorizer, provenance, targetResolver, journal, artifactBuilder) =
            DirectDeliveryRuntimeAdapterSet.Create(
                new LedgerAdapter(ledger),
                static () => true,
                static _ => true,
                Targets(),
                trust);
        return new(new DirectDeliveryService(
            authorizer, provenance, targetResolver, journal, artifactBuilder,
            auditIdFactory: static () => "audit-test"));
    }

    private static DirectDeliveryAdmittedTargets Targets() =>
        DirectDeliveryAdmittedTargets.Parse(["authentication:development:gru,sfo"]);

    private static Task RecordEvidence(
        ForgejoWebhookJournalTests.TestLedger ledger,
        IRepositoryCiArtifactAttestationSigner signer,
        string artifactDigest,
        string manifestDigest,
        string commit) =>
        new DirectDeliveryArtifactEvidenceJournal(new LedgerAdapter(ledger))
            .RecordAsync(
                new DirectDeliveryArtifactEvidence(
                    "TerraScale/TerraScale.Orchestrator", commit, TreeDigest, artifactDigest, manifestDigest, "service"),
                signer,
                default);

    private static async Task<int> CountKeysAsync(
        ForgejoWebhookJournalTests.TestLedger ledger,
        string filter)
    {
        var count = 0;
        await foreach (var _ in ledger.ListKeysAsync(filter, default))
            count++;
        return count;
    }

    private static DirectDeliveryArtifactEvidence Evidence(string commit) => new(
        "TerraScale/TerraScale.Orchestrator", commit, TreeDigest, ArtifactDigest, ManifestDigest, "service");

    private static DeliveryRequest Request(string commit, string artifactDigest = ArtifactDigest) => new(
        1,
        "operation-provenance",
        new("TerraScale/TerraScale.Orchestrator", commit, TreeDigest),
        Artifact(artifactDigest),
        new("authentication", "development", ["gru"]),
        ConfigurationDigest,
        null,
        "actor-1",
        "direct customer change");

    private static DeliveryArtifact Artifact(
        string digest = ArtifactDigest,
        string manifest = ManifestDigest) => new(digest, manifest, "service");

    private static string Manifest(
        string operationId,
        string artifactDigest = ArtifactDigest,
        string manifestDigest = ManifestDigest,
        string commit = CommitA) => $$"""
        {
          "schemaVersion": 1,
          "operationId": "{{operationId}}",
          "source": { "repository": "TerraScale/TerraScale.Orchestrator", "commit": "{{commit}}", "treeDigest": "{{TreeDigest}}" },
          "artifact": { "digest": "{{artifactDigest}}", "manifestDigest": "{{manifestDigest}}", "kind": "service", "architecture": "linux/arm64" },
          "target": { "service": "authentication", "environment": "development", "regions": ["gru"] },
          "configurationRevision": "{{ConfigurationDigest}}",
          "requestedBy": "actor-1",
          "reason": "direct customer change"
        }
        """;

    private static string SingleRegionManifest(string operationId) => Manifest(operationId);

    private static string UnadmittedManifest(string operationId) =>
        Manifest(operationId).Replace("\"environment\": \"development\"", "\"environment\": \"production\"");

    private const string CommitA = "0123456789abcdef0123456789abcdef01234567";
    private const string CommitB = "fedcba9876543210fedcba9876543210fedcba98";
    private const string TreeDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ConfigurationDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string ManifestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private const string OtherManifestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    private const string UnrecordedArtifactDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    private const string PreviousArtifactDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    private const string PreviousManifestDigest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    private const string AltPreviousArtifactDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    private const string AltPreviousManifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    /// <summary>Builds the coordinator over the real durable journal with test-owned boundaries.</summary>
    private static DirectDeliveryService CoordinatorOver(IForgejoDeliveryLedger ledger, IDeliveryTarget target) => new(
        new AllowAuthorizer(),
        new AllowProvenance(),
        new FixedResolver(target),
        new NatsDirectDeliveryJournal(ledger),
        auditIdFactory: static () => "audit-test");

    /// <summary>Deterministically reports whether one append is rejected as a continuity conflict.</summary>
    private static async Task<bool> Rejects(Func<ValueTask> append)
    {
        try
        {
            await append();
            return false;
        }
        catch (DirectDeliveryJournalConflictException)
        {
            return true;
        }
    }

    /// <summary>A deterministic admitted signing identity: signs and verifies the same digest.</summary>
    internal sealed class HashSignature(byte domain) :
        IRepositoryCiArtifactAttestationSigner,
        IRepositoryCiArtifactSignatureVerifier
    {
        public string Identity => $"test-key-{domain}";

        public OpaqueSignature Sign(ReadOnlyMemory<byte> canonicalMaterial)
        {
            var bytes = new byte[canonicalMaterial.Length + 1];
            bytes[0] = domain;
            canonicalMaterial.Span.CopyTo(bytes.AsSpan(1));
            OpaqueSignature.TryCopyFrom(SHA256.HashData(bytes), out var signature);
            return signature!;
        }

        public VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            OpaqueSignature signature) => signingIdentity == Identity && Sign(canonicalMaterial).Equals(signature)
            ? VerificationOutcome.Valid
            : VerificationOutcome.Invalid;
    }

    /// <summary>The durable evidence key for one artifact digest, as the journal derives it.</summary>
    private static string EvidenceKey(string artifactDigest) =>
        "direct.evidence." + Convert.ToHexStringLower(
            SHA256.HashData(Encoding.UTF8.GetBytes(artifactDigest.ToLowerInvariant())));

    private static string PlainDigest(char value) => new(value, 64);

    /// <summary>An ephemeral real P-256 command identity: signs and verifies real ECDSA envelopes.</summary>
    private sealed class EcdsaIdentity : IDisposable
    {
        private readonly EcdsaCommandSigner signer;
        private readonly string publicPath;

        private EcdsaIdentity(EcdsaCommandSigner signer, string publicPath)
        {
            this.signer = signer;
            this.publicPath = publicPath;
        }

        internal EcdsaCommandSignatureVerifier Verifier { get; private set; } = null!;

        internal EcdsaCommandSigner Signer => signer;

        internal static EcdsaIdentity Create()
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyPath = Path.Combine(Path.GetTempPath(), $"ts-dd-ev-private-{Guid.NewGuid():N}.pem");
            var publicPath = Path.Combine(Path.GetTempPath(), $"ts-dd-ev-public-{Guid.NewGuid():N}.pem");
            File.WriteAllText(privateKeyPath, key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
            if (OperatingSystem.IsLinux())
                File.SetUnixFileMode(privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var signer = EcdsaCommandSigner.LoadPrivatePem(privateKeyPath);
            var identity = new EcdsaIdentity(signer, publicPath)
            {
                Verifier = EcdsaCommandSignatureVerifier.LoadPublicPem([publicPath]),
            };
            File.Delete(privateKeyPath);
            return identity;
        }

        public void Dispose()
        {
            Verifier.Dispose();
            signer.Dispose();
            File.Delete(publicPath);
        }
    }

    /// <summary>Adapts the test ledger to the ledger interface without NATS types.</summary>
    internal sealed class LedgerAdapter(ForgejoWebhookJournalTests.TestLedger ledger) :
        IForgejoDeliveryLedger
    {
        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            ledger.GetAsync(key, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken) =>
            ledger.CreateAsync(key, value, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(string key, string value, ulong revision, CancellationToken cancellationToken) =>
            ledger.UpdateAsync(key, value, revision, cancellationToken);
    }

    /// <summary>An always-authorizing test authorizer for journal-integration scenarios.</summary>
    private sealed class AllowAuthorizer : IDeliveryAuthorizer
    {
        public ValueTask<DeliveryAuthorizationResult> AuthorizeAsync(
            DeliveryRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryAuthorizationResult(true));
    }

    /// <summary>An always-verifying test provenance fake for journal-integration scenarios.</summary>
    private sealed class AllowProvenance : IDeliveryProvenanceVerifier
    {
        public ValueTask<DeliveryProvenanceResult> VerifyAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(new DeliveryProvenanceResult(
                true,
                false,
                request.ConfigurationRevision,
                request.MigrationRevision));
    }

    /// <summary>Resolves one fixed target for journal-integration scenarios.</summary>
    private sealed class FixedResolver(IDeliveryTarget deliveryTarget) : IDeliveryTargetResolver
    {
        public ValueTask<IDeliveryTarget?> ResolveAsync(DeliveryTarget target, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IDeliveryTarget?>(deliveryTarget);
    }

    /// <summary>
    /// A deterministic in-memory target with a digest compare-and-swap fence and health
    /// injection, used to drive the REAL durable journal through multi-region failure and
    /// rollback sequences.
    /// </summary>
    private sealed class FencedTarget : IDeliveryTarget
    {
        private readonly Dictionary<string, (string Digest, string Manifest)> deployed = new(StringComparer.Ordinal);
        public string? FailHealthInRegion { get; init; }

        /// <summary>Every adapter call, named for assertions (observe/apply/health/rollback/converge).</summary>
        public List<string> Calls { get; } = [];

        public void Seed(string region, string digest, string manifest) => deployed[region] = (digest, manifest);

        public string? DigestOf(string region) =>
            deployed.TryGetValue(region, out var value) ? value.Digest : null;

        public ValueTask<DeliveryArtifact?> ObserveCurrentArtifactAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken)
        {
            Calls.Add($"observe:{region}");
            return ValueTask.FromResult(deployed.TryGetValue(region, out var value)
                ? new DeliveryArtifact(value.Digest, value.Manifest, "service")
                : null);
        }

        public ValueTask<string?> ObserveCurrentDigestAsync(
            DeliveryRequest request, string region, CancellationToken cancellationToken) =>
            ValueTask.FromResult(deployed.TryGetValue(region, out var value) ? value.Digest : null);

        public ValueTask<DeliveryMutationResult> ApplyAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken) =>
            ApplyFencedAsync(request, artifact, region, null, cancellationToken);

        public ValueTask<DeliveryMutationResult> ApplyFencedAsync(
            DeliveryRequest request,
            DeliveryArtifact artifact,
            string region,
            string? expectedPreviousArtifactDigest,
            CancellationToken cancellationToken)
        {
            Calls.Add($"apply:{region}");
            var current = deployed.TryGetValue(region, out var value) ? value.Digest : null;
            if (string.Equals(current, artifact.Digest, StringComparison.OrdinalIgnoreCase))
                return ValueTask.FromResult(new DeliveryMutationResult(true, false, null));
            if (!string.Equals(current, expectedPreviousArtifactDigest, StringComparison.OrdinalIgnoreCase))
                return ValueTask.FromResult(new DeliveryMutationResult(
                    false, false, current, DirectDeliveryErrorCode.MutationRace));
            var previousManifest = deployed.TryGetValue(region, out var previous) ? previous.Manifest : null;
            deployed[region] = (artifact.Digest!, artifact.ManifestDigest!);
            return ValueTask.FromResult(new DeliveryMutationResult(true, true, current,
                PreviousManifestDigest: previousManifest));
        }

        public ValueTask<DeliveryHealthResult> CheckHealthAsync(
            DeliveryRequest request, DeliveryArtifact artifact, string region, CancellationToken cancellationToken)
        {
            var rollback = !string.Equals(artifact.Digest, ArtifactDigest, StringComparison.OrdinalIgnoreCase);
            Calls.Add(rollback ? $"rollback-health:{region}" : $"health:{region}");
            var failed = !rollback && region == FailHealthInRegion;
            return ValueTask.FromResult(new DeliveryHealthResult(!failed,
                [new($"{region}-health", failed ? DeliveryHealthStatus.Failed : DeliveryHealthStatus.Passed)]));
        }

        public ValueTask<DeliveryConvergenceResult> CheckConvergenceAsync(
            DeliveryRequest request, DeliveryArtifact artifact, IReadOnlyList<string> orderedRegions, CancellationToken cancellationToken)
        {
            var rollback = !string.Equals(artifact.Digest, ArtifactDigest, StringComparison.OrdinalIgnoreCase);
            Calls.Add(rollback ? "rollback-converge" : "converge");
            return ValueTask.FromResult(new DeliveryConvergenceResult(orderedRegions.All(region =>
                deployed.TryGetValue(region, out var value) &&
                string.Equals(value.Digest, artifact.Digest, StringComparison.OrdinalIgnoreCase))));
        }

        public ValueTask<DeliveryRollbackResult> RollbackAsync(
            DeliveryRequest request,
            string region,
            string targetArtifactDigest,
            string? targetManifestDigest,
            CancellationToken cancellationToken)
        {
            Calls.Add($"rollback:{region}");
            var manifest = targetManifestDigest ??
                (deployed.TryGetValue(region, out var value) ? value.Manifest : targetArtifactDigest);
            deployed[region] = (targetArtifactDigest, manifest);
            return ValueTask.FromResult(new DeliveryRollbackResult(
                true, targetArtifactDigest, new DeliveryArtifact(targetArtifactDigest, manifest, "service")));
        }
    }

    /// <summary>
    /// A ledger whose writes fail while a value predicate matches (and until repaired): used to
    /// degrade the durable journal at an exact point in a delivery sequence while the target
    /// stays healthy, then replay against the same durable state.
    /// </summary>
    private sealed class DegradeableLedger : IForgejoDeliveryLedger
    {
        private readonly ForgejoWebhookJournalTests.TestLedger inner = new();

        public Func<string, bool>? FailWhenValue { get; set; }
        public bool Repaired { get; set; }

        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            inner.GetAsync(key, cancellationToken);

        public async Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken)
        {
            await GuardAsync(value);
            return await inner.CreateAsync(key, value, cancellationToken);
        }

        public async Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
            string key, string value, ulong expectedRevision, CancellationToken cancellationToken)
        {
            await GuardAsync(value);
            return await inner.UpdateAsync(key, value, expectedRevision, cancellationToken);
        }

        private Task GuardAsync(string value) =>
            !Repaired && FailWhenValue?.Invoke(value) == true
                ? Task.FromException(new IOException("journal degraded"))
                : Task.CompletedTask;
    }

    /// <summary>A ledger whose updates all conflict once armed: revision compare-and-set loss.</summary>
    private sealed class ConflictOnUpdateLedger : IForgejoDeliveryLedger
    {
        private readonly ForgejoWebhookJournalTests.TestLedger inner = new();

        public bool ConflictUpdates { get; set; }

        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            inner.GetAsync(key, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken) =>
            inner.CreateAsync(key, value, cancellationToken);

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
            string key, string value, ulong expectedRevision, CancellationToken cancellationToken) =>
            ConflictUpdates
                ? Task.FromException<ForgejoDeliveryLedgerEntry>(
                    new ForgejoDeliveryLedgerConflictException(new InvalidOperationException("simulated revision race")))
                : inner.UpdateAsync(key, value, expectedRevision, cancellationToken);
    }

    /// <summary>A ledger whose every operation fails with an infrastructure-class exception.</summary>
    internal sealed class UnavailableLedger : IForgejoDeliveryLedger
    {
        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(string key, string value, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(string key, string value, ulong revision, CancellationToken cancellationToken) =>
            throw new IOException("the evidence ledger is unreachable");
    }
}
