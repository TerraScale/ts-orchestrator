using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Admission fencing and bounded history for the durable direct-delivery journal: a concurrent
/// create loses to the winner, a different request fingerprint can never overwrite it, and
/// completed operation history is pruned oldest-first under a fail-closed cap.
/// </summary>
public sealed class NatsDirectDeliveryJournalTests
{
    [Test]
    public async Task ConcurrentAdmissionsFenceDifferentRequestsToOneWinner()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var requests = new[]
        {
            Request("operation-race", ArtifactDigest),
            Request("operation-race", OtherArtifactDigest),
        };

        var outcomes = await Task.WhenAll(requests.Select(request => TryAppendAsync(journal, request)));

        await Assert.That(outcomes.Count(static outcome => outcome is null)).IsEqualTo(1);
        await Assert.That(outcomes.Count(static outcome =>
            outcome is DirectDeliveryJournalConflictException)).IsEqualTo(1);
        var winner = await journal.ReadAsync("operation-race", default);
        await Assert.That(winner).IsNotNull();
        await Assert.That(winner!.ArtifactDigest is ArtifactDigest or OtherArtifactDigest).IsTrue();
        await Assert.That(ledger.Values).HasSingleItem();
    }

    private static async Task<Exception?> TryAppendAsync(
        NatsDirectDeliveryJournal journal,
        DeliveryRequest request)
    {
        try
        {
            await journal.AppendAsync(new(
                request.OperationId!,
                DirectDeliveryCoordinator.RequestFingerprint(request),
                DeliveryJournalState.Accepted,
                null,
                request.Artifact!.Digest), default);
            return null;
        }
        catch (DirectDeliveryJournalConflictException exception)
        {
            return exception;
        }
    }

    [Test]
    public async Task ALaterDifferentFingerprintCannotOverwriteAnAdmittedOperation()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var admitted = Request("operation-fence", ArtifactDigest);
        var impostor = Request("operation-fence", OtherArtifactDigest);
        await journal.AppendAsync(new(
            admitted.OperationId!,
            Fingerprint(admitted),
            DeliveryJournalState.Accepted,
            null,
            admitted.Artifact!.Digest), default);

        await Assert.That(async () => await journal.AppendAsync(new(
                impostor.OperationId!,
                Fingerprint(impostor),
                DeliveryJournalState.Applying,
                null,
                impostor.Artifact!.Digest),
            default))
            .Throws<DirectDeliveryJournalConflictException>();
        var winner = await journal.ReadAsync("operation-fence", default);
        await Assert.That(winner!.ArtifactDigest).IsEqualTo(admitted.Artifact.Digest);
    }

    [Test]
    public async Task SameRequestProgressAppendsRemainContinuous()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var request = Request("operation-progress", ArtifactDigest);
        var fingerprint = Fingerprint(request);

        await journal.AppendAsync(new(request.OperationId!, fingerprint, DeliveryJournalState.Accepted, null,
            request.Artifact!.Digest), default);
        await journal.AppendAsync(new(request.OperationId!, fingerprint, DeliveryJournalState.Applying, null,
            request.Artifact.Digest), default);
        var record = await journal.ReadAsync("operation-1".Replace("operation-1", "operation-progress"), default);

        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.Applying);
    }

    [Test]
    public async Task TerminalOperationHistoryIsBoundedOldestFirst()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 2, pruneInterval: 1);
        foreach (var operationId in new[] { "operation-a", "operation-b", "operation-c" })
        {
            var request = Request(operationId, ArtifactDigest);
            await journal.AppendAsync(new(
                operationId,
                Fingerprint(request),
                DeliveryJournalState.Succeeded,
                null,
                request.Artifact!.Digest), default);
        }

        await Assert.That(await CountOperationsAsync(ledger)).IsEqualTo(2);
        await Assert.That(await journal.ReadAsync("operation-a", default)).IsNull();
        await Assert.That(await journal.ReadAsync("operation-c", default)).IsNotNull();
    }

    [Test]
    public async Task AnUnrecoverablyInFlightHistoryFailsClosedInsteadOfGrowing()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 2, pruneInterval: 1);
        foreach (var operationId in new[] { "operation-x", "operation-y" })
        {
            var request = Request(operationId, ArtifactDigest);
            await journal.AppendAsync(new(
                operationId,
                Fingerprint(request),
                DeliveryJournalState.Accepted,
                null,
                request.Artifact!.Digest), default);
        }
        var overflow = Request("operation-z", ArtifactDigest);

        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-z",
                Fingerprint(overflow),
                DeliveryJournalState.Accepted,
                null,
                overflow.Artifact!.Digest),
            default))
            .Throws<JournalRetentionOverflowException>();
        await Assert.That(await CountOperationsAsync(ledger)).IsEqualTo(3);
    }

    [Test]
    public async Task TerminalSuccessIsAbsorbingAgainstLateConcurrentAppends()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, pruneInterval: 1);
        var request = Request("operation-absorb", ArtifactDigest);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(request);
        await journal.AppendAsync(new(
            "operation-absorb", fingerprint, DeliveryJournalState.Succeeded,
            SuccessReceipt("operation-absorb"), ArtifactDigest), default);

        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-absorb", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest),
            default))
            .Throws<DirectDeliveryJournalConflictException>();
        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-absorb", fingerprint, DeliveryJournalState.Failed,
                FailedReceipt(DirectDeliveryErrorCode.JournalUnavailable, "operation-absorb"), ArtifactDigest),
            default))
            .Throws<DirectDeliveryJournalConflictException>();
        var winner = await journal.ReadAsync("operation-absorb", default);
        await Assert.That(winner!.State).IsEqualTo(DeliveryJournalState.Succeeded);
    }

    [Test]
    public async Task ReplayableFailureStatesStayOverwritable()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, pruneInterval: 1);
        var request = Request("operation-replay", ArtifactDigest);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(request);
        await journal.AppendAsync(new(
            "operation-replay", fingerprint, DeliveryJournalState.Failed,
            FailedReceipt(DirectDeliveryErrorCode.Cancelled, "operation-replay"), ArtifactDigest), default);

        await journal.AppendAsync(new(
            "operation-replay", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest), default);

        var record = await journal.ReadAsync("operation-replay", default);
        await Assert.That(record!.State).IsEqualTo(DeliveryJournalState.Applying);
    }

    [Test]
    public async Task FailedRecordsOwingRollbackRecoveryAreNeverPruned()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1, pruneInterval: 1);
        var owed = Request("operation-owed", ArtifactDigest);
        var owedFingerprint = DirectDeliveryCoordinator.RequestFingerprint(owed);
        // Failed with a rollback-failed region: the ONLY durable copy of the pre-mutation digest.
        await journal.AppendAsync(new(
            "operation-owed", owedFingerprint, DeliveryJournalState.Failed,
            FailedReceipt(DirectDeliveryErrorCode.RollbackFailed, "operation-owed"),
            ArtifactDigest,
            [new("gru", "rollback_failed", OtherArtifactDigest, null, ValidDigest)]), default);

        var overflow = Request("operation-next", ArtifactDigest);
        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-next",
                DirectDeliveryCoordinator.RequestFingerprint(overflow),
                DeliveryJournalState.Accepted,
                null,
                ArtifactDigest),
            default))
            .Throws<JournalRetentionOverflowException>();
        await Assert.That(await journal.ReadAsync("operation-owed", default)).IsNotNull();
    }

    [Test]
    public async Task PlainFailedRecordsWithoutRecoveryDebtArePrunable()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1, pruneInterval: 1);
        var plain = Request("operation-plain", ArtifactDigest);
        await journal.AppendAsync(new(
            "operation-plain", DirectDeliveryCoordinator.RequestFingerprint(plain),
            DeliveryJournalState.Failed, FailedReceipt(DirectDeliveryErrorCode.HealthFailed, "operation-plain"),
            ArtifactDigest), default);

        var next = Request("operation-next", ArtifactDigest);
        await journal.AppendAsync(new(
            "operation-next", DirectDeliveryCoordinator.RequestFingerprint(next),
            DeliveryJournalState.Accepted, null, ArtifactDigest), default);

        await Assert.That(await journal.ReadAsync("operation-plain", default)).IsNull();
        await Assert.That(await journal.ReadAsync("operation-next", default)).IsNotNull();
    }

    [Test]
    public async Task PruningIsAmortizedOverAppendsNotPerAppend()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        // The cap remains exact even when the configured scan interval is large.
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 2, pruneInterval: 1_000);
        foreach (var index in new[] { 1, 2, 3, 4, 5 })
        {
            var request = Request($"operation-amortized-{index}", ArtifactDigest);
            await journal.AppendAsync(new(
                $"operation-amortized-{index}",
                DirectDeliveryCoordinator.RequestFingerprint(request),
                DeliveryJournalState.Succeeded,
                SuccessReceipt($"operation-amortized-{index}"),
                ArtifactDigest), default);
        }

        await Assert.That(await CountOperationsAsync(ledger)).IsEqualTo(2);
    }

    [Test]
    public async Task SecondOrderConflictOnTheAdmissionRecoveryWriteFencesToo()
    {
        var ledger = new CreateRaceLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var request = Request("operation-race2", ArtifactDigest);

        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-race2",
                DirectDeliveryCoordinator.RequestFingerprint(request),
                DeliveryJournalState.Accepted,
                null,
                ArtifactDigest),
            default))
            .Throws<DirectDeliveryJournalConflictException>();
    }

    /// <summary>
    /// Simulates the admission race end to end: the first read misses, the create conflicts
    /// (another writer won), the recovery read sees the winner, and the recovery update conflicts
    /// again — the second-order conflict must surface as the typed fence, never a raw ledger error.
    /// </summary>
    private sealed class CreateRaceLedger : IForgejoDeliveryLedger, IForgejoDeliveryRetentionLedger
    {
        private readonly Dictionary<string, ForgejoDeliveryLedgerEntry> entries = new(StringComparer.Ordinal);

        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken) =>
            Task.FromResult<ForgejoDeliveryLedgerEntry?>(entries.GetValueOrDefault(key));

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(
            string key, string value, CancellationToken cancellationToken)
        {
            entries.TryGetValue(key, out var existing);
            if (existing is not null) throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());
            var winner = new ForgejoDeliveryLedgerEntry(value, 1, key);
            entries[key] = winner;
            throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());
        }

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
            string key, string value, ulong revision, CancellationToken cancellationToken) =>
            throw new ForgejoDeliveryLedgerConflictException(new InvalidOperationException());

        public async IAsyncEnumerable<string> ListKeysAsync(
            string filter,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            yield break;
        }

        public Task DeleteAsync(string key, ulong revision, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    [Test]
    public async Task ConcurrentSameRequestAppendCannotEraseWriteAheadRollbackMaterial()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger);
        var request = Request("operation-writeahead", ArtifactDigest);
        var fingerprint = DirectDeliveryCoordinator.RequestFingerprint(request);
        var applying = new DeliveryJournalRecord(
            "operation-writeahead", fingerprint, DeliveryJournalState.Applying, null, ArtifactDigest,
            [new("gru", "applying", ValidDigest, PreviousManifestDigest: ValidDigest)]);
        await journal.AppendAsync(applying, default);

        // A recovery append that RESETS the region's recorded previous digests is the exact
        // data-destroying path this guards: the durable write-ahead is the only exact
        // rollback target for a crash between apply and the applied persist.
        var reset = applying with
        {
            Regions = [new("gru", "applying", PreviousArtifactDigest: null, PreviousManifestDigest: null)],
        };
        await Assert.That(async () => await journal.AppendAsync(reset, default))
            .Throws<DirectDeliveryJournalConflictException>();

        var changed = applying with
        {
            Regions = [new("gru", "applying", OtherArtifactDigest, PreviousManifestDigest: ValidDigest)],
        };
        await Assert.That(async () => await journal.AppendAsync(changed, default))
            .Throws<DirectDeliveryJournalConflictException>();

        // Re-affirming the SAME recorded material (advancing the region state) stays continuous.
        var reaffirmed = applying with
        {
            Regions = [new("gru", "applied", ValidDigest, PreviousManifestDigest: ValidDigest)],
        };
        await journal.AppendAsync(reaffirmed, default);
        var record = await journal.ReadAsync("operation-writeahead", default);
        await Assert.That(record!.Regions!.Single(static region => region.Region == "gru")
            .PreviousArtifactDigest).IsEqualTo(ValidDigest);
    }

    private static DeliveryReceipt SuccessReceipt(string operationId = "operation") => new(
        1, operationId, DeliveryReceiptStatus.Succeeded, null, ArtifactDigest, null,
        new(true, ValidDigest, null), new([], true),
        new(false, null, DeliveryRollbackStatus.NotRequired), "audit", new(null, null, null), ValidDigest);

    private static DeliveryReceipt FailedReceipt(string code, string operationId = "operation") => new(
        1, operationId, DeliveryReceiptStatus.Failed, null, ArtifactDigest, null,
        new(false, null, null), new([], false),
        new(false, null, DeliveryRollbackStatus.NotRequired), "audit", new(code, null, null), ValidDigest);

    private static async Task<int> CountOperationsAsync(ForgejoWebhookJournalTests.TestLedger ledger)
    {
        var count = 0;
        await foreach (var key in ledger.ListKeysAsync("direct.operation.>", default))
            count++;
        return count;
    }

    private static string Fingerprint(DeliveryRequest request) =>
        DirectDeliveryCoordinator.RequestFingerprint(request with
        {
            Source = request.Source,
            Artifact = request.Artifact,
            Target = request.Target,
        });

    [Test]
    public async Task ACorruptDurableRecordFailsClosedAsABoundedJournalFailure()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var request = Request("operation-corrupt", ArtifactDigest);
        await journal.AppendAsync(new(
            request.OperationId!,
            Fingerprint(request),
            DeliveryJournalState.Accepted,
            null,
            request.Artifact!.Digest), default);
        ledger.CorruptFirst();

        // Corruption anywhere in the durable bytes (record JSON, canonical shape, or the
        // receipt evidence section) is a typed operational failure — never a silent replay of
        // unvalidated state, and never a mutation on the way out.
        await Assert.That(async () => await journal.ReadAsync("operation-corrupt", default))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task ALegacyRecordUnderCapPressureFailsBoundedInsteadOfKillingEveryAppend()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger, ledger, operationHistoryCap: 1);
        // A pre-change record: current-shape JSON minus the receipt's manifest-digest member.
        // It deserializes but cannot round-trip canonically — exactly the durable bytes a
        // previous record codec wrote.
        var legacy = Request("operation-legacy", ArtifactDigest);
        var canonical = System.Text.Json.JsonSerializer.Serialize(new DeliveryJournalRecord(
            legacy.OperationId!,
            Fingerprint(legacy),
            DeliveryJournalState.Succeeded,
            SuccessReceipt("operation-legacy") with { ArtifactManifestDigest = null },
            legacy.Artifact!.Digest), DeliveryWireCodec.JsonOptions);
        var preChange = canonical.Replace(",\"artifactManifestDigest\":null}", "}", StringComparison.Ordinal);
        await Assert.That(preChange).IsNotEqualTo(canonical);
        await ledger.CreateAsync(LegacyOperationKey("operation-legacy"), preChange, default);

        // The fresh append's prune scan cannot read the legacy record: it must be retained
        // fail-closed (never deleted) while the scan continues to the bounded cap-overflow
        // error — not a raw InvalidDataException escaping the prune and killing every append.
        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-fresh",
                Fingerprint(Request("operation-fresh", ArtifactDigest)),
                DeliveryJournalState.Accepted,
                null,
                ArtifactDigest), default))
            .Throws<JournalRetentionOverflowException>();
        // Both records survive: the unreadable legacy record was not deleted, and the fresh
        // append itself landed before the prune surfaced the bounded overflow.
        await Assert.That(await CountOperationsAsync(ledger)).IsEqualTo(2);
        await Assert.That(await ledger.GetAsync(LegacyOperationKey("operation-legacy"), default))
            .IsNotNull();
    }

    /// <summary>The journal's hashed operation key, mirrored for injecting pre-change bytes.</summary>
    private static string LegacyOperationKey(string operationId) =>
        $"direct.operation.{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(operationId)))}";

    [Test]
    public async Task AReceiptNamingOneArtifactIdentityWithoutTheOtherIsInvalid()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new NatsDirectDeliveryJournal(ledger);
        var request = Request("operation-half-pair", ArtifactDigest);
        var halfPair = SuccessReceipt("operation-half-pair") with { ArtifactManifestDigest = null };

        await Assert.That(async () => await journal.AppendAsync(new(
                "operation-half-pair",
                Fingerprint(request),
                DeliveryJournalState.Succeeded,
                halfPair,
                request.Artifact!.Digest), default))
            .Throws<InvalidDataException>();

        await journal.AppendAsync(new(
            "operation-both-null",
            Fingerprint(request),
            DeliveryJournalState.Failed,
            FailedReceipt(DirectDeliveryErrorCode.HealthFailed, "operation-both-null") with
            {
                ArtifactDigest = null,
                ArtifactManifestDigest = null,
            },
            null), default);
        var record = await journal.ReadAsync("operation-both-null", default);
        await Assert.That(record!.Receipt!.ArtifactDigest).IsNull();
        await Assert.That(record.Receipt.ArtifactManifestDigest).IsNull();
    }

    private static DeliveryRequest Request(string operationId, string artifactDigest) => new(
        1,
        operationId,
        new("TerraScale/TerraScale.Orchestrator", new string('a', 40), ValidDigest),
        new(artifactDigest, ValidDigest, "service"),
        new("authentication", "development", ["gru"]),
        ValidDigest,
        null,
        "actor-1",
        "direct customer change");

    private const string ValidDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ArtifactDigest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    private const string OtherArtifactDigest = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
}

