using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Protocol;

namespace TerraScale.Orchestrator.Tests;

public sealed class NativeGitOpsGlobalHandoffCoordinatorTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private static readonly DateTimeOffset IssuedAt =
        new(2026, 7, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ExpiresAt =
        new(2026, 7, 17, 14, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task DurableSourceCoordinatesOnceAndExactReplayPublishesNothing()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new NativeGitOpsSourceJournalTests.TestManifestStore();
        var sources = new NativeGitOpsSourceJournal(ledger, objects);
        await sources.RecordAsync(
            "develop",
            Source(1, ["gru", "sfo"]),
            authorityEpoch: 7,
            pollSequence: 1,
            expected: null);
        var signer = new TestSigner();
        var transport = new TestTransport(
            new("GLOBAL_SPEC", 31, Duplicate: false),
            new("GLOBAL_SPEC", 32, Duplicate: false));

        var completed = await Coordinator(ledger, objects, sources, transport).CoordinateAsync(
            Repository,
            "develop",
            7,
            IssuedAt,
            ExpiresAt,
            signer,
            static () => true);
        var replayTransport = new TestTransport();
        var replay = await Coordinator(ledger, objects, sources, replayTransport).CoordinateAsync(
            Repository,
            "develop",
            7,
            IssuedAt,
            ExpiresAt,
            signer,
            static () => true);

        await Assert.That(completed.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffCoordinationDisposition.Completed);
        await Assert.That(completed.PreparationDisposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Recorded);
        await Assert.That(completed.Dispatch!.IsComplete).IsTrue();
        await Assert.That(transport.Published.Count).IsEqualTo(2);
        await Assert.That(replay.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffCoordinationDisposition.AlreadyComplete);
        await Assert.That(replay.PreparationDisposition)
            .IsEqualTo(NativeGitOpsSignedHandoffJournalDisposition.Duplicate);
        await Assert.That(replayTransport.Published).IsEmpty();
        await Assert.That(signer.Signatures).IsEqualTo(2);
    }

    [Test]
    public async Task CrashAfterGlobalStorageReusesTheExactSignedMessageOnRetry()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 3);
        var objects = new NativeGitOpsSourceJournalTests.TestManifestStore();
        var sources = new NativeGitOpsSourceJournal(ledger, objects);
        await sources.RecordAsync(
            "develop",
            Source(1, ["gru"]),
            authorityEpoch: 7,
            pollSequence: 1,
            expected: null);
        var signer = new TestSigner();
        var firstTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 41, Duplicate: false));

        await Assert.That(async () => await Coordinator(ledger, objects, sources, firstTransport)
                .CoordinateAsync(
                    Repository,
                    "develop",
                    7,
                    IssuedAt,
                    ExpiresAt,
                    signer,
                    static () => true))
            .Throws<IOException>();
        var retryTransport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 41, Duplicate: true));
        var recovered = await Coordinator(ledger, objects, sources, retryTransport).CoordinateAsync(
            Repository,
            "develop",
            7,
            IssuedAt,
            ExpiresAt,
            signer,
            static () => true);

        await Assert.That(recovered.IsComplete).IsTrue();
        await Assert.That(signer.Signatures).IsEqualTo(1);
        await Assert.That(firstTransport.Published).HasSingleItem();
        await Assert.That(retryTransport.Published).HasSingleItem();
        await Assert.That(firstTransport.Published[0].MessageId)
            .IsEqualTo(retryTransport.Published[0].MessageId);
        await Assert.That(firstTransport.Published[0].Message.Payload.Span.SequenceEqual(
            retryTransport.Published[0].Message.Payload.Span)).IsTrue();
        await Assert.That(firstTransport.Published[0].Message.Headers["TS-Signature"])
            .IsEqualTo(retryTransport.Published[0].Message.Headers["TS-Signature"]);
    }

    [Test]
    public async Task RestartedCoordinatorPublishesTheDurableGuardedRetirementDiff()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new NativeGitOpsSourceJournalTests.TestManifestStore();
        var sources = new NativeGitOpsSourceJournal(ledger, objects);
        await sources.RecordAsync(
            "develop",
            Source(1, ["gru"]),
            authorityEpoch: 7,
            pollSequence: 1,
            expected: null);
        var accepted = await sources.ReadAsync(Repository, "develop");
        await sources.RecordAsync(
            "develop",
            Source(2, [], accepted),
            authorityEpoch: 7,
            pollSequence: 2,
            expected: accepted);
        var transport = new TestTransport(
            new NativeGitOpsGlobalHandoffTransportAck("GLOBAL_SPEC", 51, Duplicate: false));

        var result = await Coordinator(
                ledger,
                objects,
                new NativeGitOpsSourceJournal(ledger, objects),
                transport)
            .CoordinateAsync(
                Repository,
                "develop",
                7,
                IssuedAt,
                ExpiresAt,
                new TestSigner(),
                static () => true);
        var payload = Encoding.UTF8.GetString(transport.Published.Single().Message.Payload.Span);

        await Assert.That(result.IsComplete).IsTrue();
        await Assert.That(payload).Contains("\"kind\":\"GuardedRetirement\"");
        await Assert.That(payload).Contains("\"acceptedGeneration\":1");
        await Assert.That(payload).Contains("\"desiredWorkloads\":[]");
    }

    [Test]
    public async Task MissingOrNewerAuthoritySourceNeverSignsOrPublishes()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var objects = new NativeGitOpsSourceJournalTests.TestManifestStore();
        var sources = new NativeGitOpsSourceJournal(ledger, objects);
        var signer = new TestSigner();
        var transport = new TestTransport();
        var coordinator = Coordinator(ledger, objects, sources, transport);

        var missing = await coordinator.CoordinateAsync(
            Repository,
            "main",
            7,
            IssuedAt,
            ExpiresAt,
            signer,
            static () => true);
        await sources.RecordAsync(
            "develop",
            Source(1, ["gru"]),
            authorityEpoch: 8,
            pollSequence: 1,
            expected: null);
        var newerAuthority = await coordinator.CoordinateAsync(
            Repository,
            "develop",
            7,
            IssuedAt,
            ExpiresAt,
            signer,
            static () => true);

        await Assert.That(missing.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffCoordinationDisposition.SourceMissing);
        await Assert.That(newerAuthority.Disposition)
            .IsEqualTo(NativeGitOpsGlobalHandoffCoordinationDisposition.AuthorityLost);
        await Assert.That(signer.Signatures).IsEqualTo(0);
        await Assert.That(transport.Published).IsEmpty();
    }

    private static NativeGitOpsGlobalHandoffCoordinator Coordinator(
        ForgejoWebhookJournalTests.TestLedger ledger,
        NativeGitOpsSourceJournalTests.TestManifestStore objects,
        NativeGitOpsSourceJournal sources,
        TestTransport transport) => new(
        sources,
        new NativeGitOpsSignedHandoffJournal(ledger, objects),
        new NativeGitOpsGlobalHandoffDispatcher(
            new NativeGitOpsGlobalHandoffPublishJournal(ledger),
            new NativeGitOpsGlobalHandoffPublisher(transport)));

    private static NativeGitOpsSourcePlan Source(
        long generation,
        IReadOnlyList<string> cells,
        NativeGitOpsAcceptedSource? accepted = null)
    {
        var workload = cells.Count == 0
            ? "[]"
            : $"[{{\"id\":\"api\",\"role\":\"Api\",\"artifactDigest\":\"{new string('0', 64)}\",\"cells\":{JsonSerializer.Serialize(cells)}}}]";
        var content = Encoding.UTF8.GetBytes(
            $"{{\"apiVersion\":\"terrascale.io/v1\",\"kind\":\"TerraScaleDesiredState\",\"generation\":{generation},\"workloads\":{workload}}}");
        var proposed = NativeGitOpsManifest.Parse(content);
        var commit = new string(generation == 1 ? 'a' : 'd', 40);
        var tree = new string(generation == 1 ? 'b' : 'e', 40);
        var blob = new string(generation == 1 ? 'c' : 'f', 40);
        return new(
            new(Repository, commit, tree, signatureVerified: true),
            new(
                Repository,
                commit,
                NativeGitOpsSourceLoader.ManifestPath,
                blob,
                Convert.ToHexStringLower(SHA256.HashData(content)),
                content),
            proposed,
            NativeGitOpsDiff.Compare(accepted?.Plan, proposed));
    }

    private sealed class TestSigner : INativeGitOpsCellSpecSigner
    {
        internal int Signatures { get; private set; }

        public OpaqueSignature Sign(CommandSignedMaterial material)
        {
            Signatures++;
            OpaqueSignature.TryCopyFrom([1, 2, checked((byte)Signatures)], out var signature);
            return signature!;
        }
    }

    private sealed class TestTransport(params NativeGitOpsGlobalHandoffTransportAck[] acknowledgements)
        : INativeGitOpsGlobalHandoffTransport
    {
        private readonly Queue<NativeGitOpsGlobalHandoffTransportAck> acknowledgements =
            new(acknowledgements);

        internal List<PublishedMessage> Published { get; } = [];

        public Task<NativeGitOpsGlobalHandoffTransportAck> PublishAsync(
            string subject,
            string messageId,
            NativeGitOpsCellWireMessage message,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Published.Add(new(subject, messageId, message));
            return Task.FromResult(acknowledgements.Dequeue());
        }
    }

    private sealed record PublishedMessage(
        string Subject,
        string MessageId,
        NativeGitOpsCellWireMessage Message);
}
