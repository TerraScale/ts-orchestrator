using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoCiTriggerJournalTests
{
    [Test]
    public async Task LeaderPersistsTheExactTriggerDecisionBeforeAcknowledgement()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var envelope = Push("refs/heads/develop");
        var handler = new ForgejoCiInboxHandler(
            new(ledger),
            () => Authority(isLeader: true));

        var receipt = await handler.HandleAsync(Payload(envelope));
        var recovered = await new ForgejoCiTriggerJournal(ledger).ReadAsync(envelope.DedupeKey);

        await Assert.That(receipt.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.Recorded);
        await Assert.That(receipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Dispatch);
        await Assert.That(recovered).IsNotNull();
        await Assert.That(recovered!.Reason).IsEqualTo(ForgejoCiTriggerReason.DevelopValidation);
        await Assert.That(recovered.Capabilities).IsEquivalentTo(receipt.Plan.Capabilities);
    }

    [Test]
    public async Task IgnoredAndHeldEventsAreAlsoDurableDecisions()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoCiTriggerJournal(ledger);
        var ignored = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/feature/example"));
        var held = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/main", deletion: true));

        var ignoredReceipt = await journal.RecordAsync(ignored, 7, 9, static () => true);
        var heldReceipt = await journal.RecordAsync(held, 7, 9, static () => true);

        await Assert.That(ignoredReceipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Ignored);
        await Assert.That(heldReceipt.Plan.Disposition).IsEqualTo(ForgejoCiTriggerDisposition.Held);
        await Assert.That(ledger.Mutations).IsEqualTo(2);
    }

    [Test]
    public async Task FollowersAndLeadershipLossCannotCommit()
    {
        var envelope = Push("refs/heads/develop");
        var followerLedger = new ForgejoWebhookJournalTests.TestLedger();
        var follower = await new ForgejoCiInboxHandler(
                new(followerLedger),
                () => Authority(isLeader: false))
            .HandleAsync(Payload(envelope));

        var lossLedger = new ForgejoWebhookJournalTests.TestLedger();
        var calls = 0;
        var lost = await new ForgejoCiInboxHandler(
                new(lossLedger),
                () => ++calls == 1 ? Authority(isLeader: true) : Authority(isLeader: false))
            .HandleAsync(Payload(envelope));

        await Assert.That(follower.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.StaleAuthority);
        await Assert.That(lost.Disposition).IsEqualTo(ForgejoCiTriggerJournalDisposition.StaleAuthority);
        await Assert.That(followerLedger.Mutations).IsEqualTo(0);
        await Assert.That(lossLedger.Mutations).IsEqualTo(0);
    }

    [Test]
    public async Task ConcurrentDeliveryConvergesOnOneDecision()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var plan = ForgejoCiTriggerPlanner.Plan(Push("refs/heads/develop"));
        var journal = new ForgejoCiTriggerJournal(ledger);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ =>
            journal.RecordAsync(plan, 7, 9, static () => true)));

        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoCiTriggerJournalDisposition.Recorded)).IsEqualTo(1);
        await Assert.That(receipts.Count(receipt =>
            receipt.Disposition == ForgejoCiTriggerJournalDisposition.Duplicate)).IsEqualTo(15);
        await Assert.That(ledger.Mutations).IsEqualTo(1);
    }

    [Test]
    public async Task CorruptEventOrDecisionFailsClosed()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var envelope = Push("refs/heads/develop");
        var journal = new ForgejoCiTriggerJournal(ledger);
        await journal.RecordAsync(
            ForgejoCiTriggerPlanner.Plan(envelope),
            7,
            9,
            static () => true);
        ledger.CorruptFirst();

        await Assert.That(async () => await journal.ReadAsync(envelope.DedupeKey))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new ForgejoCiInboxHandler(
                new(new ForgejoWebhookJournalTests.TestLedger()),
                () => Authority(isLeader: true))
            .HandleAsync("not-json"))
            .Throws<InvalidDataException>();
    }

    private static string Payload(ForgejoWebhookEnvelope envelope) => JsonSerializer.Serialize(
        ForgejoWebhookEventDocument.From(envelope),
        ForgejoWebhookEventJsonContext.Default.ForgejoWebhookEventDocument);

    [Test]
    public async Task IgnoredTriggerHistoryIsBoundedOldestFirst()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoCiTriggerJournal(ledger, triggerHistoryCap: 2);

        foreach (var index in new[] { 1, 2, 3 })
            await journal.RecordAsync(
                ForgejoCiTriggerPlanner.Plan(Push($"refs/heads/feature/bound-{index}")), 7, 9, static () => true);

        await Assert.That(await CountTriggersAsync(ledger)).IsEqualTo(2);
        await Assert.That(await journal.ReadAsync(Push("refs/heads/feature/bound-1").DedupeKey)).IsNull();
        await Assert.That(await journal.ReadAsync(Push("refs/heads/feature/bound-3").DedupeKey)).IsNotNull();
    }

    [Test]
    public async Task AnUnprunableInFlightTriggerHistoryFailsClosedInsteadOfGrowing()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoCiTriggerJournal(ledger, triggerHistoryCap: 2, dispatchAnchorRevisionHorizon: 1_000);
        foreach (var index in new[] { 1, 2 })
            await journal.RecordAsync(ForgejoCiTriggerPlanner.Plan(DispatchPush(index)), 7, 9, static () => true);

        await Assert.That(async () => await journal.RecordAsync(
                ForgejoCiTriggerPlanner.Plan(DispatchPush(3)), 7, 9, static () => true))
            .Throws<JournalRetentionOverflowException>();
        await Assert.That(await CountTriggersAsync(ledger)).IsEqualTo(3);
    }

    [Test]
    public async Task DispatchAnchorsBecomePrunableAfterTheAgeHorizonWithoutAPipeline()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        // Horizon 0: any Dispatch anchor whose pipeline never appeared is dead weight.
        var journal = new ForgejoCiTriggerJournal(ledger, triggerHistoryCap: 2, dispatchAnchorRevisionHorizon: 0);

        foreach (var seed in new[] { 1, 2, 3 })
            await journal.RecordAsync(ForgejoCiTriggerPlanner.Plan(DispatchPush(seed)), 7, 9, static () => true);

        await Assert.That(await CountTriggersAsync(ledger)).IsEqualTo(2);
        await Assert.That(await journal.ReadAsync(DispatchPush(1).DedupeKey)).IsNull();
        await Assert.That(await journal.ReadAsync(DispatchPush(3).DedupeKey)).IsNotNull();
    }

    [Test]
    public async Task DispatchAnchorsInsideTheHorizonStayEvenWithoutPipelines()
    {
        var ledger = new ForgejoWebhookJournalTests.TestLedger();
        var journal = new ForgejoCiTriggerJournal(ledger, triggerHistoryCap: 2, dispatchAnchorRevisionHorizon: 1_000);

        foreach (var seed in new[] { 1, 2 })
            await journal.RecordAsync(ForgejoCiTriggerPlanner.Plan(DispatchPush(seed)), 7, 9, static () => true);

        var overflow = ForgejoCiTriggerPlanner.Plan(DispatchPush(3));
        await Assert.That(async () => await journal.RecordAsync(overflow, 7, 9, static () => true))
            .Throws<JournalRetentionOverflowException>();
        await Assert.That(await CountTriggersAsync(ledger)).IsEqualTo(3);
    }

    [Test]
    public async Task CapOverflowIsOperationalRetryNeverATerminablePayloadFailure()
    {
        // The consumer classifies overflow as loud-log + retry and deterministic durable
        // conflicts as terminal; this pins the mapping the event loop depends on.
        var overflow = new JournalRetentionOverflowException("cap exceeded");
        var durable = new InvalidDataException("durable conflict");

        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(overflow))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(durable))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(new IOException("transient")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        // Process-stage deterministic throws (controller fail-closed, gate rejection, retired
        // schema restore) are Terminal-with-loud-log: an operator-visible decision, never a
        // silent loop catch that would burn MaxDeliver and drop CI invisibly.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(
                new InvalidDataException("Repository CI run coordination failed closed: IdentityConflict.")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Terminal);
        // A lease-loss wrapper around a transient transport failure retries: the server
        // redelivers anyway, and terminating would lose the event.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(
                new InvalidDataException("The CI controller lost its Forgejo delivery lease.", new IOException("ack timeout"))))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
        // Retention overflow raised from inside the process stage (pipeline/attestation prunes)
        // is operational: retry with a loud log, never terminate the healthy event.
        await Assert.That(ForgejoCiEventConsumer.ClassifyFailure(
                new JournalRetentionOverflowException("cap exceeded from a nested prune")))
            .IsEqualTo(ForgejoCiEventProcessDisposition.Retry);
    }

    private static ForgejoWebhookEnvelope DispatchPush(int seed) => Push("refs/heads/develop", seed);

    private static async Task<int> CountTriggersAsync(ForgejoWebhookJournalTests.TestLedger ledger)
    {
        var count = 0;
        await foreach (var key in ledger.ListKeysAsync("ci-trigger.>", default))
            count++;
        return count;
    }

    [Test]
    public async Task DisabledRuntimeProofConsumerNeverFetchesADelivery()
    {
        // The inbox is never invoked (NextAsync returns no message); it only has to be real.
        var inbox = new RepositoryCiRuntimeObservationInbox(
            new RepositoryCiArtifactAttestationJournal(
                new ForgejoWebhookJournalTests.TestLedger(),
                new NullObjectStore()),
            new NullSignatureVerifier());
        var topology = new GlobalNatsTopology(3);
        var authority = new RegionalAuthoritySnapshot(
            "leader", true, 5, 9,
            DateTimeOffset.UtcNow.AddMinutes(1), DateTimeOffset.UtcNow, null);
        RegionalAuthoritySnapshot ReadyLeader() => authority;

        var disabledFetch = new FetchCountingConsumer();
        await using (RepositoryCiRuntimeObservationNatsConsumer.Start(
            disabledFetch, inbox, ReadyLeader, topology, enabled: false))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(300));
            await Assert.That(disabledFetch.Fetches).IsEqualTo(0);
        }

        var enabledFetch = new FetchCountingConsumer();
        await using (RepositoryCiRuntimeObservationNatsConsumer.Start(
            enabledFetch, inbox, ReadyLeader, topology, enabled: true))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(300));
            await Assert.That(enabledFetch.Fetches).IsGreaterThan(0);
        }
    }

    private sealed class NullObjectStore : IDeliveryObjectStore
    {
        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Not expected in this test.");
    }

    private sealed class NullSignatureVerifier : IRepositoryCiArtifactSignatureVerifier
    {
        public TerraScale.Orchestrator.Protocol.VerificationOutcome Verify(
            string signingIdentity,
            ReadOnlyMemory<byte> canonicalMaterial,
            TerraScale.Orchestrator.Protocol.OpaqueSignature signature) =>
            TerraScale.Orchestrator.Protocol.VerificationOutcome.Invalid;
    }

    /// <summary>Records NextAsync calls; returns no message so the loop keeps polling.</summary>
    private sealed class FetchCountingConsumer : NATS.Client.JetStream.INatsJSConsumer
    {
        private int fetches;

        public int Fetches => Volatile.Read(ref fetches);

        public NATS.Client.JetStream.Models.ConsumerInfo Info =>
            throw new InvalidOperationException("A disabled consumer must never inspect consumer info.");

        public IAsyncEnumerable<NATS.Client.JetStream.INatsJSMsg<T>> ConsumeAsync<T>(
            NATS.Client.Core.INatsDeserialize<T>? serializer = null,
            NATS.Client.JetStream.NatsJSConsumeOpts? opts = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("A disabled consumer must never consume.");

        public ValueTask<NATS.Client.JetStream.INatsJSMsg<T>?> NextAsync<T>(
            NATS.Client.Core.INatsDeserialize<T>? serializer = null,
            NATS.Client.JetStream.NatsJSNextOpts? opts = null,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref fetches);
            return ValueTask.FromResult<NATS.Client.JetStream.INatsJSMsg<T>?>(null);
        }

        public IAsyncEnumerable<NATS.Client.JetStream.INatsJSMsg<T>> FetchAsync<T>(
            NATS.Client.JetStream.NatsJSFetchOpts opts,
            NATS.Client.Core.INatsDeserialize<T>? serializer = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("A disabled consumer must never fetch.");

        public IAsyncEnumerable<NATS.Client.JetStream.INatsJSMsg<T>> FetchNoWaitAsync<T>(
            NATS.Client.JetStream.NatsJSFetchOpts opts,
            NATS.Client.Core.INatsDeserialize<T>? serializer = null,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("A disabled consumer must never fetch.");

        public ValueTask RefreshAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("A disabled consumer must never refresh.");

        public ValueTask UnpinAsync(string consumerName, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("A disabled consumer must never unpin.");
    }

    private static ForgejoWebhookEnvelope Push(string reference, bool deletion = false) => Push(
        reference,
        deletion,
        "f6266f16-1bf3-46a5-9ea4-602e06ead473");

    private static ForgejoWebhookEnvelope Push(string reference, int seed) => Push(
        reference,
        deletion: false,
        $"{seed:d8}-0000-4000-8000-{seed:d12}");

    private static ForgejoWebhookEnvelope Push(string reference, bool deletion, string identity) => new(
        Guid.Parse(identity),
        ForgejoWebhookKind.Push,
        "push",
        "TerraScale/TerraScale.Orchestrator",
        "TerraScale/TerraScale.Orchestrator",
        "affe000000000000000000000000000000000001",
        deletion ? new string('0', 40) : "bffeb74224043ba2feb48d137756c8a9331c449a",
        reference,
        null,
        null,
        deletion,
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{reference}:{deletion}:{identity}"))));

    private static RegionalAuthoritySnapshot Authority(bool isLeader) => new(
        isLeader ? "leader" : "follower",
        isLeader,
        7,
        9,
        DateTimeOffset.UtcNow.AddSeconds(10),
        DateTimeOffset.UtcNow,
        null);
}
