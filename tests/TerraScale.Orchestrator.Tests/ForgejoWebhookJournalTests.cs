using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoWebhookJournalTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Delivery = "f6266f16-1bf3-46a5-9ea4-602e06ead473";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");

    [Test]
    public async Task ReplicatedIdentityReservationsBecomeAcknowledgeableAndIdempotent()
    {
        var ledger = new TestLedger();
        var journal = new ForgejoWebhookJournal(ledger);
        var envelope = Envelope("refs/heads/develop", Delivery);

        var accepted = await journal.AcceptAsync(envelope);
        var mutations = ledger.Mutations;
        var duplicate = await journal.AcceptAsync(envelope);

        await Assert.That(accepted.Disposition).IsEqualTo(ForgejoWebhookJournalDisposition.Accepted);
        await Assert.That(accepted.CanAcknowledge).IsTrue();
        await Assert.That(duplicate.Disposition).IsEqualTo(ForgejoWebhookJournalDisposition.Duplicate);
        await Assert.That(duplicate.CanAcknowledge).IsTrue();
        await Assert.That(ledger.Mutations).IsEqualTo(mutations);
        await Assert.That(ledger.Documents).Count().IsEqualTo(2);
        await Assert.That(ledger.Documents.All(document => document.State == ForgejoWebhookJournalState.Accepted)).IsTrue();
    }

    [Test]
    public async Task DeliveryCollisionAndPayloadReplayNeverBecomeAcknowledgeable()
    {
        var collisionLedger = new TestLedger();
        var collisionJournal = new ForgejoWebhookJournal(collisionLedger);
        await collisionJournal.AcceptAsync(Envelope("refs/heads/develop", Delivery));

        var collision = await collisionJournal.AcceptAsync(Envelope("refs/heads/main", Delivery));

        var replayLedger = new TestLedger();
        var replayJournal = new ForgejoWebhookJournal(replayLedger);
        await replayJournal.AcceptAsync(Envelope("refs/heads/develop", Delivery));
        var replayMutations = replayLedger.Mutations;
        var replay = await replayJournal.AcceptAsync(Envelope(
            "refs/heads/develop",
            "7c42695c-8540-4476-9ee3-6c2725647656"));

        await Assert.That(collision.Disposition).IsEqualTo(ForgejoWebhookJournalDisposition.DeliveryCollision);
        await Assert.That(collision.CanAcknowledge).IsFalse();
        await Assert.That(replay.Disposition).IsEqualTo(ForgejoWebhookJournalDisposition.PayloadReplay);
        await Assert.That(replay.CanAcknowledge).IsFalse();
        await Assert.That(replayLedger.Mutations).IsEqualTo(replayMutations);
    }

    [Test]
    public async Task EveryMutationCrashPointResumesBeforeAcknowledgement()
    {
        for (var failure = 1; failure <= 4; failure++)
        {
            var ledger = new TestLedger(failure);
            var journal = new ForgejoWebhookJournal(ledger);
            var envelope = Envelope("refs/heads/develop", Delivery);

            await Assert.That(async () => { await journal.AcceptAsync(envelope); }).Throws<IOException>();
            var recovered = await new ForgejoWebhookJournal(ledger).AcceptAsync(envelope);

            await Assert.That(recovered.CanAcknowledge).IsTrue();
            await Assert.That(ledger.Documents.Count()).IsEqualTo(2);
            await Assert.That(ledger.Documents.All(document => document.State == ForgejoWebhookJournalState.Accepted)).IsTrue();
        }
    }

    [Test]
    public async Task ConcurrentRetriesConvergeOnOneAcceptedIdentityPair()
    {
        var ledger = new TestLedger();
        var journal = new ForgejoWebhookJournal(ledger);
        var envelope = Envelope("refs/heads/develop", Delivery);

        var receipts = await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => journal.AcceptAsync(envelope)));

        await Assert.That(receipts.All(receipt => receipt.CanAcknowledge)).IsTrue();
        await Assert.That(ledger.Documents.Count()).IsEqualTo(2);
        await Assert.That(ledger.Documents.All(document => document.State == ForgejoWebhookJournalState.Accepted)).IsTrue();
    }

    [Test]
    public async Task CorruptDurableIdentityFailsClosedWithoutAcknowledgement()
    {
        var ledger = new TestLedger();
        var journal = new ForgejoWebhookJournal(ledger);
        var envelope = Envelope("refs/heads/develop", Delivery);
        await journal.AcceptAsync(envelope);
        ledger.CorruptFirst();

        await Assert.That(async () => { await journal.AcceptAsync(envelope); }).Throws<InvalidDataException>();
    }

    [Test]
    public async Task GlobalTopologyProvisionsReplicatedBoundedDeliveryJournal()
    {
        var configuration = new GlobalNatsTopology(3).Releases;

        await Assert.That(configuration.Bucket).IsEqualTo("GLOBAL_RELEASES");
        await Assert.That(configuration.NumberOfReplicas).IsEqualTo(3);
        await Assert.That(configuration.History).IsEqualTo(64);
        await Assert.That(configuration.MaxValueSize).IsEqualTo(16 * 1024);
        await Assert.That(configuration.MaxBytes).IsEqualTo(1024L * 1024 * 1024);
    }

    private static ForgejoWebhookEnvelope Envelope(string reference, string delivery)
    {
        var payload = Encoding.UTF8.GetBytes($$$"""
            {"ref":"{{{reference}}}","after":"bffeb74224043ba2feb48d137756c8a9331c449a","repository":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
            """);
        return ForgejoWebhookVerifier.Verify(
            payload,
            Secret,
            Repository,
            "application/json",
            Convert.ToHexStringLower(HMACSHA256.HashData(Secret, payload)),
            delivery,
            "push").Envelope!;
    }

    internal sealed class TestLedger(int failOnMutation = 0) : IForgejoDeliveryLedger
    {
        private readonly Dictionary<string, ForgejoDeliveryLedgerEntry> entries = new(StringComparer.Ordinal);
        private readonly object sync = new();
        private ulong revision;
        private bool failed;

        internal int Mutations { get; private set; }

        internal IReadOnlyList<string> Values
        {
            get
            {
                lock (sync)
                {
                    return entries.Values.Select(static entry => entry.Value).ToArray();
                }
            }
        }

        internal IEnumerable<ForgejoWebhookJournalDocument> Documents
        {
            get
            {
                lock (sync)
                {
                    return entries.Values.Select(entry => JsonSerializer.Deserialize(
                        entry.Value,
                        ForgejoWebhookJournalJsonContext.Default.ForgejoWebhookJournalDocument)!).ToArray();
                }
            }
        }

        public Task<ForgejoDeliveryLedgerEntry?> GetAsync(string key, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                return Task.FromResult(entries.GetValueOrDefault(key));
            }
        }

        public Task<ForgejoDeliveryLedgerEntry> CreateAsync(
            string key,
            string value,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                FailIfRequested();
                if (entries.ContainsKey(key)) throw Conflict();
                var entry = new ForgejoDeliveryLedgerEntry(value, ++revision);
                entries.Add(key, entry);
                return Task.FromResult(entry);
            }
        }

        public Task<ForgejoDeliveryLedgerEntry> UpdateAsync(
            string key,
            string value,
            ulong expectedRevision,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (sync)
            {
                FailIfRequested();
                if (!entries.TryGetValue(key, out var current) || current.Revision != expectedRevision) throw Conflict();
                var entry = new ForgejoDeliveryLedgerEntry(value, ++revision);
                entries[key] = entry;
                return Task.FromResult(entry);
            }
        }

        internal void CorruptFirst()
        {
            lock (sync)
            {
                var first = entries.First();
                entries[first.Key] = new("not-json", ++revision);
            }
        }

        private void FailIfRequested()
        {
            Mutations++;
            if (!failed && Mutations == failOnMutation)
            {
                failed = true;
                throw new IOException("simulated crash");
            }
        }

        private static ForgejoDeliveryLedgerConflictException Conflict() =>
            new(new InvalidOperationException("simulated conflict"));
    }
}
