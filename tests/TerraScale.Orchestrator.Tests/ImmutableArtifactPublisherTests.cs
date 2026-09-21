using System.Security.Cryptography;
using TerraScale.Orchestrator.Delivery.Artifacts;

namespace TerraScale.Orchestrator.Tests;

public sealed class ImmutableArtifactPublisherTests
{
    [Test]
    public async Task Concurrent_and_repeated_publishers_share_exactly_one_chunk_prefix_and_metadata_record()
    {
        var bytes = RandomNumberGenerator.GetBytes(2 * ImmutableArtifactPublisher.ChunkBytes + 17);
        var store = new Store();
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            await using var snapshot = await Capture(bytes);
            return await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        }));
        await Assert.That(results.Distinct().Count()).IsEqualTo(1);
        await Assert.That(store.Messages.Count).IsEqualTo(4);
        await using var repeated = await Capture(bytes);
        await new ImmutableArtifactPublisher(store).PublishAsync(repeated, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(4);
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task Lost_chunk_or_metadata_acknowledgements_resume_after_restart_without_extra_bytes(int lostAppend)
    {
        var bytes = RandomNumberGenerator.GetBytes(ImmutableArtifactPublisher.ChunkBytes + 17);
        var store = new Store { LoseAcknowledgement = lostAppend };
        await using (var first = await Capture(bytes))
            await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(first, CancellationToken.None)).Throws<IOException>();
        await using var retry = await Capture(bytes);
        await new ImmutableArtifactPublisher(store).PublishAsync(retry, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(3);
        await Assert.That(store.Messages.Where(entry => entry.Subject.Contains(".C.", StringComparison.Ordinal))
            .SelectMany(entry => entry.Bytes).SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    [Arguments("metadata")]
    [Arguments("chunk")]
    [Arguments("missing")]
    [Arguments("trailing")]
    [Arguments("extra-metadata")]
    public async Task Poisoned_committed_objects_are_rejected_without_repair_or_replacement(string poison)
    {
        byte[] bytes = [1, 2, 3];
        var store = new Store();
        await using var snapshot = await Capture(bytes);
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        switch (poison)
        {
            case "metadata": store.Messages[1].Bytes[0] ^= 1; break;
            case "chunk": store.Messages[0].Bytes[0] ^= 1; break;
            case "missing": store.Messages.RemoveAt(0); break;
            case "trailing": store.Messages.Add(new(store.Messages[0].Subject, 3, [9])); break;
            case "extra-metadata": store.Messages.Add(new(store.Messages[1].Subject, 3, [9])); break;
        }
        var before = Fingerprint(store);
        await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None)).Throws<InvalidDataException>();
        await Assert.That(Fingerprint(store)).IsEqualTo(before);
    }

    [Test]
    public async Task Poisoned_partial_prefix_is_rejected_without_publishing_metadata()
    {
        var store = new Store { LoseAcknowledgement = 1 };
        await using var snapshot = await Capture([1, 2, 3]);
        await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None)).Throws<IOException>();
        store.Messages[0].Bytes[0] ^= 1;
        await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None)).Throws<InvalidDataException>();
        await Assert.That(store.Messages.Count).IsEqualTo(1);
    }

    [Test]
    public async Task Stale_absence_cannot_duplicate_an_existing_chunk_or_metadata()
    {
        var store = new Store();
        await using var snapshot = await Capture([1, 2, 3]);
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        store.HideNextReads = 2;
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(2);
    }

    [Test]
    public async Task In_flight_metadata_conflicts_retry_until_the_committed_winner_is_visible()
    {
        var store = new Store { CompetingMetadataCommit = true, HideCommittedMetadataReads = 2 };
        await using var snapshot = await Capture([1, 2, 3]);
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(2);
        await Assert.That(store.HideCommittedMetadataReads).IsEqualTo(0);
    }

    [Test]
    public async Task An_invisible_metadata_winner_has_a_bounded_conflict_budget()
    {
        var store = new Store { CompetingMetadataCommit = true, HideCommittedMetadataReads = 20 };
        await using var snapshot = await Capture([1, 2, 3]);
        await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None))
            .Throws<IOException>();
        await Assert.That(store.Messages.Count).IsEqualTo(2);
        await Assert.That(store.HideCommittedMetadataReads).IsEqualTo(12);
        store.HideCommittedMetadataReads = 0;
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Snapshot_is_independent_of_source_mutation_and_bounds_temporary_storage()
    {
        byte[] bytes = [1, 2, 3];
        using var source = new MemoryStream(bytes, writable: true);
        await using var snapshot = await ArtifactPublicationSnapshot.CaptureAsync(source, CancellationToken.None);
        source.Position = 0;
        source.WriteByte(9);
        var store = new Store();
        var digest = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        await Assert.That(digest).IsEqualTo("sha256:" + Convert.ToHexStringLower(SHA256.HashData(new byte[] { 1, 2, 3 })));
        await Assert.That(store.Messages[0].Bytes.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        await Assert.That(async () => _ = await ArtifactPublicationSnapshot.CaptureAsync(new MemoryStream([1, 2, 3]), CancellationToken.None, limit: 2))
            .Throws<InvalidDataException>();
        await Assert.That(async () => _ = await ArtifactPublicationSnapshot.CaptureAsync(new MemoryStream(), CancellationToken.None))
            .Throws<InvalidDataException>();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.That(async () => _ = await ArtifactPublicationSnapshot.CaptureAsync(new MemoryStream([1]), cancelled.Token))
            .Throws<OperationCanceledException>();
    }

    [Test]
    public async Task Publication_cancellation_leaves_a_resumable_prefix_and_no_metadata()
    {
        var store = new Store();
        using var stopping = new CancellationTokenSource();
        store.AfterAppend = () => stopping.Cancel();
        var bytes = new byte[ImmutableArtifactPublisher.ChunkBytes + 1];
        await using var snapshot = await Capture(bytes);
        await Assert.That(async () => _ = await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, stopping.Token)).Throws<OperationCanceledException>();
        await Assert.That(store.Messages.Count).IsEqualTo(1);
        store.AfterAppend = null;
        await new ImmutableArtifactPublisher(store).PublishAsync(snapshot, CancellationToken.None);
        await Assert.That(store.Messages.Count).IsEqualTo(3);
    }

    private static Task<ArtifactPublicationSnapshot> Capture(byte[] bytes) =>
        ArtifactPublicationSnapshot.CaptureAsync(new MemoryStream(bytes), CancellationToken.None);

    private static string Fingerprint(Store store) => string.Join('|', store.Messages.Select(entry =>
        entry.Subject + ":" + entry.Sequence + ":" + Convert.ToHexString(entry.Bytes)));

    private sealed record Entry(string Subject, ulong Sequence, byte[] Bytes);

    private sealed class Store : IArtifactPublicationStore
    {
        private readonly Lock gate = new();
        private ulong sequence;
        internal List<Entry> Messages { get; } = [];
        internal int LoseAcknowledgement { get; init; }
        internal int HideNextReads { get; set; }
        internal int HideCommittedMetadataReads { get; set; }
        internal bool CompetingMetadataCommit { get; init; }
        internal Action? AfterAppend { get; set; }
        public string Bucket => "ORCH_ARTIFACTS";

        public async Task<ArtifactPublicationMessage?> ReadNextAsync(string subject, ulong after, CancellationToken cancellationToken)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (HideNextReads > 0) { HideNextReads--; return null; }
                var entry = Messages.FirstOrDefault(entry => entry.Subject == subject && entry.Sequence > after);
                if (entry is not null && subject.Contains(".M.", StringComparison.Ordinal) && HideCommittedMetadataReads > 0)
                {
                    HideCommittedMetadataReads--;
                    return null;
                }
                return entry is null ? null : new(entry.Sequence, entry.Bytes.ToArray());
            }
        }

        public async Task<ulong?> AppendAsync(string subject, ReadOnlyMemory<byte> bytes, ulong expected, CancellationToken cancellationToken)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            lock (gate)
            {
                if ((Messages.LastOrDefault(entry => entry.Subject == subject)?.Sequence ?? 0) != expected) return null;
                Messages.Add(new(subject, ++sequence, bytes.ToArray()));
                AfterAppend?.Invoke();
                if (sequence == (ulong)LoseAcknowledgement) throw new IOException("Injected lost acknowledgement after durable append.");
                if (CompetingMetadataCommit && subject.Contains(".M.", StringComparison.Ordinal)) return null;
                return sequence;
            }
        }
    }
}
