using System.Text;
using System.Text.Json;

namespace TerraScale.Orchestrator.Delivery.Artifacts;

internal sealed record ArtifactPublicationMessage(ulong Sequence, ReadOnlyMemory<byte> Bytes);

internal interface IArtifactPublicationStore
{
    string Bucket { get; }
    Task<ArtifactPublicationMessage?> ReadNextAsync(string subject, ulong after, CancellationToken cancellationToken);
    // Null means a conditional append lost. An ambiguous acknowledgement must throw;
    // restarting reads the durable prefix before attempting the same append again.
    Task<ulong?> AppendAsync(string subject, ReadOnlyMemory<byte> bytes, ulong expected, CancellationToken cancellationToken);
}

/// <summary>
/// An immutable object-store writer. One deterministic chunk subject per digest, fixed chunk
/// boundaries and subject-sequence CAS make concurrent publishers and crashed retries share
/// a single verified prefix. Metadata is created once, after all bytes have been checked.
/// </summary>
internal sealed class ImmutableArtifactPublisher(IArtifactPublicationStore store)
{
    internal const int ChunkBytes = 128 * 1024;
    private const int MaximumConflicts = 8;

    internal async Task<string> PublishAsync(ArtifactPublicationSnapshot snapshot, CancellationToken cancellationToken)
    {
        var name = "sha256-" + snapshot.Hex;
        var chunkSubject = $"$O.{store.Bucket}.C.{name}";
        var metadataSubject = $"$O.{store.Bucket}.M.{Base64Url(Encoding.UTF8.GetBytes(name))}";
        var metadata = Metadata(snapshot, name);

        var existing = await store.ReadNextAsync(metadataSubject, 0, cancellationToken).ConfigureAwait(false);
        if (existing is not null) RequireBytes(existing, metadata);
        snapshot.Content.Position = 0;
        var buffer = new byte[ChunkBytes];
        ulong sequence = 0;
        while (snapshot.Content.Position < snapshot.Content.Length)
        {
            var count = (int)Math.Min(buffer.Length, snapshot.Content.Length - snapshot.Content.Position);
            await snapshot.Content.ReadExactlyAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            sequence = await EnsureChunkAsync(chunkSubject, buffer.AsMemory(0, count), sequence, existing is null, cancellationToken).ConfigureAwait(false);
        }
        if (await store.ReadNextAsync(chunkSubject, sequence, cancellationToken).ConfigureAwait(false) is not null)
            throw new InvalidDataException("The immutable artifact has unexpected trailing chunks.");
        // Always use CAS, including after an absent or stale metadata read. Never roll up or
        // overwrite an existing name, and never purge another publisher's chunks.
        await EnsureMetadataAsync(metadataSubject, metadata, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return "sha256:" + snapshot.Hex;
    }

    private async Task EnsureMetadataAsync(string subject, ReadOnlyMemory<byte> bytes, CancellationToken cancellationToken)
    {
        for (var conflict = 0; conflict < MaximumConflicts; conflict++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await store.AppendAsync(subject, bytes, 0, cancellationToken).ConfigureAwait(false) is not null) return;
            var current = await store.ReadNextAsync(subject, 0, cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                RequireBytes(current, bytes);
                if (await store.ReadNextAsync(subject, current.Sequence, cancellationToken).ConfigureAwait(false) is not null)
                    throw new InvalidDataException("The immutable artifact has multiple metadata records.");
                return;
            }
            // A competing append may still be committing through the quorum when the
            // server reports an in-flight sequence conflict. Do not spin on that window.
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
        }
        throw new IOException("The artifact metadata is contended; retry publication.");
    }

    private async Task<ulong> EnsureChunkAsync(string subject, ReadOnlyMemory<byte> bytes, ulong after, bool allowAppend, CancellationToken cancellationToken)
    {
        for (var conflict = 0; conflict < MaximumConflicts; conflict++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = await store.ReadNextAsync(subject, after, cancellationToken).ConfigureAwait(false);
            if (current is not null)
            {
                if (current.Sequence <= after) throw new InvalidDataException("The artifact chunk sequence did not advance.");
                RequireBytes(current, bytes);
                return current.Sequence;
            }
            if (!allowAppend) throw new InvalidDataException("A committed immutable artifact is missing chunks.");
            var appended = await store.AppendAsync(subject, bytes, after, cancellationToken).ConfigureAwait(false);
            if (appended is { } sequence)
            {
                if (sequence <= after) throw new InvalidDataException("The artifact append sequence did not advance.");
                return sequence;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken).ConfigureAwait(false);
        }
        throw new IOException("The artifact chunk is contended; retry publication.");
    }

    private static void RequireBytes(ArtifactPublicationMessage message, ReadOnlyMemory<byte> expected)
    {
        if (message.Sequence == 0 || !message.Bytes.Span.SequenceEqual(expected.Span))
            throw new InvalidDataException("Existing immutable artifact content or metadata conflicts with the snapshot.");
    }

    private byte[] Metadata(ArtifactPublicationSnapshot snapshot, string name)
    {
        // This wire layout is fixed independently of SDK model defaults/property order.
        // The object reader supplies mtime from the committed stream message timestamp.
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("name", name);
            writer.WriteString("bucket", store.Bucket);
            writer.WriteString("nuid", name);
            writer.WriteNumber("size", snapshot.Content.Length);
            writer.WriteNumber("chunks", (snapshot.Content.Length + ChunkBytes - 1) / ChunkBytes);
            writer.WriteString("digest", "SHA-256=" + Base64Url(snapshot.Hash));
            writer.WriteStartObject("options");
            writer.WriteNumber("max_chunk_size", ChunkBytes);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    // ObjectStore 2.7.2 uses padded base64url for both metadata subjects and digests.
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');
}
