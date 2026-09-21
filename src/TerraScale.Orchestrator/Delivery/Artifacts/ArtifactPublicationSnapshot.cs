using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Delivery.Artifacts;

/// <summary>Hash and publish the same private snapshot, even if the input file changes.</summary>
internal sealed class ArtifactPublicationSnapshot(FileStream content, byte[] hash) : IAsyncDisposable
{
    internal FileStream Content { get; } = content;
    internal byte[] Hash { get; } = hash;
    internal string Hex { get; } = Convert.ToHexStringLower(hash);

    internal static async Task<ArtifactPublicationSnapshot> CaptureAsync(Stream source, CancellationToken cancellationToken,
        long limit = RegionalArtifactCache.MaximumArtifactBytes)
    {
        if (limit is < 1 or > RegionalArtifactCache.MaximumArtifactBytes) throw new ArgumentOutOfRangeException(nameof(limit));
        var directory = Directory.CreateTempSubdirectory("ts-artifact-publication-");
        FileStream? file = null;
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var path = Path.Combine(directory.FullName, "content");
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.ReadWrite, Share = FileShare.Read | FileShare.Delete,
                Options = FileOptions.Asynchronous | FileOptions.DeleteOnClose
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            file = new(path, options);
            File.Delete(path);
            directory.Delete();
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[ImmutableArtifactPublisher.ChunkBytes];
            while (true)
            {
                var read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (read == 0) break;
                if (file.Length > limit - read) throw new InvalidDataException("The artifact exceeds the publication byte limit.");
                await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                hash.AppendData(buffer, 0, read);
            }
            if (file.Length == 0) throw new InvalidDataException("An artifact must contain bytes.");
            await file.FlushAsync(cancellationToken).ConfigureAwait(false);
            file.Position = 0;
            return new(file, hash.GetHashAndReset());
        }
        catch
        {
            if (file is not null) await file.DisposeAsync().ConfigureAwait(false);
            if (directory.Exists) directory.Delete(true);
            throw;
        }
    }

    public ValueTask DisposeAsync() => Content.DisposeAsync();
}
