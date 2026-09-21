using System.Security.Cryptography;
using NATS.Client.ObjectStore;

namespace TerraScale.Orchestrator.ControlPlane.Delivery;

internal sealed record RegionalArtifactChunk(long TotalBytes, byte[] Bytes);

/// <summary>Controller-private bytes. Callers must separately authorize every chunk release.</summary>
internal interface IRegionalArtifactReader
{
    Task<RegionalArtifactChunk> ReadAsync(string digest, long offset, int length, CancellationToken cancellationToken);
}

internal interface IRegionalArtifactDownloader
{
    Task CopyAsync(string digest, Stream destination, CancellationToken cancellationToken);
}

internal sealed class NatsRegionalArtifactDownloader(INatsObjStore store) : IRegionalArtifactDownloader
{
    public async Task CopyAsync(string digest, Stream destination, CancellationToken cancellationToken)
    {
        var name = "sha256-" + digest[7..];
        var before = await store.GetInfoAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (before.Name != name || before.Deleted || before.Options?.Link is not null || string.IsNullOrEmpty(before.Nuid) ||
            before.Size is 0 or > RegionalArtifactCache.MaximumArtifactBytes)
            throw new InvalidDataException("The regional artifact metadata is not a bounded direct object.");
        var after = await store.GetAsync(name, destination, leaveOpen: true, cancellationToken).ConfigureAwait(false);
        // The SDK follows links internally. Reject a metadata change between its lookup and ours;
        // the cache also verifies the requested content digest before making any bytes available.
        if (after.Name != name || after.Deleted || after.Options?.Link is not null || after.Nuid != before.Nuid ||
            after.Size != before.Size || after.Digest != before.Digest)
            throw new InvalidDataException("The regional artifact changed during download.");
    }
}

/// <summary>
/// Bounded, disposable controller cache. One download can outlive request cancellation, with its
/// own deadline; a dependency ignoring that deadline cannot accumulate additional downloads.
/// Files are unlinked immediately and only digest-verified handles enter the LRU.
/// </summary>
internal sealed class RegionalArtifactCache : IRegionalArtifactReader, IDisposable
{
    internal const int MaximumChunkBytes = 524_288;
    internal const long MaximumArtifactBytes = 512L * 1024 * 1024;
    internal const long MaximumCacheBytes = 2 * MaximumArtifactBytes;
    private const int MaximumEntries = 8;
    private readonly IRegionalArtifactDownloader downloader;
    private readonly long artifactLimit;
    private readonly long cacheLimit;
    private readonly TimeSpan downloadTimeout;
    private readonly Lock gate = new();
    private readonly CancellationTokenSource stopping = new();
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private Task? download;
    private string? downloadingDigest;
    private long bytes;
    private long sequence;
    private bool disposed;

    internal RegionalArtifactCache(IRegionalArtifactDownloader downloader, long artifactLimit = MaximumArtifactBytes,
        long cacheLimit = MaximumCacheBytes, TimeSpan? downloadTimeout = null)
    {
        if (artifactLimit is < 1 or > MaximumArtifactBytes || cacheLimit < artifactLimit || cacheLimit > MaximumCacheBytes)
            throw new ArgumentOutOfRangeException(nameof(artifactLimit));
        this.downloader = downloader;
        this.artifactLimit = artifactLimit;
        this.cacheLimit = cacheLimit;
        this.downloadTimeout = downloadTimeout ?? TimeSpan.FromMinutes(2);
        if (this.downloadTimeout <= TimeSpan.Zero || this.downloadTimeout > TimeSpan.FromMinutes(2))
            throw new ArgumentOutOfRangeException(nameof(downloadTimeout));
    }

    internal (long Bytes, int Entries, bool Downloading) Snapshot
    {
        get { lock (gate) return (bytes, entries.Count, download is { IsCompleted: false }); }
    }

    public async Task<RegionalArtifactChunk> ReadAsync(string digest, long offset, int length, CancellationToken cancellationToken)
    {
        if (!HostDesiredArtifactReader.ValidDigest(digest) || digest != digest.ToLowerInvariant() ||
            offset < 0 || offset >= artifactLimit || length is < 1 or > MaximumChunkBytes)
            throw new ArgumentException("Artifact reads require a canonical digest and bounded range.");
        Task? loading = null;
        Entry? entry;
        lock (gate)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (!entries.TryGetValue(digest, out entry))
            {
                if (download is { IsCompleted: false })
                {
                    if (downloadingDigest != digest) throw new IOException("The regional artifact cache is busy.");
                }
                else
                {
                    // Reserve the maximum, including a partial file, before starting any I/O.
                    while (bytes > cacheLimit - artifactLimit || entries.Count >= MaximumEntries)
                    {
                        var victim = entries.Where(pair => pair.Value.Readers == 0).OrderBy(pair => pair.Value.Used).FirstOrDefault();
                        if (victim.Value is null) throw new IOException("The regional artifact cache is pinned.");
                        entries.Remove(victim.Key);
                        bytes -= victim.Value.Length;
                        victim.Value.File.Dispose();
                    }
                    downloadingDigest = digest;
                    var token = stopping.Token;
                    download = Task.Run(() => DownloadAsync(digest, token), CancellationToken.None);
                    _ = download.ContinueWith(static task => _ = task.Exception, CancellationToken.None,
                        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                }
                loading = download;
            }
            else Pin(entry);
        }
        if (loading is not null)
        {
            await loading.WaitAsync(cancellationToken).ConfigureAwait(false);
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                if (!entries.TryGetValue(digest, out entry)) throw new IOException("The regional artifact was evicted; retry the request.");
                Pin(entry);
            }
        }
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry is null || offset >= entry.Length) throw new InvalidDataException("The artifact range is outside its content.");
            var buffer = new byte[(int)Math.Min(length, entry.Length - offset)];
            var read = 0;
            while (read < buffer.Length)
            {
                var count = await RandomAccess.ReadAsync(entry.File.SafeFileHandle, buffer.AsMemory(read), offset + read,
                    cancellationToken).ConfigureAwait(false);
                if (count == 0) throw new InvalidDataException("The cached artifact is truncated.");
                read += count;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(entry.Length, buffer);
        }
        finally
        {
            if (entry is not null)
                lock (gate)
                {
                    entry.Readers--;
                    if (disposed && entry.Readers == 0) entry.File.Dispose();
                }
        }
    }

    private void Pin(Entry entry) { entry.Readers++; entry.Used = ++sequence; }

    private async Task DownloadAsync(string digest, CancellationToken stoppingToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        deadline.CancelAfter(downloadTimeout);
        FileStream? file = null;
        try
        {
            file = CreatePrivateFile();
            using var writer = new BoundedArtifactWriter(file, artifactLimit, deadline.Token);
            await downloader.CopyAsync(digest, writer, deadline.Token).ConfigureAwait(false);
            deadline.Token.ThrowIfCancellationRequested();
            if (writer.Written == 0 || writer.Digest() != digest)
                throw new InvalidDataException("The regional artifact failed its requested content digest check.");
            await file.FlushAsync(deadline.Token).ConfigureAwait(false);
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                deadline.Token.ThrowIfCancellationRequested();
                entries.Add(digest, new(file, writer.Written, ++sequence));
                bytes += writer.Written;
                file = null;
            }
        }
        finally { file?.Dispose(); }
    }

    private static FileStream CreatePrivateFile()
    {
        var directory = Directory.CreateTempSubdirectory("ts-regional-artifact-");
        FileStream? file = null;
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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
            return file;
        }
        catch { file?.Dispose(); if (directory.Exists) directory.Delete(true); throw; }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            foreach (var entry in entries.Values)
                if (entry.Readers == 0) entry.File.Dispose();
            entries.Clear();
            bytes = 0;
        }
        stopping.Cancel();
        stopping.Dispose();
    }

    private sealed class Entry(FileStream file, long length, long used)
    {
        internal FileStream File { get; } = file;
        internal long Length { get; } = length;
        internal long Used { get; set; } = used;
        internal int Readers { get; set; }
    }

    private sealed class BoundedArtifactWriter(Stream destination, long limit, CancellationToken deadline) : Stream
    {
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        internal long Written { get; private set; }
        internal string Digest() => "sha256:" + Convert.ToHexStringLower(hash.GetHashAndReset());
        private void Check(int count)
        {
            deadline.ThrowIfCancellationRequested();
            if (count > limit - Written) throw new InvalidDataException("The regional artifact exceeds its byte limit.");
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Check(buffer.Length);
            destination.Write(buffer);
            hash.AppendData(buffer);
            Written += buffer.Length;
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Check(buffer.Length);
            cancellationToken.ThrowIfCancellationRequested();
            await destination.WriteAsync(buffer, deadline).ConfigureAwait(false);
            hash.AppendData(buffer.Span);
            Written += buffer.Length;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        protected override void Dispose(bool disposing) { if (disposing) hash.Dispose(); base.Dispose(disposing); }
        public override void Flush() { deadline.ThrowIfCancellationRequested(); destination.Flush(); }
        public override Task FlushAsync(CancellationToken cancellationToken) => destination.FlushAsync(cancellationToken);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Written;
        public override long Position { get => Written; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
