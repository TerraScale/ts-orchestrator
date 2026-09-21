using System.Security.Cryptography;
using TerraScale.Orchestrator.ControlPlane.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RegionalArtifactCacheTests
{
    [Test]
    public async Task Concurrent_and_sequential_ranges_share_one_verified_download_and_bound_memory()
    {
        var bytes = RandomNumberGenerator.GetBytes(2 * RegionalArtifactCache.MaximumChunkBytes + 17);
        var downloader = new Downloader((_, stream, token) => stream.WriteAsync(bytes, token).AsTask());
        using var cache = new RegionalArtifactCache(downloader);
        var digest = Digest(bytes);
        var chunks = await Task.WhenAll(Enumerable.Range(0, 3).Select(index =>
            cache.ReadAsync(digest, index * RegionalArtifactCache.MaximumChunkBytes, RegionalArtifactCache.MaximumChunkBytes, CancellationToken.None)));
        await Assert.That(chunks.SelectMany(chunk => chunk.Bytes).SequenceEqual(bytes)).IsTrue();
        await Assert.That(chunks.All(chunk => chunk.TotalBytes == bytes.Length)).IsTrue();
        await Assert.That(downloader.Calls).IsEqualTo(1);
        await Assert.That(cache.Snapshot.Bytes).IsEqualTo(bytes.LongLength);
        await Assert.That((await cache.ReadAsync(digest, 2, 10, CancellationToken.None)).Bytes.SequenceEqual(bytes[2..12])).IsTrue();
        await Assert.That(downloader.Calls).IsEqualTo(1);
    }

    [Test]
    [Arguments("corrupt")]
    [Arguments("empty")]
    [Arguments("truncated")]
    [Arguments("oversize")]
    [Arguments("exception")]
    public async Task Failed_downloads_release_no_bytes_and_do_not_poison_retries(string fault)
    {
        byte[] bytes = [1, 2, 3, 4];
        var fail = true;
        var downloader = new Downloader(async (_, stream, token) =>
        {
            var payload = fail ? fault switch { "corrupt" => new byte[] { 9, 8 }, "empty" => [], "truncated" => bytes[..2],
                "oversize" => new byte[9], _ => bytes } : bytes;
            await stream.WriteAsync(payload, token);
            if (fail && fault == "exception") throw new IOException("Injected failure after writing content.");
        });
        using var cache = new RegionalArtifactCache(downloader, 8, 16);
        if (fault == "exception")
            await Assert.That(async () => _ = await cache.ReadAsync(Digest(bytes), 0, 4, CancellationToken.None)).Throws<IOException>();
        else
            await Assert.That(async () => _ = await cache.ReadAsync(Digest(bytes), 0, 4, CancellationToken.None)).Throws<InvalidDataException>();
        await Assert.That(cache.Snapshot.Bytes).IsEqualTo(0);
        await Assert.That(cache.Snapshot.Entries).IsEqualTo(0);
        fail = false;
        await Assert.That((await cache.ReadAsync(Digest(bytes), 0, 4, CancellationToken.None)).Bytes.SequenceEqual(bytes)).IsTrue();
        await Assert.That(downloader.Calls).IsEqualTo(2);
    }

    [Test]
    public async Task Cache_evicts_by_recency_and_reserves_partial_download_space()
    {
        var payloads = Enumerable.Range(1, 4).Select(value => Enumerable.Repeat((byte)value, 8).ToArray()).ToDictionary(Digest);
        var downloader = new Downloader((digest, stream, token) => stream.WriteAsync(payloads[digest], token).AsTask());
        using var cache = new RegionalArtifactCache(downloader, 8, 16);
        var keys = payloads.Keys.ToArray();
        foreach (var index in new[] { 0, 1, 0, 2, 0, 1 })
        {
            await cache.ReadAsync(keys[index], 0, 8, CancellationToken.None);
            await Assert.That(cache.Snapshot.Bytes <= 16).IsTrue();
            await Assert.That(cache.Snapshot.Entries <= 2).IsTrue();
        }
        await Assert.That(downloader.Calls).IsEqualTo(4);
    }

    [Test]
    public async Task Entry_count_is_bounded_even_for_tiny_objects()
    {
        var payloads = Enumerable.Range(1, 12).Select(value => new[] { (byte)value }).ToDictionary(Digest);
        using var cache = new RegionalArtifactCache(new Downloader((digest, stream, token) => stream.WriteAsync(payloads[digest], token).AsTask()), 8, 32);
        foreach (var digest in payloads.Keys) await cache.ReadAsync(digest, 0, 1, CancellationToken.None);
        await Assert.That(cache.Snapshot.Entries).IsEqualTo(8);
        await Assert.That(cache.Snapshot.Bytes).IsEqualTo(8);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Cancelled_waiters_and_stalled_downloads_cannot_accumulate_work_or_publish_after_disposal(bool synchronous)
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        byte[] bytes = [1, 2, 3];
        var downloader = new Downloader(async (_, stream, _) =>
        {
            started.TrySetResult();
            if (synchronous) release.Task.GetAwaiter().GetResult(); else await release.Task;
            await stream.WriteAsync(bytes); // Deliberately ignore cancellation; writer still enforces it.
        });
        using var cache = new RegionalArtifactCache(downloader, downloadTimeout: TimeSpan.FromMilliseconds(100));
        using var cancel = new CancellationTokenSource();
        var read = cache.ReadAsync(Digest(bytes), 0, 3, cancel.Token);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            await Assert.That(async () => _ = await read).Throws<OperationCanceledException>();
            for (var i = 0; i < 5; i++)
                await Assert.That(async () => _ = await cache.ReadAsync(Digest([9]), 0, 1, CancellationToken.None)).Throws<IOException>();
            await Assert.That(downloader.Calls).IsEqualTo(1);
            await Assert.That(cache.Snapshot.Downloading).IsTrue();
            cache.Dispose();
            await Assert.That(async () => _ = await cache.ReadAsync(Digest(bytes), 0, 3, CancellationToken.None)).Throws<ObjectDisposedException>();
        }
        finally
        {
            release.TrySetResult();
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (cache.Snapshot.Downloading) await Task.Delay(5, deadline.Token);
        }
        await Assert.That(cache.Snapshot.Bytes).IsEqualTo(0);
    }

    [Test]
    public async Task Cancelled_request_does_not_cancel_a_shared_download_and_new_waiter_can_use_it()
    {
        byte[] bytes = [1, 2, 3];
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var downloader = new Downloader(async (_, stream, token) => { started.TrySetResult(); await release.Task; await stream.WriteAsync(bytes, token); });
        using var cache = new RegionalArtifactCache(downloader);
        using var cancel = new CancellationTokenSource();
        var first = cache.ReadAsync(Digest(bytes), 0, 3, cancel.Token);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            await Assert.That(async () => _ = await first).Throws<OperationCanceledException>();
            var second = cache.ReadAsync(Digest(bytes), 0, 3, CancellationToken.None);
            release.TrySetResult();
            await Assert.That((await second).Bytes.SequenceEqual(bytes)).IsTrue();
            await Assert.That(downloader.Calls).IsEqualTo(1);
        }
        finally { release.TrySetResult(); }
    }

    [Test]
    public async Task Invalid_ranges_and_noncanonical_digests_never_reach_storage()
    {
        var downloader = new Downloader((_, _, _) => throw new InvalidOperationException());
        using var cache = new RegionalArtifactCache(downloader);
        foreach (var (digest, offset, length) in new[] { (Digest([1]).ToUpperInvariant(), 0L, 1), ("../file", 0L, 1),
                     (Digest([1]), -1L, 1), (Digest([1]), RegionalArtifactCache.MaximumArtifactBytes, 1),
                     (Digest([1]), 0L, 0), (Digest([1]), 0L, RegionalArtifactCache.MaximumChunkBytes + 1) })
            await Assert.That(async () => _ = await cache.ReadAsync(digest, offset, length, CancellationToken.None)).Throws<ArgumentException>();
        await Assert.That(downloader.Calls).IsEqualTo(0);
    }

    internal static string Digest(byte[] bytes) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));

    [Test]
    public async Task A_download_finishing_after_its_own_deadline_cannot_publish_an_entry()
    {
        byte[] bytes = [1, 2, 3];
        var downloader = new Downloader(async (_, stream, _) =>
        {
            await Task.Delay(100);
            await stream.WriteAsync(bytes);
        });
        using var cache = new RegionalArtifactCache(downloader, downloadTimeout: TimeSpan.FromMilliseconds(10));
        await Assert.That(async () => _ = await cache.ReadAsync(Digest(bytes), 0, 3, CancellationToken.None)).Throws<OperationCanceledException>();
        await Assert.That(cache.Snapshot.Bytes).IsEqualTo(0);
        await Assert.That(cache.Snapshot.Entries).IsEqualTo(0);
    }

    internal sealed class Downloader(Func<string, Stream, CancellationToken, Task> copy) : IRegionalArtifactDownloader
    {
        internal int Calls;
        public Task CopyAsync(string digest, Stream destination, CancellationToken cancellationToken)
        { Interlocked.Increment(ref Calls); return copy(digest, destination, cancellationToken); }
    }
}
