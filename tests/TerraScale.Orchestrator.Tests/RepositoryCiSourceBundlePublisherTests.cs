using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class RepositoryCiSourceBundlePublisherTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";

    [Test]
    public async Task ExactArchiveIsContentAddressedAndReadVerified()
    {
        var store = new TestObjectStore();
        var publisher = new RepositoryCiSourceBundlePublisher(store);
        var archive = Archive();

        var first = await publisher.PublishAsync(archive);
        var retry = await publisher.PublishAsync(archive);

        await Assert.That(first).IsEqualTo(retry);
        await Assert.That(first.Revision).IsSameReferenceAs(archive.Revision);
        await Assert.That(first.ContentSha256).IsEqualTo(archive.ContentSha256);
        await Assert.That(first.ContentLength).IsEqualTo(archive.ContentLength);
        await Assert.That(first.ObjectName).IsEqualTo($"ci-source-{archive.ContentSha256}");
        await Assert.That(store.Values[first.ObjectName]).IsEquivalentTo(archive.Content.ToArray());
        await Assert.That(store.PutCount).IsEqualTo(2);
    }

    [Test]
    public async Task ArchiveDigestSubstitutionFailsBeforeStorage()
    {
        var store = new TestObjectStore();
        var publisher = new RepositoryCiSourceBundlePublisher(store);
        var valid = Archive();
        var substituted = new ForgejoSourceArchive(valid.Revision, new string('a', 64), valid.Content.ToArray());

        await Assert.That(async () => await publisher.PublishAsync(substituted))
            .Throws<InvalidDataException>();
        await Assert.That(store.PutCount).IsEqualTo(0);
    }

    [Test]
    public async Task CorruptObjectStoreReadbackFailsClosed()
    {
        var store = new TestObjectStore { CorruptReadback = true };
        var publisher = new RepositoryCiSourceBundlePublisher(store);

        await Assert.That(async () => await publisher.PublishAsync(Archive()))
            .Throws<InvalidDataException>();
    }

    private static ForgejoSourceArchive Archive()
    {
        var content = new byte[] { 0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4 };
        return new(
            new(Repository, Commit, Tree, signatureVerified: true),
            Convert.ToHexStringLower(SHA256.HashData(content)),
            content);
    }

    private sealed class TestObjectStore : IDeliveryObjectStore
    {
        internal Dictionary<string, byte[]> Values { get; } = new(StringComparer.Ordinal);
        internal int PutCount { get; private set; }
        internal bool CorruptReadback { get; init; }

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PutCount++;
            Values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(CorruptReadback
                ? Encoding.UTF8.GetBytes("corrupt")
                : Values[name].ToArray());
        }
    }
}
