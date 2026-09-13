using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class RepositoryCiOciRegistryPublisherTests
{
    private const string ArtifactRepository = "TerraScale/TerraScale.Orchestrator";
    private const string CandidateDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Test]
    public async Task ExactAbsentImageUsesSafeSkopeoInspectCopyAndReadback()
    {
        await using var fixture = Fixture.Create();
        var digest = fixture.LocalDigest;
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            1,
            string.Empty,
            "manifest unknown"));
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            0,
            string.Empty,
            string.Empty));
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            0,
            digest,
            string.Empty));

        var receipt = await fixture.PublishAsync(static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciRegistryPublicationDisposition.Published);
        await Assert.That(receipt.PublishedDigest).IsEqualTo(digest);
        await Assert.That(fixture.Process.Calls.Select(static call => call.Operation)
            .SequenceEqual(new[]
            {
                RepositoryCiOciRegistryProcessOperation.Inspect,
                RepositoryCiOciRegistryProcessOperation.Copy,
                RepositoryCiOciRegistryProcessOperation.Inspect,
            })).IsTrue();
        var copy = fixture.Process.Calls.Single(static call =>
            call.Operation == RepositoryCiOciRegistryProcessOperation.Copy);
        await Assert.That(copy.Arguments[0]).IsEqualTo("copy");
        await Assert.That(copy.Arguments).Contains("--all");
        await Assert.That(copy.Arguments).Contains("--preserve-digests");
        await Assert.That(copy.Arguments).Contains("--authfile");
        await Assert.That(copy.Arguments).Contains(fixture.AuthFile);
        await Assert.That(copy.Arguments.Any(static value =>
            value.StartsWith("oci-archive:", StringComparison.Ordinal) &&
            value.EndsWith(":release", StringComparison.Ordinal))).IsTrue();
        await Assert.That(copy.Arguments.Any(static value => value.Contains("password", StringComparison.OrdinalIgnoreCase)))
            .IsFalse();
        foreach (var call in fixture.Process.Calls)
            await Assert.That(call.Arguments).Contains(fixture.AuthFile);
    }

    [Test]
    public async Task ExactExistingDigestIsDuplicateWithoutCopy()
    {
        await using var fixture = Fixture.Create();
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            0,
            fixture.LocalDigest,
            string.Empty));

        var receipt = await fixture.PublishAsync(static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciRegistryPublicationDisposition.Duplicate);
        await Assert.That(fixture.Process.Calls).HasSingleItem();
    }

    [Test]
    public async Task DifferentExistingDigestIsIdentityConflictWithoutCopy()
    {
        await using var fixture = Fixture.Create();
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            0,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            string.Empty));

        var receipt = await fixture.PublishAsync(static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciRegistryPublicationDisposition.IdentityConflict);
        await Assert.That(fixture.Process.Calls).HasSingleItem();
    }

    [Test]
    public async Task AuthorityLossAfterInspectionStopsBeforeCopyAndCleansStaging()
    {
        await using var fixture = Fixture.Create();
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            1,
            string.Empty,
            "not found"));
        var checks = 0;

        var receipt = await fixture.PublishAsync(() => ++checks < 2);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciRegistryPublicationDisposition.StaleAuthority);
        await Assert.That(fixture.Process.Calls).HasSingleItem();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task TraversalLinkDuplicateAndMissingPlatformArchivesFailClosedAndClean()
    {
        await using var traversal = Fixture.Create(Outer([Entry(TarEntryType.RegularFile, "../image.tar", [1])]));
        await Assert.That(async () => await traversal.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(Directory.GetFileSystemEntries(traversal.StagingRoot)).IsEmpty();

        await using var link = Fixture.Create(Outer([
            new PaxTarEntry(TarEntryType.SymbolicLink, "image.tar") { LinkName = "target" },
        ]));
        await Assert.That(async () => await link.PublishAsync(static () => true))
            .Throws<InvalidDataException>();

        var layout = """{"imageLayoutVersion":"1.0.0"}"""u8.ToArray();
        var missingArm = """{"schemaVersion":2,"manifests":[{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","platform":{"os":"linux","architecture":"amd64"}}]}"""u8.ToArray();
        await using var missing = Fixture.Create(Outer([
            Entry(TarEntryType.RegularFile, "oci-layout", layout),
            Entry(TarEntryType.RegularFile, "index.json", missingArm),
        ]));
        await Assert.That(async () => await missing.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task MissingReachableBlobFailsClosedBeforeRegistryInspection()
    {
        var image = BuildImage(omitBlob: true);
        await using var fixture = Fixture.Create(image.Archive);

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Process.Calls).IsEmpty();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task TamperedBlobFailsClosedBeforeRegistryInspection()
    {
        var image = BuildImage(tamperBlob: true);
        await using var fixture = Fixture.Create(image.Archive);

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Process.Calls).IsEmpty();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task WrongDeclaredDescriptorSizeFailsClosedBeforeRegistryInspection()
    {
        var image = BuildImage(wrongRootSize: true);
        await using var fixture = Fixture.Create(image.Archive);

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Process.Calls).IsEmpty();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task AmbiguousRootIdentityFailsClosedBeforeRegistryInspection()
    {
        var image = BuildImage(extraRootDescriptor: true);
        await using var fixture = Fixture.Create(image.Archive);

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Process.Calls).IsEmpty();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task MultipleSdkTagAliasesSelectOneExactImageIdentity()
    {
        var image = BuildImage(aliasRootDescriptor: true);
        await using var fixture = Fixture.Create(image.Archive);
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.Exited,
            0,
            image.LocalDigest,
            string.Empty));

        var receipt = await fixture.PublishAsync(static () => true);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(RepositoryCiOciRegistryPublicationDisposition.Duplicate);
        await Assert.That(fixture.Process.Calls).HasSingleItem();
    }

    [Test]
    public async Task DuplicateBlobPathFailsClosedBeforeRegistryInspection()
    {
        var image = BuildImage(duplicateBlob: true);
        await using var fixture = Fixture.Create(image.Archive);

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
        await Assert.That(fixture.Process.Calls).IsEmpty();
        await Assert.That(Directory.GetFileSystemEntries(fixture.StagingRoot)).IsEmpty();
    }

    [Test]
    public async Task MissingDuplicateAndOversizedResultManifestFailClosed()
    {
        var image = BuildImage();
        await using var missing = Fixture.Create(Outer([
            Entry(TarEntryType.RegularFile, "image.tar", image.InnerArchive),
        ]));
        await Assert.That(async () => await missing.PublishAsync(static () => true))
            .Throws<InvalidDataException>();

        await using var duplicate = Fixture.Create(Outer([
            Entry(TarEntryType.RegularFile, "image.tar", image.InnerArchive),
            Entry(TarEntryType.RegularFile, "terrascale-ci-result-v2.json", "{}"u8.ToArray()),
            Entry(TarEntryType.RegularFile, "terrascale-ci-result-v2.json", "{}"u8.ToArray()),
        ]));
        await Assert.That(async () => await duplicate.PublishAsync(static () => true))
            .Throws<InvalidDataException>();

        await using var oversized = Fixture.Create(Outer([
            Entry(TarEntryType.RegularFile, "image.tar", image.InnerArchive),
            Entry(TarEntryType.RegularFile, "terrascale-ci-result-v2.json", new byte[16 * 1024 * 1024 + 1]),
        ]));
        await Assert.That(async () => await oversized.PublishAsync(static () => true))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task TimeoutIsNotReportedAsSuccess()
    {
        await using var fixture = Fixture.Create();
        fixture.Process.Results.Enqueue(new(
            RepositoryCiOciRegistryProcessDisposition.TimedOut,
            -1,
            string.Empty,
            string.Empty));

        await Assert.That(async () => await fixture.PublishAsync(static () => true))
            .Throws<TimeoutException>();
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private Fixture(
            string authFile,
            string stagingRoot,
            byte[] archive,
            string localDigest,
            TestProcess process)
        {
            AuthFile = authFile;
            StagingRoot = stagingRoot;
            Archive = archive;
            LocalDigest = localDigest;
            Process = process;
            Publisher = new(
                new RepositoryCiOciRegistryPublisherConfiguration(
                    new Uri("https://registry.example.test"),
                    "terrascale",
                    AuthFile,
                    StagingRoot),
                Process);
        }

        internal string AuthFile { get; }
        internal string StagingRoot { get; }
        internal byte[] Archive { get; }
        internal string LocalDigest { get; }
        internal TestProcess Process { get; }
        private RepositoryCiOciRegistryPublisher Publisher { get; }

        internal static Fixture Create(byte[]? archive = null)
        {
            var auth = Path.Combine(Path.GetTempPath(), $"oci-auth-{Guid.NewGuid():N}");
            File.WriteAllText(auth, "{}");
            File.SetUnixFileMode(auth, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var staging = Path.Combine(Path.GetTempPath(), $"oci-staging-{Guid.NewGuid():N}");
            Directory.CreateDirectory(staging);
            var image = BuildImage();
            return new(
                auth,
                staging,
                archive ?? Outer([
                    Entry(TarEntryType.RegularFile, "image.tar", image.InnerArchive),
                    Entry(TarEntryType.RegularFile, "terrascale-ci-result-v2.json", "{}"u8.ToArray()),
                ]),
                image.LocalDigest,
                new TestProcess());
        }

        internal async Task<RepositoryCiOciRegistryPublicationReceipt> PublishAsync(
            Func<bool> authorityStillValid) =>
            await Publisher.PublishAsync(
                ArtifactRepository,
                CandidateDigest,
                Convert.ToHexStringLower(SHA256.HashData(Archive)),
                Archive.LongLength,
                async (destination, cancellationToken) =>
                {
                    await destination.WriteAsync(Archive, cancellationToken);
                },
                authorityStillValid);

        public ValueTask DisposeAsync()
        {
            try { File.Delete(AuthFile); } catch { }
            try { Directory.Delete(StagingRoot, recursive: true); } catch { }
            return ValueTask.CompletedTask;
        }
    }

    private sealed class TestProcess : IRepositoryCiOciRegistryProcess
    {
        internal Queue<RepositoryCiOciRegistryProcessResult> Results { get; } = [];
        internal List<Call> Calls { get; } = [];

        public Task<RepositoryCiOciRegistryProcessResult> RunAsync(
            RepositoryCiOciRegistryProcessInvocation invocation,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls.Add(new(invocation.Operation, invocation.Executable, invocation.Arguments));
            return Task.FromResult(Results.Count == 0
                ? new RepositoryCiOciRegistryProcessResult(
                    RepositoryCiOciRegistryProcessDisposition.Exited,
                    1,
                    string.Empty,
                    "not found")
                : Results.Dequeue());
        }
    }

    private sealed record Call(
        RepositoryCiOciRegistryProcessOperation Operation,
        string Executable,
        IReadOnlyList<string> Arguments);

    private sealed record BuiltImage(
        byte[] Index,
        byte[] InnerArchive,
        byte[] Archive,
        string LocalDigest);

    private sealed record Blob(
        string Digest,
        byte[] Content);

    private static BuiltImage BuildImage(
        bool omitBlob = false,
        bool tamperBlob = false,
        bool wrongRootSize = false,
        bool extraRootDescriptor = false,
        bool duplicateBlob = false,
        bool aliasRootDescriptor = false)
    {
        var configA = new Blob(
            Digest(Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}")),
            Encoding.UTF8.GetBytes("{\"architecture\":\"amd64\",\"os\":\"linux\"}"));
        var layerA = new Blob(Digest(Encoding.UTF8.GetBytes("layer-amd64")), Encoding.UTF8.GetBytes("layer-amd64"));
        var configB = new Blob(
            Digest(Encoding.UTF8.GetBytes("{\"architecture\":\"arm64\",\"os\":\"linux\"}")),
            Encoding.UTF8.GetBytes("{\"architecture\":\"arm64\",\"os\":\"linux\"}"));
        var layerB = new Blob(Digest(Encoding.UTF8.GetBytes("layer-arm64")), Encoding.UTF8.GetBytes("layer-arm64"));
        var manifestA = new Blob(
            Digest(Manifest(configA, layerA)),
            Manifest(configA, layerA));
        var manifestB = new Blob(
            Digest(Manifest(configB, layerB)),
            Manifest(configB, layerB));
        var platformIndex = new Blob(
            Digest(PlatformIndex(manifestA, manifestB)),
            PlatformIndex(manifestA, manifestB));
        var index = RootIndex(platformIndex, manifestA, wrongRootSize, extraRootDescriptor, aliasRootDescriptor);

        var entries = new List<TarEntry>
        {
            Entry(TarEntryType.RegularFile, "oci-layout", """{"imageLayoutVersion":"1.0.0"}"""u8.ToArray()),
            Entry(TarEntryType.RegularFile, "index.json", index),
        };
        var blobs = new[] { platformIndex, manifestA, manifestB, configA, layerA, configB, layerB };
        foreach (var blob in blobs)
        {
            if (omitBlob && blob == layerA) continue;
            var content = tamperBlob && blob == layerA
                ? Encoding.UTF8.GetBytes("tampered-layer")
                : blob.Content;
            entries.Add(Entry(TarEntryType.RegularFile, $"blobs/sha256/{blob.Digest[7..]}", content));
            if (duplicateBlob && blob == layerA)
                entries.Add(Entry(TarEntryType.RegularFile, $"blobs/sha256/{blob.Digest[7..]}", blob.Content));
        }
        var innerArchive = Tar(entries);
        return new(
            index,
            innerArchive,
            Outer([
                Entry(TarEntryType.RegularFile, "image.tar", innerArchive),
                Entry(TarEntryType.RegularFile, "terrascale-ci-result-v2.json", "{}"u8.ToArray()),
            ]),
            platformIndex.Digest);
    }

    private static byte[] PlatformIndex(
        Blob manifestA,
        Blob manifestB)
    {
        return Encoding.UTF8.GetBytes(
            $"{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{manifestA.Digest}\",\"size\":{manifestA.Content.LongLength},\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}},{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{manifestB.Digest}\",\"size\":{manifestB.Content.LongLength},\"platform\":{{\"os\":\"linux\",\"architecture\":\"arm64\"}}}}]}}");
    }

    private static byte[] RootIndex(
        Blob platformIndex,
        Blob manifestA,
        bool wrongRootSize,
        bool extraRootDescriptor,
        bool aliasRootDescriptor)
    {
        var size = wrongRootSize ? platformIndex.Content.LongLength + 1 : platformIndex.Content.LongLength;
        var alias = aliasRootDescriptor
            ? $",{{\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"digest\":\"{platformIndex.Digest}\",\"size\":{platformIndex.Content.LongLength},\"platform\":{{\"architecture\":\"unknown\",\"os\":\"unknown\"}},\"annotations\":{{\"io.containerd.image.name\":\"docker.io/library/service:latest\",\"org.opencontainers.image.ref.name\":\"latest\"}}}}"
            : string.Empty;
        var conflicting = extraRootDescriptor
            ? $",{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{manifestA.Digest}\",\"size\":{manifestA.Content.LongLength},\"annotations\":{{\"org.opencontainers.image.ref.name\":\"other\"}}}}"
            : string.Empty;
        return Encoding.UTF8.GetBytes(
            $"{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"digest\":\"{platformIndex.Digest}\",\"size\":{size},\"platform\":{{\"architecture\":\"unknown\",\"os\":\"unknown\"}},\"annotations\":{{\"io.containerd.image.name\":\"docker.io/library/service:release\",\"org.opencontainers.image.ref.name\":\"release\"}}}}{alias}{conflicting}]}}");
    }

    private static byte[] Manifest(Blob config, Blob layer) => Encoding.UTF8.GetBytes(
        $"{{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{config.Digest}\",\"size\":{config.Content.LongLength}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"{layer.Digest}\",\"size\":{layer.Content.LongLength}}}]}}");

    private static string Digest(byte[] value) =>
        "sha256:" + Convert.ToHexStringLower(SHA256.HashData(value));

    private static byte[] Outer(IEnumerable<TarEntry> entries)
    {
        var tar = Tar(entries);
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(tar);
        return output.ToArray();
    }

    private static byte[] Tar(IEnumerable<TarEntry> entries)
    {
        using var output = new MemoryStream();
        using (var writer = new TarWriter(output, TarEntryFormat.Pax, leaveOpen: true))
        {
            foreach (var entry in entries) writer.WriteEntry(entry);
        }
        return output.ToArray();
    }

    private static PaxTarEntry Entry(TarEntryType type, string name, byte[] data) => new(type, name)
    {
        DataStream = new MemoryStream(data, writable: false),
    };
}

