using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.ControlPlane.Delivery;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerSourceMaterializerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string ArchiveRoot = "TerraScale.Orchestrator-bffeb742";

    [Test]
    public async Task ExactBundleMaterializesOnlyPrivateRegularSourceFiles()
    {
        var archive = Archive(
            Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
            Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"),
            Entry("scripts/tool.sh", "#!/bin/sh\n", UnixFileMode.UserRead | UnixFileMode.UserExecute |
                UnixFileMode.GroupExecute | UnixFileMode.OtherExecute));
        var parent = TemporaryParent();
        try
        {
            var destination = Path.Combine(parent, "source");
            var plan = Plan(archive);
            var materialized = await new CiRunnerSourceMaterializer(new TestObjectStore(archive))
                .MaterializeAsync(plan, destination);

            await Assert.That(materialized.Root).IsEqualTo(destination);
            await Assert.That(materialized.PlanDigest).IsEqualTo(plan.Digest);
            await Assert.That(materialized.BundleSha256).IsEqualTo(plan.Source.BundleSha256);
            await Assert.That(materialized.FileCount).IsEqualTo(3);
            await Assert.That(materialized.ExpandedBytes).IsGreaterThan(0);
            await Assert.That(File.Exists(Path.Combine(destination, ".terrascale", "ci-v2.json"))).IsTrue();
            await Assert.That(File.Exists(Path.Combine(destination, ".terrascale", "ci.Dockerfile"))).IsTrue();
            await Assert.That(Directory.Exists(Path.Combine(destination, ArchiveRoot))).IsFalse();
            await Assert.That(File.GetUnixFileMode(destination)).IsEqualTo(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await Assert.That(File.GetUnixFileMode(Path.Combine(destination, "scripts", "tool.sh"))).IsEqualTo(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            await Assert.That(File.GetUnixFileMode(Path.Combine(destination, ".terrascale", "ci.Dockerfile")))
                .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Test]
    public async Task CorruptionAndMissingRecipeFailWithoutLeavingAWorkspace()
    {
        var archive = Archive(
            Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
            Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"));
        var parent = TemporaryParent();
        try
        {
            var corruptDestination = Path.Combine(parent, "corrupt");
            var corrupt = archive.ToArray();
            corrupt[^1] ^= 1;
            await Assert.That(async () => await new CiRunnerSourceMaterializer(new TestObjectStore(corrupt))
                    .MaterializeAsync(Plan(archive), corruptDestination))
                .Throws<InvalidDataException>();
            await Assert.That(Directory.Exists(corruptDestination)).IsFalse();

            var missingRecipe = Archive(Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"));
            var missingDestination = Path.Combine(parent, "missing");
            await Assert.That(async () => await new CiRunnerSourceMaterializer(new TestObjectStore(missingRecipe))
                    .MaterializeAsync(Plan(missingRecipe), missingDestination))
                .Throws<InvalidDataException>();
            await Assert.That(Directory.Exists(missingDestination)).IsFalse();
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    [Test]
    public async Task LinksTraversalAndDuplicatePathsFailClosed()
    {
        var parent = TemporaryParent();
        try
        {
            var link = new PaxTarEntry(TarEntryType.SymbolicLink, $"{ArchiveRoot}/link")
            {
                LinkName = "../outside",
            };
            await RejectedAsync(
                Archive(
                    Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
                    Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"),
                    link),
                Path.Combine(parent, "link"));

            await RejectedAsync(
                Archive(
                    Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
                    Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"),
                    Entry("../outside", "stolen")),
                Path.Combine(parent, "traversal"));
            await Assert.That(File.Exists(Path.Combine(parent, "outside"))).IsFalse();

            await RejectedAsync(
                Archive(
                    Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
                    Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"),
                    Entry("duplicate", "first"),
                    Entry("duplicate", "second")),
                Path.Combine(parent, "duplicate"));

            await RejectedAsync(
                Archive(
                    Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
                    Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n"),
                    new PaxTarEntry(TarEntryType.Directory, $"{ArchiveRoot}/")),
                Path.Combine(parent, "duplicate-root"));

            await RejectedAsync(
                ArchiveWithTrailingData(
                    Entry(RepositoryCiImpactPlanner.DescriptorPath, "{}"),
                    Entry(CiRunnerExecutionPlanner.RecipePath, "FROM scratch\n")),
                Path.Combine(parent, "trailing"));
        }
        finally
        {
            Directory.Delete(parent, recursive: true);
        }
    }

    private static async Task RejectedAsync(byte[] archive, string destination)
    {
        await Assert.That(async () => await new CiRunnerSourceMaterializer(new TestObjectStore(archive))
                .MaterializeAsync(Plan(archive), destination))
            .Throws<InvalidDataException>();
        await Assert.That(Directory.Exists(destination)).IsFalse();
    }

    private static CiRunnerExecutionPlan Plan(byte[] archive)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(archive));
        var source = new CiRunnerSourcePlan(
            Repository,
            Commit,
            Tree,
            RepositoryCiSourceBundlePublisher.ObjectName(digest),
            digest,
            archive.Length,
            RepositoryCiImpactPlanner.DescriptorPath,
            CiRunnerExecutionPlanner.RecipePath);
        var build = new CiRunnerBuildKitPlan(
            CiRunnerExecutionPlanner.Frontend,
            "ci-build",
            [RepositoryCiArchitecture.Any],
            CiRunnerExecutionOutputKind.Evidence,
            CiRunnerNetworkScope.PublicDependenciesOnly,
            CiRunnerCredentialProfile.None,
            CiRunnerCacheScope.UntrustedIsolated,
            $"untrusted-{new string('d', 64)}",
            1_000,
            512L * 1024 * 1024,
            1024L * 1024 * 1024,
            128,
            16L * 1024 * 1024,
            TimeSpan.FromMinutes(15));
        return new(
            new string('a', 64),
            "ci-job",
            new string('b', 64),
            new string('c', 64),
            1,
            source,
            build);
    }

    private static byte[] Archive(params TarEntry[] entries)
    {
        var payload = Tar(entries);
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(payload);
        return output.ToArray();
    }

    private static byte[] ArchiveWithTrailingData(params TarEntry[] entries)
    {
        using var payload = new MemoryStream();
        payload.Write(Tar(entries));
        payload.WriteByte(1);
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(payload.ToArray());
        return output.ToArray();
    }

    private static byte[] Tar(IEnumerable<TarEntry> entries)
    {
        using var output = new MemoryStream();
        using (var writer = new TarWriter(output, TarEntryFormat.Pax, leaveOpen: true))
        {
            writer.WriteEntry(new PaxTarEntry(TarEntryType.Directory, $"{ArchiveRoot}/"));
            foreach (var entry in entries) writer.WriteEntry(entry);
        }
        return output.ToArray();
    }

    private static PaxTarEntry Entry(
        string path,
        string content,
        UnixFileMode mode = UnixFileMode.UserRead | UnixFileMode.UserWrite) => new(
            TarEntryType.RegularFile,
            $"{ArchiveRoot}/{path}")
        {
            DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content), writable: false),
            Mode = mode,
        };

    private static string TemporaryParent()
    {
        var path = Path.Combine(Path.GetTempPath(), $"ci-source-{Guid.NewGuid():N}");
        Directory.CreateDirectory(path);
        return path;
    }

    private sealed class TestObjectStore(byte[] content) : IDeliveryObjectStore
    {
        public Task PutAsync(string name, ReadOnlyMemory<byte> value, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(content.ToArray());
        }
    }
}
