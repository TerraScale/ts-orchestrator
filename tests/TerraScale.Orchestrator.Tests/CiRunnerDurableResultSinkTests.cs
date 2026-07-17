using System.Collections.Concurrent;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class CiRunnerDurableResultSinkTests
{
    [Test]
    public async Task ExactSuccessStoresRedactedLogDeterministicArtifactAndCanonicalEvidence()
    {
        using var fixture = await Fixture.CreateAsync();
        var store = new ObjectStore();
        var sink = new CiRunnerDurableResultSink(store);

        var first = await sink.PersistAsync(fixture.Evidence, fixture.Log, fixture.Export, default);
        var artifactName = $"ci-result-artifact-{fixture.Evidence.OutputSha256}";
        var firstArtifact = store.Values[artifactName].ToArray();
        var replay = await sink.PersistAsync(fixture.Evidence, fixture.Log, fixture.Export, default);
        var stored = JsonSerializer.Deserialize(
            store.Values[$"ci-result-evidence-{first.EvidenceDigest}"],
            CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence);

        await Assert.That(first).IsEqualTo(replay);
        await Assert.That(first.RequiredTestSkips).IsEqualTo(0);
        await Assert.That(first.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.Unspecified);
        await Assert.That(store.Values[artifactName].SequenceEqual(firstArtifact)).IsTrue();
        await Assert.That(store.Values[$"ci-result-log-{fixture.Evidence.LogSha256}"]
            .SequenceEqual(fixture.Log)).IsTrue();
        await Assert.That(stored).IsNotNull();
        await Assert.That(stored!.Workload).IsEqualTo(fixture.Evidence);
        await Assert.That(stored.RetentionDays).IsEqualTo(30);
        await Assert.That(stored.ArtifactSha256)
            .IsEqualTo(Convert.ToHexStringLower(SHA256.HashData(firstArtifact)));
        var native = stored.Artifacts!.Single();
        var nativeContent = "native"u8.ToArray();
        var nativeCanonical = Encoding.UTF8.GetBytes(
            $"f:orchestrator:{nativeContent.Length}:0:{Convert.ToHexStringLower(SHA256.HashData(nativeContent))}\n");
        await Assert.That(native.Artifact).IsEqualTo("TerraScale/TerraScale.Orchestrator");
        await Assert.That(native.Architecture).IsEqualTo(RepositoryCiArchitecture.LinuxX64);
        await Assert.That(native.Path).IsEqualTo("linux-x64");
        await Assert.That(native.Digest)
            .IsEqualTo(Convert.ToHexStringLower(SHA256.HashData(nativeCanonical)));
        await Assert.That(ArchiveEntries(firstArtifact)).IsEquivalentTo([
            CiRunnerDurableResultSink.ResultManifestPath,
            "linux-x64/orchestrator",
            "result.txt",
        ]);
    }

    [Test]
    public async Task WorkloadFailureStoresOnlyItsRedactedLogAndEvidence()
    {
        using var fixture = await Fixture.CreateAsync();
        var store = new ObjectStore();
        var failure = fixture.Evidence with
        {
            BuildDisposition = CiRunnerBuildKitExecutionDisposition.ProcessFailed,
            ExitCode = 17,
            MetadataSha256 = string.Empty,
            OutputSha256 = string.Empty,
            OutputFiles = 0,
            OutputBytes = 0,
            Succeeded = false,
            FailureKind = RepositoryCiJobFailureKind.WorkloadFailed,
            FailureCode = CiRunnerWorkloadFailureCode.ProcessFailed,
        };

        var result = await new CiRunnerDurableResultSink(store).PersistAsync(
            failure,
            fixture.Log,
            null,
            default);

        await Assert.That(result.RequiredTestSkips).IsEqualTo(0);
        await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        await Assert.That(store.Values.Keys).IsEquivalentTo([
            $"ci-result-log-{failure.LogSha256}",
            $"ci-result-evidence-{result.EvidenceDigest}",
        ]);
    }

    [Test]
    public async Task SubstitutedLogAndCorruptReadbackFailBeforeTerminalEvidence()
    {
        using var fixture = await Fixture.CreateAsync();
        var sink = new CiRunnerDurableResultSink(new ObjectStore());
        var substituted = fixture.Log.ToArray();
        substituted[0] ^= 1;

        await Assert.That(async () => await sink.PersistAsync(
                fixture.Evidence,
                substituted,
                fixture.Export,
                default))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new CiRunnerDurableResultSink(
                new ObjectStore(corruptReads: true)).PersistAsync(
                fixture.Evidence,
                fixture.Log,
                fixture.Export,
                default))
            .Throws<InvalidDataException>();
    }

    [Test]
    public async Task LinkedOutputAndDuplicateManifestFieldsFailClosed()
    {
        using (var linked = await Fixture.CreateAsync())
        {
            File.CreateSymbolicLink(Path.Combine(linked.Export, "link"), "/etc/passwd");
            var rejected = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                linked.Evidence,
                linked.Log,
                linked.Export,
                default);
            await Assert.That(rejected.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var duplicate = await Fixture.CreateAsync())
        {
            await File.WriteAllTextAsync(
                Path.Combine(duplicate.Export, CiRunnerDurableResultSink.ResultManifestPath),
                $$"""
                {"schemaVersion":1,"schemaVersion":1,"job":"{{duplicate.Evidence.Job}}","planDigest":"{{duplicate.Evidence.PlanDigest}}","succeeded":true,"requiredTestSkips":0}
                """);
            var rejected = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                duplicate.Evidence,
                duplicate.Log,
                duplicate.Export,
                default);
            await Assert.That(rejected.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var missing = await Fixture.CreateAsync())
        {
            var manifest = new CiRunnerResultManifest(
                1,
                missing.Evidence.Job,
                missing.Evidence.PlanDigest,
                true,
                0,
                [new("TerraScale/TerraScale.Orchestrator", RepositoryCiArchitecture.LinuxX64, "missing")]);
            await File.WriteAllBytesAsync(
                Path.Combine(missing.Export, CiRunnerDurableResultSink.ResultManifestPath),
                JsonSerializer.SerializeToUtf8Bytes(
                    manifest,
                    CiRunnerDurableResultJsonContext.Default.CiRunnerResultManifest));
            var rejected = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                missing.Evidence,
                missing.Log,
                missing.Export,
                default);
            await Assert.That(rejected.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }
    }

    private static string[] ArchiveEntries(byte[] content)
    {
        using var input = new MemoryStream(content, writable: false);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var reader = new TarReader(gzip);
        var names = new List<string>();
        while (reader.GetNextEntry() is { } entry)
            if (entry.EntryType is TarEntryType.RegularFile or TarEntryType.V7RegularFile)
                names.Add(entry.Name);
        return names.ToArray();
    }

    private sealed class ObjectStore(bool corruptReads = false) : IDeliveryObjectStore
    {
        private readonly ConcurrentDictionary<string, byte[]> values = new(StringComparer.Ordinal);

        internal IReadOnlyDictionary<string, byte[]> Values => values;

        public Task PutAsync(string name, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            values[name] = content.ToArray();
            return Task.CompletedTask;
        }

        public Task<byte[]> GetAsync(string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var content = values.TryGetValue(name, out var value)
                ? value.ToArray()
                : throw new IOException("Missing CI result test object.");
            if (corruptReads)
                content = content.Length == 0 ? [1] : content.Append((byte)1).ToArray();
            return Task.FromResult(content);
        }
    }

    private sealed class Process(byte[] log) : ICiRunnerBuildKitProcess
    {
        public Task<CiRunnerBuildKitProcessResult> RunAsync(
            CiRunnerBuildKitInvocation invocation,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Directory.CreateDirectory(invocation.ExportDirectory);
            File.WriteAllText(Path.Combine(invocation.ExportDirectory, "result.txt"), "passed");
            var artifactRoot = Directory.CreateDirectory(Path.Combine(invocation.ExportDirectory, "linux-x64"));
            File.WriteAllText(Path.Combine(artifactRoot.FullName, "orchestrator"), "native");
            var manifest = new CiRunnerResultManifest(
                1,
                "ci-job",
                CiRunnerSourceMaterializerTests.Plan([0x1f, 0x8b, 0x08, 1]).Digest,
                true,
                0,
                [new(
                    "TerraScale/TerraScale.Orchestrator",
                    RepositoryCiArchitecture.LinuxX64,
                    "linux-x64")]);
            File.WriteAllBytes(
                Path.Combine(invocation.ExportDirectory, CiRunnerDurableResultSink.ResultManifestPath),
                JsonSerializer.SerializeToUtf8Bytes(
                    manifest,
                    CiRunnerDurableResultJsonContext.Default.CiRunnerResultManifest));
            File.WriteAllText(invocation.MetadataFile, "{\"result\":\"ok\"}");
            return Task.FromResult(new CiRunnerBuildKitProcessResult(
                CiRunnerBuildKitProcessDisposition.Exited,
                0,
                Convert.ToHexStringLower(SHA256.HashData(log)),
                log.LongLength,
                log.ToArray()));
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly CiRunnerBuildKitInvocationTests.InvocationFixture fixture;

        private Fixture(
            CiRunnerBuildKitInvocationTests.InvocationFixture fixture,
            string export,
            byte[] log,
            CiRunnerWorkloadEvidence evidence)
        {
            this.fixture = fixture;
            Export = export;
            Log = log;
            Evidence = evidence;
        }

        internal string Export { get; }
        internal byte[] Log { get; }
        internal CiRunnerWorkloadEvidence Evidence { get; }

        internal static async Task<Fixture> CreateAsync()
        {
            var fixture = CiRunnerBuildKitInvocationTests.Fixture();
            var log = "build completed safely\n"u8.ToArray();
            var result = await new CiRunnerBuildKitExecutor(new Process(log)).ExecuteAsync(
                fixture.Plan,
                fixture.Source,
                fixture.Runtime);
            var export = CiRunnerBuildKitInvocationCompiler.Create(
                fixture.Plan,
                fixture.Source,
                fixture.Runtime).ExportDirectory;
            return new(
                fixture,
                export,
                log,
                new(
                    1,
                    "runner-static",
                    new string('a', 64),
                    fixture.Plan.Job,
                    new string('b', 64),
                    fixture.Plan.ExecutionIdentityDigest,
                    new string('d', 64),
                    new string('e', 64),
                    1,
                    1,
                    fixture.Plan.Attempt,
                    1,
                    fixture.Plan.Digest,
                    fixture.Plan.Source.BundleSha256,
                    fixture.Source.DescriptorSha256,
                    fixture.Source.RecipeSha256,
                    result.Disposition,
                    result.ExitCode,
                    result.LogSha256,
                    result.LogBytes,
                    result.MetadataSha256,
                    result.OutputSha256,
                    result.OutputFiles,
                    result.OutputBytes,
                    true,
                    RepositoryCiJobFailureKind.Unspecified,
                    CiRunnerWorkloadFailureCode.Unspecified));
        }

        public void Dispose() => fixture.Dispose();
    }
}
