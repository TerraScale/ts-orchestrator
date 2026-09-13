using System.Collections.Concurrent;
using System.Formats.Tar;
using System.IO.Compression;
using System.Runtime.Versioning;
using System.Security.Cryptography;
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

        var first = await sink.PersistAsync(fixture.Evidence, fixture.Log, fixture.Export, fixture.Plan, default);
        var artifactName = $"ci-result-artifact-{fixture.Evidence.OutputSha256}";
        var firstArtifact = store.Values[artifactName].ToArray();
        var replay = await sink.PersistAsync(fixture.Evidence, fixture.Log, fixture.Export, fixture.Plan, default);
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
        await Assert.That(stored.Artifacts).IsEmpty();
        await Assert.That(ArchiveEntries(firstArtifact)).IsEquivalentTo([
            CiRunnerDurableResultSink.ResultManifestPath,
            "result.txt",
        ]);
    }

    [Test]
    public async Task CandidateRootsMatchSignedArchitecturesAndBecomeDurableContentEvidence()
    {
        using var fixture = await CandidateFixture.CreateAsync();
        var store = new ObjectStore();

        var result = await new CiRunnerDurableResultSink(store).PersistAsync(
            fixture.Evidence,
            fixture.Log,
            fixture.Export,
            fixture.Plan,
            default);
        var stored = JsonSerializer.Deserialize(
            store.Values[$"ci-result-evidence-{result.EvidenceDigest}"],
            CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence)!;

        await Assert.That(stored.Artifacts!.Select(static value => value.Architecture))
            .IsEquivalentTo([RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64]);
        await Assert.That(stored.Artifacts!.Select(static value => value.Path))
            .IsEquivalentTo(["linux-x64", "linux-arm64"]);
        await Assert.That(stored.Artifacts!.All(static value => value.Files == 1 && value.Bytes > 0 &&
            value.Digest.Length == 64)).IsTrue();
        await Assert.That(stored.Artifacts!.All(static value => value.Entrypoints.SequenceEqual(["app"])))
            .IsTrue();
        await Assert.That(ArchiveEntries(store.Values[stored.ArtifactObject])).IsEquivalentTo([
            CiRunnerDurableResultSink.ResultManifestPath,
            "linux-x64/app",
            "linux-arm64/app",
        ]);
    }

    [Test]
    public async Task GenericOutputAcceptsRollingManifestWithoutArtifactDeclarations()
    {
        using var fixture = await Fixture.CreateAsync();
        await File.WriteAllTextAsync(
            Path.Combine(fixture.Export, CiRunnerDurableResultSink.ResultManifestPath),
            $$"""
            {"schemaVersion":2,"job":"{{fixture.Evidence.Job}}","planDigest":"{{fixture.Evidence.PlanDigest}}","succeeded":true,"requiredTestSkips":0}
            """);
        var output = await CiRunnerBuildKitExecutor.HashOutputAsync(fixture.Export, 1024 * 1024, default);
        var evidence = fixture.Evidence with
        {
            OutputSha256 = output.Digest,
            OutputFiles = output.Files,
            OutputBytes = output.Bytes,
        };
        var store = new ObjectStore();

        var result = await new CiRunnerDurableResultSink(store).PersistAsync(
            evidence,
            fixture.Log,
            fixture.Export,
            fixture.Plan,
            default);
        var stored = JsonSerializer.Deserialize(
            store.Values[$"ci-result-evidence-{result.EvidenceDigest}"],
            CiRunnerDurableResultJsonContext.Default.CiRunnerStoredWorkloadEvidence)!;

        await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.Unspecified);
        await Assert.That(stored.Artifacts).IsEmpty();
    }

    [Test]
    public async Task SubstitutedArchitectureAndUndeclaredOutputAreRejectedBeforeArtifactEvidence()
    {
        using (var substituted = await CandidateFixture.CreateAsync())
        {
            substituted.WriteManifest([
                new("TerraScale/TerraScale.Orchestrator", "LinuxArm64", "linux-x64", ["app"]),
                new("TerraScale/TerraScale.Orchestrator", "LinuxX64", "linux-arm64", ["app"]),
            ]);
            var result = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                substituted.Evidence,
                substituted.Log,
                substituted.Export,
                substituted.Plan,
                default);
            await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var undeclared = await CandidateFixture.CreateAsync())
        {
            await File.WriteAllTextAsync(Path.Combine(undeclared.Export, "extra.txt"), "substituted");
            var output = await CiRunnerBuildKitExecutor.HashOutputAsync(
                undeclared.Export,
                1024 * 1024,
                default);
            var evidence = undeclared.Evidence with
            {
                OutputSha256 = output.Digest,
                OutputFiles = output.Files,
                OutputBytes = output.Bytes,
            };
            var result = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                evidence,
                undeclared.Log,
                undeclared.Export,
                undeclared.Plan,
                default);
            await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var mislabeled = await CandidateFixture.CreateAsync())
        {
            var arm64 = Path.Combine(mislabeled.Export, "linux-arm64", "app");
            await File.WriteAllBytesAsync(arm64, Elf(62));
            File.SetUnixFileMode(arm64, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
            var output = await CiRunnerBuildKitExecutor.HashOutputAsync(
                mislabeled.Export,
                1024 * 1024,
                default);
            var evidence = mislabeled.Evidence with
            {
                OutputSha256 = output.Digest,
                OutputFiles = output.Files,
                OutputBytes = output.Bytes,
            };
            var result = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                evidence,
                mislabeled.Log,
                mislabeled.Export,
                mislabeled.Plan,
                default);
            await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var missingEntrypoint = await CandidateFixture.CreateAsync())
        {
            missingEntrypoint.WriteManifest([
                new("TerraScale/TerraScale.Orchestrator", "LinuxX64", "linux-x64", ["missing"]),
                new("TerraScale/TerraScale.Orchestrator", "LinuxArm64", "linux-arm64", ["app"]),
            ]);
            var result = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                missingEntrypoint.Evidence,
                missingEntrypoint.Log,
                missingEntrypoint.Export,
                missingEntrypoint.Plan,
                default);
            await Assert.That(result.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }
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
            fixture.Plan,
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
                fixture.Plan,
                default))
            .Throws<InvalidDataException>();
        await Assert.That(async () => await new CiRunnerDurableResultSink(
                new ObjectStore(corruptReads: true)).PersistAsync(
                fixture.Evidence,
                fixture.Log,
                fixture.Export,
                fixture.Plan,
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
                linked.Plan,
                default);
            await Assert.That(rejected.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var duplicate = await Fixture.CreateAsync())
        {
            await File.WriteAllTextAsync(
                Path.Combine(duplicate.Export, CiRunnerDurableResultSink.ResultManifestPath),
                $$"""
                {"schemaVersion":2,"schemaVersion":2,"job":"{{duplicate.Evidence.Job}}","planDigest":"{{duplicate.Evidence.PlanDigest}}","succeeded":true,"requiredTestSkips":0}
                """);
            var rejected = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                duplicate.Evidence,
                duplicate.Log,
                duplicate.Export,
                duplicate.Plan,
                default);
            await Assert.That(rejected.FailureKind).IsEqualTo(RepositoryCiJobFailureKind.WorkloadFailed);
        }

        using (var missing = await Fixture.CreateAsync())
        {
            var manifest = new CiRunnerResultManifest(
                2,
                missing.Evidence.Job,
                missing.Evidence.PlanDigest,
                true,
                0,
                [new("TerraScale/TerraScale.Orchestrator", "LinuxX64", "missing", ["app"])]);
            await File.WriteAllBytesAsync(
                Path.Combine(missing.Export, CiRunnerDurableResultSink.ResultManifestPath),
                JsonSerializer.SerializeToUtf8Bytes(
                    manifest,
                    CiRunnerDurableResultJsonContext.Default.CiRunnerResultManifest));
            var rejected = await new CiRunnerDurableResultSink(new ObjectStore()).PersistAsync(
                missing.Evidence,
                missing.Log,
                missing.Export,
                missing.Plan,
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
            var manifest = new CiRunnerResultManifest(
                2,
                "ci-job",
                CiRunnerSourceMaterializerTests.Plan([0x1f, 0x8b, 0x08, 1]).Digest,
                true,
                0,
                []);
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
        internal CiRunnerExecutionPlan Plan => fixture.Plan;

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

    private sealed class CandidateFixture : IDisposable
    {
        private readonly CiRunnerBuildKitInvocationTests.InvocationFixture fixture;

        private CandidateFixture(
            CiRunnerBuildKitInvocationTests.InvocationFixture fixture,
            CiRunnerExecutionPlan plan,
            string export,
            byte[] log,
            CiRunnerWorkloadEvidence evidence)
        {
            this.fixture = fixture;
            Plan = plan;
            Export = export;
            Log = log;
            Evidence = evidence;
        }

        internal CiRunnerExecutionPlan Plan { get; }
        internal string Export { get; }
        internal byte[] Log { get; }
        internal CiRunnerWorkloadEvidence Evidence { get; }

        internal static async Task<CandidateFixture> CreateAsync()
        {
            var fixture = CiRunnerBuildKitInvocationTests.Fixture();
            var original = fixture.Plan;
            var plan = new CiRunnerExecutionPlan(
                original.PipelineDigest,
                original.Job,
                original.JobDigest,
                original.ExecutionIdentityDigest,
                original.Attempt,
                original.Source,
                new(
                    CiRunnerExecutionPlanner.Frontend,
                    "ci-artifact",
                    [RepositoryCiArchitecture.LinuxX64, RepositoryCiArchitecture.LinuxArm64],
                    CiRunnerExecutionOutputKind.CandidateArtifacts,
                    original.Build.Network,
                    original.Build.Credentials,
                    original.Build.Cache,
                    original.Build.CacheNamespace,
                    original.Build.CpuMilliCores,
                    original.Build.MemoryBytes,
                    original.Build.EphemeralDiskBytes,
                    original.Build.Pids,
                    original.Build.MaximumLogBytes,
                    original.Build.Timeout));
            var export = Path.Combine(fixture.Root, "candidate");
            Directory.CreateDirectory(Path.Combine(export, "linux-x64"));
            Directory.CreateDirectory(Path.Combine(export, "linux-arm64"));
            var x64 = Path.Combine(export, "linux-x64", "app");
            var arm64 = Path.Combine(export, "linux-arm64", "app");
            await File.WriteAllBytesAsync(x64, Elf(62));
            await File.WriteAllBytesAsync(arm64, Elf(183));
            File.SetUnixFileMode(x64, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
            File.SetUnixFileMode(arm64, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                UnixFileMode.UserExecute);
            var log = "candidate built safely\n"u8.ToArray();
            WriteManifest(export, plan, [
                new("TerraScale/TerraScale.Orchestrator", "LinuxX64", "linux-x64", ["app"]),
                new("TerraScale/TerraScale.Orchestrator", "LinuxArm64", "linux-arm64", ["app"]),
            ]);
            var output = await CiRunnerBuildKitExecutor.HashOutputAsync(export, 1024 * 1024, default);
            return new(
                fixture,
                plan,
                export,
                log,
                CreateEvidence(plan, fixture.Source, log, output));
        }

        internal void WriteManifest(CiRunnerResultArtifact[] artifacts) =>
            WriteManifest(Export, Plan, artifacts);

        private static void WriteManifest(
            string export,
            CiRunnerExecutionPlan plan,
            CiRunnerResultArtifact[] artifacts) =>
            File.WriteAllBytes(
                Path.Combine(export, CiRunnerDurableResultSink.ResultManifestPath),
                JsonSerializer.SerializeToUtf8Bytes(
                    new CiRunnerResultManifest(2, plan.Job, plan.Digest, true, 0, artifacts),
                    CiRunnerDurableResultJsonContext.Default.CiRunnerResultManifest));

        private static CiRunnerWorkloadEvidence CreateEvidence(
            CiRunnerExecutionPlan plan,
            CiRunnerMaterializedSource source,
            byte[] log,
            (string Digest, int Files, long Bytes) output) => new(
                1,
                "runner-artifact",
                plan.PipelineDigest,
                plan.Job,
                plan.JobDigest,
                plan.ExecutionIdentityDigest,
                new string('d', 64),
                new string('e', 64),
                1,
                1,
                plan.Attempt,
                1,
                plan.Digest,
                plan.Source.BundleSha256,
                source.DescriptorSha256,
                source.RecipeSha256,
                CiRunnerBuildKitExecutionDisposition.Succeeded,
                0,
                Convert.ToHexStringLower(SHA256.HashData(log)),
                log.LongLength,
                new string('f', 64),
                output.Digest,
                output.Files,
                output.Bytes,
                true,
                RepositoryCiJobFailureKind.Unspecified,
                CiRunnerWorkloadFailureCode.Unspecified);

        public void Dispose() => fixture.Dispose();
    }

    private static byte[] Elf(byte machine)
    {
        var header = new byte[20];
        "\x7fELF"u8.CopyTo(header);
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[18] = machine;
        return header;
    }
}

