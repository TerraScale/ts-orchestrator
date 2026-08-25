using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class ForgejoRepositoryCiSourceGraphTests
{
    private const string Root = "TerraScale/Root";
    private const string Downstream = "TerraScale/Downstream";
    private const string BaseCommit = "affe000000000000000000000000000000000001";
    private const string RootDevelopCommit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string RootMainCommit = "cffeb74224043ba2feb48d137756c8a9331c449b";
    private const string DownstreamDevelopCommit = "dffeb74224043ba2feb48d137756c8a9331c449c";
    private const string DownstreamMainCommit = "effeb74224043ba2feb48d137756c8a9331c449d";

    [Test]
    public async Task ConfigurationDefaultsToRootAndRejectsCatalogsThatOmitIt()
    {
        var fixture = await ConfigurationFixture.CreateAsync();
        try
        {
            var defaulted = ForgejoRepositoryCiSourceGraphConfiguration.Load(null, fixture.Source)!;
            await Assert.That(defaulted.Repositories).IsEquivalentTo([Root]);

            await File.WriteAllTextAsync(fixture.GraphFile, $$"""
                {"schemaVersion":1,"repositories":["{{Downstream}}","{{Root}}"]}
                """);
            var configured = ForgejoRepositoryCiSourceGraphConfiguration.Load(
                fixture.GraphFile,
                fixture.Source)!;
            await Assert.That(configured.Repositories).IsEquivalentTo([Root, Downstream]);

            await File.WriteAllTextAsync(fixture.GraphFile, $$"""
                {"schemaVersion":1,"repositories":["{{Downstream}}"]}
                """);
            await Assert.That(() => ForgejoRepositoryCiSourceGraphConfiguration.Load(
                    fixture.GraphFile,
                    fixture.Source))
                .Throws<InvalidDataException>();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task ExactAffectedGraphIncludesProtectedDependentAndRoutesItsArchive()
    {
        var fixture = await ConfigurationFixture.CreateAsync();
        try
        {
            var clients = Clients();
            await using var graph = ForgejoRepositoryCiSourceGraph.CreateForTests(
                fixture.Source,
                await fixture.LoadGraphAsync(),
                configuration => clients[configuration.Repository]);

            var trigger = Trigger("refs/heads/develop", RootDevelopCommit);
            var resolved = await graph.ResolvePipelineAsync(trigger, ["src/root.cs"]);
            var pipeline = RepositoryCiPipelineJournal.CreatePlan(
                trigger,
                resolved.DescriptorFiles,
                [new RepositoryCiChange(Root, ["src/root.cs"])],
                resolved.Sources,
                generation: 1,
                minimumRunnerSequence: 1,
                maximumRunnerSequence: 2);
            var downstream = resolved.Sources.Single(static source => source.Repository == Downstream);
            var archive = await graph.ReadArchiveAsync(downstream);

            await Assert.That(resolved.DescriptorFiles.Select(static file => file.Repository))
                .IsEquivalentTo([Root, Downstream]);
            await Assert.That(resolved.Sources.Select(static source => source.Repository))
                .IsEquivalentTo([Root, Downstream]);
            await Assert.That(pipeline.Jobs.Select(static job => job.Plan.Repository))
                .IsEquivalentTo([Root, Downstream]);
            await Assert.That(resolved.Sources.Single(static source => source.Repository == Root).Commit)
                .IsEqualTo(RootDevelopCommit);
            await Assert.That(downstream.Commit).IsEqualTo(DownstreamDevelopCommit);
            await Assert.That(clients[Downstream].PolledBranches).Contains("develop");
            await Assert.That(archive.Revision.Repository).IsEqualTo(Downstream);
            await Assert.That(clients[Downstream].ArchiveReads).IsEqualTo(1);
            await Assert.That(clients[Root].ArchiveReads).IsEqualTo(0);
        }
        finally
        {
            fixture.Dispose();
        }
    }

    [Test]
    public async Task QualificationSnapshotsExactProtectedMainAcrossAffectedRepositories()
    {
        var fixture = await ConfigurationFixture.CreateAsync();
        try
        {
            var clients = Clients();
            await using var graph = ForgejoRepositoryCiSourceGraph.CreateForTests(
                fixture.Source,
                await fixture.LoadGraphAsync(),
                configuration => clients[configuration.Repository]);

            var observations = await graph.ReadCurrentMainSourcesAsync(
                Trigger("refs/heads/main", RootMainCommit),
                ["src/root.cs"]);

            await Assert.That(observations.Select(static observation => observation.Revision.Repository))
                .IsEquivalentTo([Root, Downstream]);
            await Assert.That(observations.All(static observation => observation.Protected)).IsTrue();
            await Assert.That(observations.Single(static observation => observation.Revision.Repository == Root)
                .Revision.Commit).IsEqualTo(RootMainCommit);
            await Assert.That(observations.Single(static observation => observation.Revision.Repository == Downstream)
                .Revision.Commit).IsEqualTo(DownstreamMainCommit);

            clients[Root].MainCommit = RootDevelopCommit;
            await Assert.That(async () => await graph.ReadCurrentMainSourcesAsync(
                    Trigger("refs/heads/main", RootMainCommit),
                    ["src/root.cs"]))
                .Throws<InvalidDataException>();
        }
        finally
        {
            fixture.Dispose();
        }
    }

    private static Dictionary<string, FakeSourceClient> Clients() => new(StringComparer.Ordinal)
    {
        [Root] = new(Root, RootDevelopCommit, RootMainCommit, dependency: null),
        [Downstream] = new(Downstream, DownstreamDevelopCommit, DownstreamMainCommit, Root),
    };

    private static ForgejoCiTriggerPlan Trigger(string sourceRef, string commit) =>
        ForgejoCiTriggerPlanner.Plan(new(
            Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
            ForgejoWebhookKind.Push,
            "push",
            Root,
            Root,
            BaseCommit,
            commit,
            sourceRef,
            null,
            null,
            false,
            new string('a', 64)));

    private sealed class FakeSourceClient(
        string repository,
        string developCommit,
        string mainCommit,
        string? dependency) : IForgejoRepositorySourceClient
    {
        internal List<string> PolledBranches { get; } = [];
        internal int ArchiveReads { get; private set; }
        internal string MainCommit { get; set; } = mainCommit;

        public Task<ForgejoResolvedRevision> ResolveAsync(
            string commit,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(Revision(commit));
        }

        public Task<ForgejoBranchObservation> PollBranchAsync(
            string branch,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PolledBranches.Add(branch);
            var commit = branch == "main" ? MainCommit : developCommit;
            return Task.FromResult(new ForgejoBranchObservation(branch, isProtected: true, Revision(commit)));
        }

        public Task<ForgejoSourceFile> ReadFileAsync(
            string commit,
            string path,
            int maximumBytes,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dependencyJson = dependency is null
                ? string.Empty
                : $$"""{"repository":"{{dependency}}","reason":"runtime compatibility"}""";
            var content = Encoding.UTF8.GetBytes($$"""
                {
                  "apiVersion":"terrascale.ci/v3",
                  "repository":"{{repository}}",
                  "repositoryDependencies":[{{dependencyJson}}],
                  "nodes":[
                    {"id":"build","kind":"Build","resourceWeight":"Heavy","profiles":["Feature","Build"],"paths":["src/"]},
                    {"id":"artifact","kind":"Artifact","resourceWeight":"Heavy","profiles":["Build"],"dependsOn":["build"]}
                  ]
                }
                """);
            return Task.FromResult(new ForgejoSourceFile(
                repository,
                commit,
                path,
                Hash(Encoding.UTF8.GetBytes($"{repository}:{commit}"))[..40],
                Hash(content),
                content));
        }

        public Task<ForgejoSourceArchive> ReadArchiveAsync(
            ForgejoResolvedRevision revision,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ArchiveReads++;
            var content = Encoding.UTF8.GetBytes(repository);
            return Task.FromResult(new ForgejoSourceArchive(revision, Hash(content), content));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private ForgejoResolvedRevision Revision(string commit) => new(
            repository,
            commit,
            Hash(Encoding.UTF8.GetBytes(commit))[..40],
            signatureVerified: true);
    }

    private sealed class ConfigurationFixture : IDisposable
    {
        private ConfigurationFixture(string tokenFile, string graphFile, ForgejoSourceConfiguration source)
        {
            TokenFile = tokenFile;
            GraphFile = graphFile;
            Source = source;
        }

        private string TokenFile { get; }
        internal string GraphFile { get; }
        internal ForgejoSourceConfiguration Source { get; }

        internal static async Task<ConfigurationFixture> CreateAsync()
        {
            var tokenFile = Path.GetTempFileName();
            var graphFile = Path.GetTempFileName();
            await File.WriteAllTextAsync(tokenFile, "0123456789abcdef0123456789abcdef01234567");
            File.SetUnixFileMode(tokenFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return new(
                tokenFile,
                graphFile,
                ForgejoSourceConfiguration.Resolve("https://git.terrascale.test/", Root, tokenFile)!);
        }

        internal async Task<ForgejoRepositoryCiSourceGraphConfiguration> LoadGraphAsync()
        {
            await File.WriteAllTextAsync(GraphFile, $$"""
                {"schemaVersion":1,"repositories":["{{Root}}","{{Downstream}}"]}
                """);
            return ForgejoRepositoryCiSourceGraphConfiguration.Load(GraphFile, Source)!;
        }

        public void Dispose()
        {
            File.Delete(TokenFile);
            File.Delete(GraphFile);
        }
    }

    private static string Hash(ReadOnlySpan<byte> content) =>
        Convert.ToHexStringLower(SHA256.HashData(content));
}
