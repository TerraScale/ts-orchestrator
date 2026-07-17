using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class NativeGitOpsSourceLoaderTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string Blob = "217eb74224043ba2feb48d137756c8a9331c44ee";
    private const string Commit2 = "cffeb74224043ba2feb48d137756c8a9331c449b";
    private const string Tree2 = "317eb74224043ba2feb48d137756c8a9331c44dd";
    private const string Blob2 = "417eb74224043ba2feb48d137756c8a9331c44cc";
    private const string Token = "0123456789abcdef0123456789abcdef01234567";
    private const string DigestV1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string DigestV2 = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Test]
    public async Task VerifiedExactCommitLoadsAndCompilesBoundedManifest()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var manifest = Manifest(1, DigestV1);
            var handler = new RecordingHandler(_ => FileResponse(manifest));
            await using var client = Client(tokenFile, handler);

            var result = await NativeGitOpsSourceLoader.LoadAsync(
                client,
                new(Repository, Commit, Tree, signatureVerified: true));

            await Assert.That(result.Revision.Commit).IsEqualTo(Commit);
            await Assert.That(result.SourceFile.Blob).IsEqualTo(Blob);
            await Assert.That(result.SourceFile.ContentSha256).IsEqualTo(
                Convert.ToHexStringLower(SHA256.HashData(manifest)));
            await Assert.That(result.Proposed.Generation).IsEqualTo(1);
            await Assert.That(result.Diff.Changes).HasSingleItem();
            await Assert.That(result.Diff.Changes[0].Kind).IsEqualTo(NativeGitOpsChangeKind.Create);
            await Assert.That(handler.Requests).HasSingleItem();
            await Assert.That(handler.Requests[0].Path).IsEqualTo(
                "/api/v1/repos/TerraScale/TerraScale.Orchestrator/contents/.terrascale/orchestrator.json");
            await Assert.That(handler.Requests[0].Query).IsEqualTo($"?ref={Commit}");
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AcceptedPlanProducesTypedUpdateFromNewCommitContent()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var accepted = NativeGitOpsManifest.Parse(Manifest(1, DigestV1));
            var handler = new RecordingHandler(_ => FileResponse(Manifest(2, DigestV2)));
            await using var client = Client(tokenFile, handler);

            var result = await NativeGitOpsSourceLoader.LoadAsync(
                client,
                new(Repository, Commit, Tree, signatureVerified: true),
                accepted);

            await Assert.That(result.Diff.Changes).HasSingleItem();
            await Assert.That(result.Diff.Changes[0].Kind).IsEqualTo(NativeGitOpsChangeKind.Update);
            await Assert.That(result.Diff.AcceptedGeneration).IsEqualTo(1);
            await Assert.That(result.Diff.ProposedGeneration).IsEqualTo(2);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task UnverifiedRevisionIsRejectedBeforeNetworkAccess()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(_ => throw new InvalidOperationException("Network access was unexpected."));
            await using var client = Client(tokenFile, handler);

            await Assert.That(async () => await NativeGitOpsSourceLoader.LoadAsync(
                    client,
                    new(Repository, Commit, Tree, signatureVerified: false)))
                .Throws<InvalidDataException>();
            await Assert.That(handler.Requests).IsEmpty();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task FileMetadataAndEncodingSubstitutionFailClosed()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var content = Manifest(1, DigestV1);
            var responses = new Func<HttpResponseMessage>[]
            {
                () => FileResponse(content, type: "symlink"),
                () => FileResponse(content, path: ".terrascale/other.json"),
                () => FileResponse(content, size: content.Length + 1),
                () => FileResponse(content, encoding: "utf-8"),
                () => FileResponse(content, encodedContent: "***"),
            };

            foreach (var response in responses)
            {
                await using var client = Client(tokenFile, new(_ => response()));
                await Assert.That(async () => await client.ReadFileAsync(
                        Commit,
                        NativeGitOpsSourceLoader.ManifestPath,
                        NativeGitOpsManifest.MaximumBytes))
                    .Throws<InvalidDataException>();
            }
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task UnsafePathsAndCallerBoundsFailBeforeOrDuringBoundedRead()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var content = Manifest(1, DigestV1);
            var handler = new RecordingHandler(_ => FileResponse(content));
            await using var client = Client(tokenFile, handler);

            await Assert.That(async () => await client.ReadFileAsync(Commit, "../orchestrator.json", 1024))
                .Throws<ArgumentException>();
            await Assert.That(async () => await client.ReadFileAsync(Commit, "manifest.json", 0))
                .Throws<ArgumentOutOfRangeException>();
            await Assert.That(handler.Requests).IsEmpty();

            await Assert.That(async () => await client.ReadFileAsync(
                    Commit,
                    NativeGitOpsSourceLoader.ManifestPath,
                    content.Length - 1))
                .Throws<InvalidDataException>();
            await Assert.That(handler.Requests).HasSingleItem();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task FencedReconcilerAdvancesDurableAcceptedPlanAcrossCommits()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(
                _ => FileResponse(Manifest(1, DigestV1)),
                _ => FileResponse(Manifest(2, DigestV2), blob: Blob2));
            await using var client = Client(tokenFile, handler);
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var manifests = new NativeGitOpsSourceJournalTests.TestManifestStore();
            var journal = new NativeGitOpsSourceJournal(ledger, manifests);
            var authority = Authority(7);
            var reconciler = new NativeGitOpsSourceReconciler(client, journal, () => authority);

            var initial = await reconciler.ReconcileAsync(
                new("develop", true, new(Repository, Commit, Tree, signatureVerified: true)),
                7,
                1);
            var updated = await reconciler.ReconcileAsync(
                new("develop", true, new(Repository, Commit2, Tree2, signatureVerified: true)),
                7,
                2);
            var accepted = await journal.ReadAsync(Repository, "develop");

            await Assert.That(initial.Disposition)
                .IsEqualTo(NativeGitOpsSourceJournalDisposition.Recorded);
            await Assert.That(updated.Disposition)
                .IsEqualTo(NativeGitOpsSourceJournalDisposition.Recorded);
            await Assert.That(updated.SourcePlan!.Diff.Changes).HasSingleItem();
            await Assert.That(updated.SourcePlan.Diff.Changes[0].Kind)
                .IsEqualTo(NativeGitOpsChangeKind.Update);
            await Assert.That(accepted!.Revision.Commit).IsEqualTo(Commit2);
            await Assert.That(accepted.Plan.Generation).IsEqualTo(2);
            await Assert.That(manifests.PutCount).IsEqualTo(2);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AuthorityLossDuringManifestReadCannotAdvanceAcceptedState()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var authority = Authority(7);
            var handler = new RecordingHandler(_ =>
            {
                authority = Authority(8, leader: false);
                return FileResponse(Manifest(1, DigestV1));
            });
            await using var client = Client(tokenFile, handler);
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var manifests = new NativeGitOpsSourceJournalTests.TestManifestStore();
            var reconciler = new NativeGitOpsSourceReconciler(
                client,
                new(ledger, manifests),
                () => authority);

            var result = await reconciler.ReconcileAsync(
                new("develop", true, new(Repository, Commit, Tree, signatureVerified: true)),
                7,
                1);

            await Assert.That(result.Disposition)
                .IsEqualTo(NativeGitOpsSourceJournalDisposition.StaleAuthority);
            await Assert.That(result.SourcePlan).IsNull();
            await Assert.That(ledger.Mutations).IsEqualTo(0);
            await Assert.That(manifests.PutCount).IsEqualTo(0);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task RepositoryWithoutNativeManifestKeepsAcceptedStateUnchanged()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(_ => new(HttpStatusCode.NotFound));
            await using var client = Client(tokenFile, handler);
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var manifests = new NativeGitOpsSourceJournalTests.TestManifestStore();
            var reconciler = new NativeGitOpsSourceReconciler(
                client,
                new(ledger, manifests),
                () => Authority(7));

            var result = await reconciler.ReconcileAsync(
                new("develop", true, new(Repository, Commit, Tree, signatureVerified: true)),
                7,
                1);

            await Assert.That(result.Disposition)
                .IsEqualTo(NativeGitOpsSourceJournalDisposition.NotConfigured);
            await Assert.That(result.SourcePlan).IsNull();
            await Assert.That(ledger.Mutations).IsEqualTo(0);
            await Assert.That(manifests.PutCount).IsEqualTo(0);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AuthorityLossDuringBlobWriteLeavesOnlyUnreferencedContent()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var authority = Authority(7);
            var handler = new RecordingHandler(_ => FileResponse(Manifest(1, DigestV1)));
            await using var client = Client(tokenFile, handler);
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var manifests = new NativeGitOpsSourceJournalTests.TestManifestStore
            {
                AfterPut = () => authority = Authority(8, leader: false)
            };
            var reconciler = new NativeGitOpsSourceReconciler(
                client,
                new(ledger, manifests),
                () => authority);

            var result = await reconciler.ReconcileAsync(
                new("develop", true, new(Repository, Commit, Tree, signatureVerified: true)),
                7,
                1);

            await Assert.That(result.Disposition)
                .IsEqualTo(NativeGitOpsSourceJournalDisposition.StaleAuthority);
            await Assert.That(ledger.Mutations).IsEqualTo(0);
            await Assert.That(manifests.Values).HasSingleItem();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private static byte[] Manifest(long generation, string digest) => Encoding.UTF8.GetBytes($$"""
        {"apiVersion":"terrascale.io/v1","kind":"TerraScaleDesiredState","generation":{{generation}},"workloads":[{"id":"platform","role":"Platform","artifactDigest":"{{digest}}","cells":["gru"]}]}
        """);

    private static HttpResponseMessage FileResponse(
        byte[] content,
        string type = "file",
        string path = NativeGitOpsSourceLoader.ManifestPath,
        long? size = null,
        string encoding = "base64",
        string? encodedContent = null,
        string blob = Blob) => Json(JsonSerializer.Serialize(new
        {
            type,
            name = "orchestrator.json",
            path,
            sha = blob,
            size = size ?? content.LongLength,
            encoding,
            content = encodedContent ?? Convert.ToBase64String(content),
        }));

    private static ForgejoSourceClient Client(string tokenFile, RecordingHandler handler)
    {
        var configuration = ForgejoSourceConfiguration.Resolve(
            "https://git.terrascale.tech/",
            Repository,
            tokenFile)!;
        return new(configuration, new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan });
    }

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private static async Task<string> CreateTokenFileAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"forgejo-api-{Guid.NewGuid():N}.token");
        await File.WriteAllTextAsync(path, Token, new UTF8Encoding(false));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private static RegionalAuthoritySnapshot Authority(long epoch, bool leader = true)
    {
        var now = DateTimeOffset.UtcNow;
        return new(
            leader ? "leader" : "follower",
            leader,
            epoch,
            epoch,
            now.AddSeconds(10),
            now,
            null);
    }

    private sealed class RecordingHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> remaining = new(responses);

        internal List<RequestRecord> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(new(request.RequestUri!.AbsolutePath, request.RequestUri.Query));
            return Task.FromResult(remaining.Dequeue()(request));
        }
    }

    private sealed record RequestRecord(string Path, string Query);
}
