using System.IO.Compression;
using System.Net;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class ForgejoSourceClientTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string BaseCommit = "affe000000000000000000000000000000000001";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string Token = "0123456789abcdef0123456789abcdef01234567";

    [Test]
    public async Task RunOptionsRejectPollingWithoutGlobalAuthority()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_FORGEJO_API_URL"] = "https://git.terrascale.tech/",
                ["TS_ORCH_FORGEJO_REPOSITORY"] = Repository,
                ["TS_ORCH_FORGEJO_API_TOKEN_FILE"] = tokenFile,
            };

            var configuration = ForgejoSourceConfiguration.Resolve(
                values["TS_ORCH_FORGEJO_API_URL"],
                values["TS_ORCH_FORGEJO_REPOSITORY"],
                values["TS_ORCH_FORGEJO_API_TOKEN_FILE"]);

            await Assert.That(configuration!.Repository).IsEqualTo(Repository);
            await Assert.That(() => OrchestratorOptions.Parse(["run"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task ConfigurationRequiresCompletePrivateAndSecureApiIdentity()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var remote = ForgejoSourceConfiguration.Resolve("https://git.terrascale.tech/", Repository, tokenFile);
            var local = ForgejoSourceConfiguration.Resolve("http://127.0.0.1:3000/", Repository, tokenFile);

            await Assert.That(remote).IsNotNull();
            await Assert.That(local).IsNotNull();
            await Assert.That(() => ForgejoSourceConfiguration.Resolve(
                    "http://git.terrascale.tech/", Repository, tokenFile)).Throws<ArgumentException>();
            await Assert.That(() => ForgejoSourceConfiguration.Resolve(
                    "https://git.terrascale.tech/", Repository, null)).Throws<ArgumentException>();

            File.SetUnixFileMode(tokenFile, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => ForgejoSourceConfiguration.Resolve(
                    "https://git.terrascale.tech/", Repository, tokenFile)).Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task ExactCommitResolutionPinsTreeAndVerifiedSignature()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(_ =>
            {
                var response = Json($$$$"""
                    {"sha":"{{{{Commit}}}}","commit":{"tree":{"sha":"{{{{Tree}}}}"},"verification":{"verified":true}}}
                    """);
                response.Content.Headers.ContentType!.MediaType = "Application/Json";
                return response;
            });
            await using var client = Client(tokenFile, handler);

            var resolved = await client.ResolveAsync(Commit.ToUpperInvariant());

            await Assert.That(resolved.Repository).IsEqualTo(Repository);
            await Assert.That(resolved.Commit).IsEqualTo(Commit);
            await Assert.That(resolved.Tree).IsEqualTo(Tree);
            await Assert.That(resolved.SignatureVerified).IsTrue();
            await Assert.That(handler.Requests).HasSingleItem();
            await Assert.That(handler.Requests[0].Path).IsEqualTo(
                $"/api/v1/repos/TerraScale/TerraScale.Orchestrator/git/commits/{Commit}");
            await Assert.That(handler.Requests[0].Query).IsEqualTo("?stat=false&verification=true&files=false");
            await Assert.That(handler.Requests[0].AuthenticationScheme).IsEqualTo("token");
            await Assert.That(handler.Requests[0].AuthenticationParameter).IsEqualTo(Token);
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task BranchPollingResolvesObservedCommitRatherThanMovingRef()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(
                _ => Json($$$$"""{"name":"develop","protected":true,"commit":{"id":"{{{{Commit}}}}"}}"""),
                _ => Json($$$$"""{"sha":"{{{{Commit}}}}","commit":{"tree":{"sha":"{{{{Tree}}}}"},"verification":{"verified":false}}}"""));
            await using var client = Client(tokenFile, handler);

            var observation = await client.PollBranchAsync("develop");

            await Assert.That(observation.Branch).IsEqualTo("develop");
            await Assert.That(observation.Protected).IsTrue();
            await Assert.That(observation.Revision.Commit).IsEqualTo(Commit);
            await Assert.That(observation.Revision.Tree).IsEqualTo(Tree);
            await Assert.That(handler.Requests[0].Path).EndsWith("/branches/develop");
            await Assert.That(handler.Requests[1].Path).EndsWith($"/git/commits/{Commit}");
            await Assert.That(async () => { await client.PollBranchAsync("feature/arbitrary"); }).Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task ExactRevisionRangeReturnsBoundedChangedPaths()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var handler = new RecordingHandler(_ => Json("""
                {"total_commits":2,"files":[
                  {"filename":"src/z.cs","status":"modified"},
                  {"filename":"src/a.cs","status":"renamed"}
                ]}
                """));
            await using var client = Client(tokenFile, handler);

            var paths = await client.ReadChangedPathsAsync(Push());

            await Assert.That(paths).IsEquivalentTo([
                RepositoryCiImpactPlanner.DescriptorPath,
                "src/a.cs",
                "src/z.cs",
            ]);
            await Assert.That(paths.SequenceEqual([
                RepositoryCiImpactPlanner.DescriptorPath,
                "src/a.cs",
                "src/z.cs",
            ], StringComparer.Ordinal)).IsTrue();
            await Assert.That(handler.Requests).HasSingleItem();
            await Assert.That(handler.Requests[0].Path).EndsWith($"/compare/{BaseCommit}...{Commit}");
            await Assert.That(handler.Requests[0].Query).IsEmpty();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AmbiguousOrUnsafeComparisonPathsFailClosed()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var duplicate = new RecordingHandler(_ => Json("""
                {"files":[
                  {"filename":"src/a.cs","status":"modified"},
                  {"filename":"src/a.cs","status":"added"}
                ]}
                """));
            await using var duplicateClient = Client(tokenFile, duplicate);
            await Assert.That(async () => await duplicateClient.ReadChangedPathsAsync(Push()))
                .Throws<InvalidDataException>();

            var unsafePath = new RecordingHandler(_ => Json("""
                {"files":[{"filename":"../secret","status":"modified"}]}
                """));
            await using var unsafeClient = Client(tokenFile, unsafePath);
            await Assert.That(async () => await unsafeClient.ReadChangedPathsAsync(Push()))
                .Throws<InvalidDataException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AmbiguousOrSubstitutedGitObjectsFailClosed()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var substituted = new RecordingHandler(_ => Json($$$$"""
                {"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","commit":{"tree":{"sha":"{{{{Tree}}}}"}}}
                """));
            await using var substitutedClient = Client(tokenFile, substituted);
            await Assert.That(async () => { await substitutedClient.ResolveAsync(Commit); }).Throws<InvalidDataException>();

            var duplicate = new RecordingHandler(_ => Json($$$$"""
                {"sha":"{{{{Commit}}}}","sha":"{{{{Commit}}}}","commit":{"tree":{"sha":"{{{{Tree}}}}"}}}
                """));
            await using var duplicateClient = Client(tokenFile, duplicate);
            await Assert.That(async () => { await duplicateClient.ResolveAsync(Commit); }).Throws<InvalidDataException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task AuthenticationAndResponseBoundsFailWithoutCredentialDisclosure()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var denied = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = Json($$$$"""{"error":"{{{{Token}}}}"}""").Content
            });
            await using var deniedClient = Client(tokenFile, denied);
            var deniedError = await Assert.That(async () => { await deniedClient.ResolveAsync(Commit); })
                .Throws<UnauthorizedAccessException>();
            await Assert.That(deniedError!.Message).DoesNotContain(Token);

            var oversized = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[64 * 1024 + 1])
                {
                    Headers = { ContentType = new("application/json") }
                }
            });
            await using var oversizedClient = Client(tokenFile, oversized);
            await Assert.That(async () => { await oversizedClient.ResolveAsync(Commit); }).Throws<InvalidDataException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task ExactArchiveFetchBindsResolvedCommitTreeAndContent()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var content = Gzip("exact source");
            var handler = new RecordingHandler(_ => Archive(content));
            await using var client = Client(tokenFile, handler);
            var revision = new ForgejoResolvedRevision(Repository, Commit, Tree, signatureVerified: true);

            var archive = await client.ReadArchiveAsync(revision);

            await Assert.That(archive.Revision).IsSameReferenceAs(revision);
            await Assert.That(archive.Content.ToArray()).IsEquivalentTo(content);
            await Assert.That(archive.ContentLength).IsEqualTo(content.Length);
            await Assert.That(archive.ContentSha256).IsEqualTo(
                Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(content)));
            await Assert.That(handler.Requests).HasSingleItem();
            await Assert.That(handler.Requests[0].Path).IsEqualTo(
                $"/api/v1/repos/TerraScale/TerraScale.Orchestrator/archive/{Commit}.tar.gz");
            await Assert.That(handler.Requests[0].AuthenticationParameter).IsEqualTo(Token);
            await Assert.That(handler.Requests[0].Accept).IsEqualTo(
                "application/gzip,application/octet-stream");
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task TerminalCommitStatusRequiresExactForgejoReadback()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var accepted = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent($$"""
                    {"id":42,"context":"{{ForgejoSourceClient.CiStatusContext}}","description":"TerraScale CI passed.","status":"success"}
                    """, Encoding.UTF8, "application/json"),
            });
            await using var client = Client(tokenFile, accepted);

            await client.ReportCommitStatusAsync(Commit, ForgejoCommitStatusState.Success);

            var request = accepted.Requests.Single();
            using var body = JsonDocument.Parse(request.Body);
            await Assert.That(request.Method).IsEqualTo("POST");
            await Assert.That(request.Path).IsEqualTo(
                $"/api/v1/repos/TerraScale/TerraScale.Orchestrator/statuses/{Commit}");
            await Assert.That(request.ContentType).IsEqualTo("application/json");
            await Assert.That(body.RootElement.GetProperty("context").GetString())
                .IsEqualTo(ForgejoSourceClient.CiStatusContext);
            await Assert.That(body.RootElement.GetProperty("description").GetString())
                .IsEqualTo("TerraScale CI passed.");
            await Assert.That(body.RootElement.GetProperty("state").GetString()).IsEqualTo("success");

            var substituted = new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = Json("""
                    {"id":43,"context":"other","description":"TerraScale CI failed.","status":"failure"}
                    """).Content,
            });
            await using var substitutedClient = Client(tokenFile, substituted);
            await Assert.That(async () => await substitutedClient.ReportCommitStatusAsync(
                    Commit,
                    ForgejoCommitStatusState.Failure))
                .Throws<InvalidDataException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    [Test]
    public async Task ArchiveFetchRejectsWrongRepositoryTypeSizeAndMagic()
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var wrongRepository = new RecordingHandler(_ => Archive(Gzip("unused")));
            await using var wrongRepositoryClient = Client(tokenFile, wrongRepository);
            await Assert.That(async () => await wrongRepositoryClient.ReadArchiveAsync(
                    new("TerraScale/TerraBase", Commit, Tree, signatureVerified: true)))
                .Throws<ArgumentException>();
            await Assert.That(wrongRepository.Requests).IsEmpty();

            var wrongType = new RecordingHandler(_ => Archive(Gzip("source"), "application/zip"));
            await using var wrongTypeClient = Client(tokenFile, wrongType);
            await Assert.That(async () => await wrongTypeClient.ReadArchiveAsync(Revision()))
                .Throws<InvalidDataException>();

            var oversized = new RecordingHandler(_ =>
            {
                var response = Archive(Gzip("source"));
                response.Content.Headers.ContentLength = (long)ForgejoSourceClient.MaximumArchiveBytes + 1;
                return response;
            });
            await using var oversizedClient = Client(tokenFile, oversized);
            await Assert.That(async () => await oversizedClient.ReadArchiveAsync(Revision()))
                .Throws<InvalidDataException>();

            var mismatchedLength = new RecordingHandler(_ =>
            {
                var response = Archive(Gzip("source"));
                response.Content.Headers.ContentLength--;
                return response;
            });
            await using var mismatchedLengthClient = Client(tokenFile, mismatchedLength);
            await Assert.That(async () => await mismatchedLengthClient.ReadArchiveAsync(Revision()))
                .Throws<InvalidDataException>();

            var wrongMagic = new RecordingHandler(_ => Archive([1, 2, 3, 4]));
            await using var wrongMagicClient = Client(tokenFile, wrongMagic);
            await Assert.That(async () => await wrongMagicClient.ReadArchiveAsync(Revision()))
                .Throws<InvalidDataException>();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private static ForgejoSourceClient Client(string tokenFile, RecordingHandler handler)
    {
        var configuration = ForgejoSourceConfiguration.Resolve(
            "https://git.terrascale.tech/",
            Repository,
            tokenFile)!;
        return new(configuration, new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan });
    }

    private static ForgejoWebhookEnvelope Push() => new(
        Guid.Parse("f6266f16-1bf3-46a5-9ea4-602e06ead473"),
        ForgejoWebhookKind.Push,
        "push",
        Repository,
        Repository,
        BaseCommit,
        Commit,
        "refs/heads/develop",
        null,
        null,
        false,
        new string('a', 64));

    private static HttpResponseMessage Json(string value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage Archive(byte[] value, string mediaType = "application/gzip") =>
        new(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(value)
            {
                Headers = { ContentType = new(mediaType) }
            }
        };

    private static byte[] Gzip(string value)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
            gzip.Write(Encoding.UTF8.GetBytes(value));
        return output.ToArray();
    }

    private static ForgejoResolvedRevision Revision() =>
        new(Repository, Commit, Tree, signatureVerified: true);

    private static async Task<string> CreateTokenFileAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"forgejo-api-{Guid.NewGuid():N}.token");
        await File.WriteAllTextAsync(path, Token, new UTF8Encoding(false));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private sealed class RecordingHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses)
        : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, HttpResponseMessage>> remaining = new(responses);

        internal List<RequestRecord> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var body = request.Content is null
                ? string.Empty
                : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new(
                request.Method.Method,
                request.RequestUri!.AbsolutePath,
                request.RequestUri.Query,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                string.Join(",", request.Headers.Accept.Select(static value => value.MediaType)),
                request.Content?.Headers.ContentType?.MediaType,
                body));
            return remaining.Dequeue()(request);
        }
    }

    private sealed record RequestRecord(
        string Method,
        string Path,
        string Query,
        string? AuthenticationScheme,
        string? AuthenticationParameter,
        string Accept,
        string? ContentType,
        string Body);
}

