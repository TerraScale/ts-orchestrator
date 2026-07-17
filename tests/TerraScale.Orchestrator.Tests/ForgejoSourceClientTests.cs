using System.Net;
using System.Runtime.Versioning;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class ForgejoSourceClientTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Commit = "bffeb74224043ba2feb48d137756c8a9331c449a";
    private const string Tree = "117eb74224043ba2feb48d137756c8a9331c44ff";
    private const string Token = "0123456789abcdef0123456789abcdef01234567";

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
            Requests.Add(new(
                request.RequestUri!.AbsolutePath,
                request.RequestUri.Query,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter));
            return Task.FromResult(remaining.Dequeue()(request));
        }
    }

    private sealed record RequestRecord(
        string Path,
        string Query,
        string? AuthenticationScheme,
        string? AuthenticationParameter);
}
