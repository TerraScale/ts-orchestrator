using System.Net;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class ForgejoGenericPackagePublisherTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Token = "forgejo-package-test-token-1234567890";

    [Test]
    public async Task MissingPackageIsUploadedAndVerifiedByExactReadback()
    {
        var content = Encoding.UTF8.GetBytes("immutable candidate archive");
        var handler = new RecordingHandler(
            static (_, _) => Response(HttpStatusCode.NotFound),
            static (_, _) => Response(HttpStatusCode.Created),
            (_, _) => Package(content));

        var receipt = await PublishAsync(handler, content);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(ForgejoGenericPackagePublicationDisposition.Recorded);
        await Assert.That(handler.Requests.Select(static value => value.Method)
            .SequenceEqual(["GET", "PUT", "GET"])).IsTrue();
        await Assert.That(handler.Requests[1].Body).IsEquivalentTo(content);
        await Assert.That(handler.Requests[1].ContentType).IsEqualTo("application/octet-stream");
        await Assert.That(handler.Requests.All(static value => value.AuthenticationScheme == "token" &&
            value.AuthenticationParameter == Token)).IsTrue();
        await Assert.That(handler.Requests.Select(static value => value.Path).Distinct()).HasSingleItem();
        var digest = Convert.ToHexStringLower(SHA256.HashData(content));
        await Assert.That(handler.Requests[0].Path).IsEqualTo(
            $"/api/packages/TerraScale/generic/ci-terrascale.orchestrator/{digest}/ci-job.tar.gz");
    }

    [Test]
    public async Task ExactExistingPackageIsAnIdempotentDuplicateWithoutUpload()
    {
        var content = Encoding.UTF8.GetBytes("existing archive");
        var handler = new RecordingHandler((_, _) => Package(content));

        var receipt = await PublishAsync(handler, content);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(ForgejoGenericPackagePublicationDisposition.Duplicate);
        await Assert.That(handler.Requests).HasSingleItem();
        await Assert.That(handler.Requests[0].Method).IsEqualTo("GET");
    }

    [Test]
    public async Task ExistingBytesUnderTheImmutableIdentityAreRejected()
    {
        var content = Encoding.UTF8.GetBytes("candidate archive");
        var handler = new RecordingHandler((_, _) => Package(Encoding.UTF8.GetBytes("different archive")));

        var receipt = await PublishAsync(handler, content);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(ForgejoGenericPackagePublicationDisposition.IdentityConflict);
        await Assert.That(handler.Requests).HasSingleItem();
    }

    [Test]
    public async Task ConcurrentExactUploadIsReconciledAsDuplicate()
    {
        var content = Encoding.UTF8.GetBytes("concurrent archive");
        var handler = new RecordingHandler(
            static (_, _) => Response(HttpStatusCode.NotFound),
            static (_, _) => Response(HttpStatusCode.Conflict),
            (_, _) => Package(content));

        var receipt = await PublishAsync(handler, content);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(ForgejoGenericPackagePublicationDisposition.Duplicate);
        await Assert.That(handler.Requests.Select(static value => value.Method)
            .SequenceEqual(["GET", "PUT", "GET"])).IsTrue();
    }

    [Test]
    public async Task LostAuthorityAfterPreflightCannotStartAnUpload()
    {
        var content = Encoding.UTF8.GetBytes("candidate archive");
        var handler = new RecordingHandler(static (_, _) => Response(HttpStatusCode.NotFound));
        var checks = 0;

        var receipt = await PublishAsync(handler, content, () => ++checks == 1);

        await Assert.That(receipt.Disposition)
            .IsEqualTo(ForgejoGenericPackagePublicationDisposition.StaleAuthority);
        await Assert.That(handler.Requests).HasSingleItem();
        await Assert.That(handler.Requests[0].Method).IsEqualTo("GET");
    }

    [Test]
    public async Task InvalidLocalSourceCannotReachForgejoUpload()
    {
        var content = Encoding.UTF8.GetBytes("candidate archive");
        var handler = new RecordingHandler(static (_, _) => Response(HttpStatusCode.NotFound));
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var configuration = ForgejoSourceConfiguration.Resolve(
                "https://forgejo.test/", Repository, tokenFile)!;
            await using var publisher = new ForgejoGenericPackagePublisher(
                configuration,
                new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan });
            var digest = Convert.ToHexStringLower(SHA256.HashData(content));

            await Assert.That(async () => await publisher.PublishAsync(
                    Repository,
                    "ci-terrascale.orchestrator",
                    digest,
                    "ci-job.tar.gz",
                    digest,
                    content.LongLength,
                    (destination, cancellationToken) =>
                        destination.WriteAsync(Encoding.UTF8.GetBytes("wrong-local-data"), cancellationToken).AsTask(),
                    static () => true))
                .Throws<InvalidDataException>();
            await Assert.That(handler.Requests).HasSingleItem();
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private static async Task<ForgejoGenericPackagePublicationReceipt> PublishAsync(
        RecordingHandler handler,
        byte[] content,
        Func<bool>? authorityStillValid = null)
    {
        var tokenFile = await CreateTokenFileAsync();
        try
        {
            var configuration = ForgejoSourceConfiguration.Resolve(
                "https://forgejo.test/",
                Repository,
                tokenFile)!;
            await using var publisher = new ForgejoGenericPackagePublisher(
                configuration,
                new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan });
            var digest = Convert.ToHexStringLower(SHA256.HashData(content));
            return await publisher.PublishAsync(
                Repository,
                "ci-terrascale.orchestrator",
                digest,
                "ci-job.tar.gz",
                digest,
                content.LongLength,
                (destination, cancellationToken) =>
                    destination.WriteAsync(content, cancellationToken).AsTask(),
                authorityStillValid ?? (() => true));
        }
        finally
        {
            File.Delete(tokenFile);
        }
    }

    private static async Task<string> CreateTokenFileAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"forgejo-package-{Guid.NewGuid():N}.token");
        await File.WriteAllTextAsync(path, Token, new UTF8Encoding(false));
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private static HttpResponseMessage Response(HttpStatusCode status) => new(status);

    private static HttpResponseMessage Package(byte[] content)
    {
        var response = Response(HttpStatusCode.OK);
        response.Content = new ByteArrayContent(content);
        response.Content.Headers.ContentType = new("application/octet-stream");
        return response;
    }

    private sealed class RecordingHandler(
        params Func<HttpRequestMessage, byte[], HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        private readonly Queue<Func<HttpRequestMessage, byte[], HttpResponseMessage>> remaining = new(responses);

        internal List<RequestRecord> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Requests.Add(new(
                request.Method.Method,
                request.RequestUri!.AbsolutePath,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                request.Content?.Headers.ContentType?.MediaType,
                body));
            return remaining.Dequeue()(request, body);
        }
    }

    private sealed record RequestRecord(
        string Method,
        string Path,
        string? AuthenticationScheme,
        string? AuthenticationParameter,
        string? ContentType,
        byte[] Body);
}
