using System.Net;
using TUnit.Assertions;
using TUnit.Core;
using TerraScale.Orchestrator.ControlPlane.EdgeRouting;
using static TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting.FakeCloudflareKvTransport;

namespace TerraScale.Orchestrator.ControlPlane.Tests.EdgeRouting;

public sealed class CloudflareKvClientTests
{
    private static CloudflareKvClient Client(FakeCloudflareKvTransport transport) =>
        new("token", AccountId, new HttpClient(transport));

    [Test]
    public async Task ResolvesNamespaceIdByExactTitleAndReturnsNullForUnknownTitles()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);

        await Assert.That(await client.ResolveNamespaceIdAsync("REGIONS")).IsEqualTo(RegionsNamespaceId);
        await Assert.That(await client.ResolveNamespaceIdAsync("PLACEMENT")).IsEqualTo(PlacementNamespaceId);
        await Assert.That(await client.ResolveNamespaceIdAsync("absent")).IsNull();
    }

    [Test]
    public async Task GetReturnsNullForMissingKeysAndTheStoredValueOtherwise()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);
        transport.Seed(PlacementNamespaceId, "db:orders", """{"v":2}""");

        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:orders")).IsEqualTo("""{"v":2}""");
        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:absent")).IsNull();
    }

    [Test]
    public async Task PutStoresTheExactValueAndBulkOperationsRoundTrip()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);

        await client.PutKeyValueAsync(RegionsNamespaceId, "regions", """{"v":1}""");
        await client.PutKeysInBulkAsync(PlacementNamespaceId,
        [
            new KeyValuePair<string, string>("db:alpha", """{"v":2,"rev":1}"""),
            new KeyValuePair<string, string>("db:beta", """{"v":2,"rev":1}"""),
        ]);
        await Assert.That(await client.GetKeyValueAsync(RegionsNamespaceId, "regions")).IsEqualTo("""{"v":1}""");
        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:alpha")).IsEqualTo("""{"v":2,"rev":1}""");

        await client.DeleteKeysInBulkAsync(PlacementNamespaceId, ["db:alpha", "db:beta"]);
        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:alpha")).IsNull();
        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:beta")).IsNull();
    }

    [Test]
    public async Task BulkOperationsRejectOutOfBoundsKeyCounts()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);
        var tooMany = Enumerable.Range(0, CloudflareKvClient.MaximumBulkKeys + 1)
            .Select(index => new KeyValuePair<string, string>($"db-{index}", "{}"))
            .ToArray();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.PutKeysInBulkAsync(PlacementNamespaceId, tooMany));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.DeleteKeysInBulkAsync(PlacementNamespaceId, []));
    }

    [Test]
    public async Task EnvelopeFailuresRaiseTypedErrorsWithStatusAndErrors()
    {
        using var transport = new FakeCloudflareKvTransport();
        transport.Fail("PUT", "/values/regions", HttpStatusCode.BadRequest);
        using var client = Client(transport);

        var failure = (await Assert.ThrowsAsync<CloudflareKvException>(
            () => client.PutKeyValueAsync(RegionsNamespaceId, "regions", "{}")))!;
        await Assert.That(failure.Status).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(failure.Errors.Single().Code).IsEqualTo(10000);
        await Assert.That(failure.Errors.Single().Message).IsEqualTo("scripted failure");
    }

    [Test]
    public async Task NamespaceNotFoundClass404RaisesTheTypedException()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);

        var failure = (await Assert.ThrowsAsync<CloudflareKvNamespaceNotFoundException>(
            () => client.GetKeyValueAsync("ns-gone", "db:orders")))!;
        await Assert.That(failure.Status).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(failure.Errors.Single().Message).Contains("namespace not found");
    }

    [Test]
    public async Task PlainKeyAbsent404ReturnsNullWithoutAnyNamespaceResolution()
    {
        using var transport = new FakeCloudflareKvTransport();
        using var client = Client(transport);

        await Assert.That(await client.GetKeyValueAsync(PlacementNamespaceId, "db:absent")).IsNull();
        await Assert.That(transport.Calls.Any(call => call == "GET namespaces")).IsFalse();
    }

    [Test]
    public async Task StalledBodyReadFailsWithATimeoutWithinTheCallBound()
    {
        using var client = new CloudflareKvClient(
            "token",
            AccountId,
            new HttpClient(new StalledBodyTransport()),
            callTimeout: TimeSpan.FromMilliseconds(100));
        using var wall = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await Assert.ThrowsAsync<TimeoutException>(
            () => client.GetKeyValueAsync(RegionsNamespaceId, "regions", wall.Token));
    }

    /// <summary>
    /// Serves headers immediately but a body stream that never yields a byte; the read only
    /// completes when the caller's cancellation token fires, exactly like a stalled socket.
    /// </summary>
    private sealed class StalledBodyTransport : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new StalledStream()),
            });

        private sealed class StalledStream : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
                Stall(cancellationToken);

            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

            private static async ValueTask<int> Stall(CancellationToken cancellationToken)
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return 0;
            }
        }
    }
}
