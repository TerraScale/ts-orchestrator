using System.Net;
using System.Net.Sockets;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsRuntimeSecurityTests
{
    [Test]
    public async Task AnonymousProbeReportsTransportFailureInsteadOfTreatingItAsDenial()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        var exception = await Assert.That(async () =>
                await NatsRuntime.VerifyAnonymousDeniedAsync(
                    $"nats://127.0.0.1:{port}",
                    tls: null,
                    CancellationToken.None))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("authentication probe failed");
        await Assert.That(exception.Message).DoesNotContain("accepted an anonymous client");
    }
}
