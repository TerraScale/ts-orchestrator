using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Oci.Common;
using Oci.Common.Auth;
using Oci.CoreService;
using Oci.SecretsService;
using Oci.WorkrequestsService;
using TerraScale.Orchestrator.ControlPlane.Providers;

namespace TerraScale.Orchestrator.Tests;

public sealed class OciSdkEndpointTests
{
    [Test]
    [Arguments("compute", "/20160918/instances/synthetic")]
    [Arguments("network", "/20160918/vnics/synthetic")]
    [Arguments("storage", "/20160918/volumes/synthetic")]
    [Arguments("work-request", "/20160918/workRequests/synthetic")]
    [Arguments("vault", "/20190301/secretbundles/synthetic")]
    public async Task Explicit_endpoint_overrides_the_credential_region_template_on_the_wire(string service, string path)
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = Directory.CreateTempSubdirectory("ts-oci-endpoint-");
        File.SetUnixFileMode(root.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var key = RSA.Create(2048);
            var keyFile = Path.Combine(root.FullName, "synthetic.pem");
            await File.WriteAllTextAsync(keyFile, key.ExportRSAPrivateKeyPem());
            File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var configFile = Path.Combine(root.FullName, "synthetic-config");
            await File.WriteAllTextAsync(configFile, $"""
                [DEFAULT]
                user=ocid1.user.oc1..synthetic
                tenancy=ocid1.tenancy.oc1..synthetic
                fingerprint=00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
                region=sa-saopaulo-1
                key_file={keyFile}
                """);
            var authentication = new ConfigFileAuthenticationDetailsProvider(configFile, "DEFAULT");
            var configuration = new ClientConfiguration { TimeoutMillis = 5000 };
            var endpoint = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
            using RegionalClientBase client = service switch
            {
                "compute" => new ComputeClient(authentication, configuration, endpoint),
                "network" => new VirtualNetworkClient(authentication, configuration, endpoint),
                "storage" => new BlockstorageClient(authentication, configuration, endpoint),
                "work-request" => new WorkRequestClient(authentication, configuration, endpoint),
                _ => new SecretsClient(authentication, configuration, endpoint)
            };
            // Keep a regression local: substitute a closed loopback port for the
            // credential-region template that would otherwise reach real OCI.
            client.SetRealmSpecificEndpointTemplate("http://127.0.0.1:1/{ignored}");
            OciSdkEndpoint.Pin(client);
            var server = ServeAsync(listener, timeout.Token);
            await (client switch
            {
                ComputeClient compute => (Task)compute.GetInstance(new() { InstanceId = "synthetic" }, cancellationToken: timeout.Token),
                VirtualNetworkClient network => network.GetVnic(new() { VnicId = "synthetic" }, cancellationToken: timeout.Token),
                BlockstorageClient storage => storage.GetVolume(new() { VolumeId = "synthetic" }, cancellationToken: timeout.Token),
                WorkRequestClient requests => requests.GetWorkRequest(new() { WorkRequestId = "synthetic" }, cancellationToken: timeout.Token),
                SecretsClient vault => vault.GetSecretBundle(new() { SecretId = "synthetic" }, cancellationToken: timeout.Token),
                _ => throw new InvalidOperationException("Unexpected test SDK client.")
            });
            var headers = await server.WaitAsync(timeout.Token);
            await Assert.That(headers).Contains($"GET {path} HTTP/1.1");
            await Assert.That(headers.ToLowerInvariant()).Contains("authorization: signature ");
        }
        finally { root.Delete(recursive: true); }
    }

    private static async Task<string> ServeAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        using var socket = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        var headers = new StringBuilder();
        while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
        {
            headers.AppendLine(line);
            if (headers.Length > 16 * 1024) throw new InvalidDataException("Oversized local SDK test request.");
        }
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"), cancellationToken);
        return headers.ToString();
    }
}
