using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class ForgejoWebhookServerTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Delivery = "f6266f16-1bf3-46a5-9ea4-602e06ead473";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");

    [Test]
    public async Task ConfigurationRequiresCompletePrivateAndSecureBinding()
    {
        var secretFile = await CreateSecretFileAsync();
        try
        {
            var local = ForgejoWebhookConfiguration.Resolve(
                "http://127.0.0.1:8080/hooks/forgejo/",
                Repository,
                secretFile);
            var secure = ForgejoWebhookConfiguration.Resolve(
                "https://webhooks.internal.example/hooks/forgejo/",
                Repository,
                secretFile);

            await Assert.That(local).IsNotNull();
            await Assert.That(secure).IsNotNull();
            await Assert.That(() => ForgejoWebhookConfiguration.Resolve(
                    "http://192.0.2.1:8080/hooks/forgejo/", Repository, secretFile))
                .Throws<ArgumentException>();
            await Assert.That(() => ForgejoWebhookConfiguration.Resolve(
                    "http://127.0.0.1:8080/hooks/forgejo/", Repository, null))
                .Throws<ArgumentException>();

            File.SetUnixFileMode(secretFile, UnixFileMode.UserRead | UnixFileMode.OtherRead);
            await Assert.That(() => ForgejoWebhookConfiguration.Resolve(
                    "http://127.0.0.1:8080/hooks/forgejo/", Repository, secretFile))
                .Throws<ArgumentException>();
        }
        finally
        {
            File.Delete(secretFile);
        }
    }

    [Test]
    public async Task SignedEventReturnsAcceptedOnlyAfterDurableJournalCommit()
    {
        var secretFile = await CreateSecretFileAsync();
        try
        {
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var started = StartServer(secretFile, new ForgejoWebhookJournal(ledger));
            await using var server = started.Server;
            var configuration = started.Configuration;
            using var client = Client();
            var payload = PushPayload();

            using var accepted = await client.SendAsync(Request(configuration, payload, Signature(payload)));
            using var duplicate = await client.SendAsync(Request(configuration, payload, Signature(payload)));

            await Assert.That(accepted.StatusCode).IsEqualTo(HttpStatusCode.Accepted);
            await Assert.That(duplicate.StatusCode).IsEqualTo(HttpStatusCode.Accepted);
            await Assert.That(ledger.Documents.Count()).IsEqualTo(2);
            await Assert.That(ledger.Documents.All(document => document.State == ForgejoWebhookJournalState.Accepted)).IsTrue();
        }
        finally
        {
            File.Delete(secretFile);
        }
    }

    [Test]
    public async Task RunOptionsRejectWebhookWithoutGlobalAuthority()
    {
        var secretFile = await CreateSecretFileAsync();
        try
        {
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_FORGEJO_LISTEN_PREFIX"] = "http://127.0.0.1:8080/hooks/forgejo/",
                ["TS_ORCH_FORGEJO_REPOSITORY"] = Repository,
                ["TS_ORCH_FORGEJO_SECRET_FILE"] = secretFile,
            };

            var configuration = ForgejoWebhookConfiguration.Resolve(
                values["TS_ORCH_FORGEJO_LISTEN_PREFIX"],
                values["TS_ORCH_FORGEJO_REPOSITORY"],
                values["TS_ORCH_FORGEJO_SECRET_FILE"]);
            var catalog = OrchestratorOptions.Parse(
                ["catalog"],
                name => name == "TS_ORCH_FORGEJO_LISTEN_PREFIX" ? values[name] : null);

            await Assert.That(configuration!.Repository).IsEqualTo(Repository);
            await Assert.That(() => OrchestratorOptions.Parse(["run"], values.GetValueOrDefault))
                .Throws<ArgumentException>();
            await Assert.That(catalog.ForgejoWebhook).IsNull();
        }
        finally
        {
            File.Delete(secretFile);
        }
    }

    [Test]
    public async Task InvalidSignatureAndJournalFailureNeverReturnSuccess()
    {
        var secretFile = await CreateSecretFileAsync();
        try
        {
            var ledger = new ForgejoWebhookJournalTests.TestLedger(failOnMutation: 1);
            var started = StartServer(secretFile, new ForgejoWebhookJournal(ledger));
            await using var server = started.Server;
            var configuration = started.Configuration;
            using var client = Client();
            var payload = PushPayload();

            using var invalid = await client.SendAsync(Request(configuration, payload, new string('0', 64)));
            using var unavailable = await client.SendAsync(Request(configuration, payload, Signature(payload)));

            await Assert.That(invalid.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
            await Assert.That(unavailable.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
            await Assert.That(ledger.Documents).IsEmpty();
        }
        finally
        {
            File.Delete(secretFile);
        }
    }

    [Test]
    public async Task MethodAndBodyBoundsAreRejectedBeforeJournalMutation()
    {
        var secretFile = await CreateSecretFileAsync();
        try
        {
            var ledger = new ForgejoWebhookJournalTests.TestLedger();
            var started = StartServer(secretFile, new ForgejoWebhookJournal(ledger));
            await using var server = started.Server;
            var configuration = started.Configuration;
            using var client = Client();
            using var get = await client.GetAsync(configuration.ListenPrefix);
            var oversizedStatus = await OversizedStatusAsync(configuration);

            await Assert.That(get.StatusCode).IsEqualTo(HttpStatusCode.MethodNotAllowed);
            await Assert.That(oversizedStatus).IsEqualTo((int)HttpStatusCode.RequestEntityTooLarge);
            await Assert.That(ledger.Documents).IsEmpty();
        }
        finally
        {
            File.Delete(secretFile);
        }
    }

    private static (ForgejoWebhookConfiguration Configuration, ForgejoWebhookServer Server) StartServer(
        string secretFile,
        ForgejoWebhookJournal journal)
    {
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var configuration = Configuration(secretFile);
            try
            {
                return (configuration, ForgejoWebhookServer.Start(configuration, journal));
            }
            catch (HttpListenerException exception) when (IsAddressInUse(exception))
            {
                // FreePort() cannot reserve a port for HttpListener. Select a new one if another
                // test process claims the probe result before the server binds it.
            }
        }

        throw new InvalidOperationException("Unable to claim a loopback port for the Forgejo webhook test server.");
    }

    private static ForgejoWebhookConfiguration Configuration(string secretFile) =>
        ForgejoWebhookConfiguration.Resolve(
            $"http://127.0.0.1:{FreePort()}/hooks/forgejo/",
            Repository,
            secretFile)!;

    private static bool IsAddressInUse(HttpListenerException exception) =>
        exception.ErrorCode == (int)SocketError.AddressAlreadyInUse;

    private static HttpClient Client() => new() { Timeout = TimeSpan.FromSeconds(5) };

    private static HttpRequestMessage Request(
        ForgejoWebhookConfiguration configuration,
        byte[] payload,
        string signature)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, configuration.ListenPrefix)
        {
            Content = new ByteArrayContent(payload)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        request.Headers.Add("X-Forgejo-Signature", signature);
        request.Headers.Add("X-Forgejo-Delivery", Delivery);
        request.Headers.Add("X-Forgejo-Event", "push");
        return request;
    }

    private static byte[] PushPayload() => Encoding.UTF8.GetBytes("""
        {"ref":"refs/heads/develop","before":"affe000000000000000000000000000000000001","after":"bffeb74224043ba2feb48d137756c8a9331c449a","repository":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
        """);

    private static string Signature(byte[] payload) => Convert.ToHexStringLower(HMACSHA256.HashData(Secret, payload));

    private static async Task<int> OversizedStatusAsync(ForgejoWebhookConfiguration configuration)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, configuration.ListenPrefix.Port);
        await using var stream = client.GetStream();
        var request = Encoding.ASCII.GetBytes(
            $"POST {configuration.ListenPrefix.AbsolutePath} HTTP/1.1\r\n" +
            $"Host: 127.0.0.1:{configuration.ListenPrefix.Port}\r\n" +
            "Content-Type: application/json\r\n" +
            $"Content-Length: {ForgejoWebhookVerifier.MaximumPayloadBytes + 1}\r\n" +
            "Connection: close\r\n\r\n");
        await stream.WriteAsync(request);
        using var reader = new StreamReader(stream, Encoding.ASCII);
        var statusLine = await reader.ReadLineAsync()
            ?? throw new InvalidOperationException("The webhook server returned no HTTP status line.");
        return int.Parse(statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1],
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string> CreateSecretFileAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"forgejo-webhook-{Guid.NewGuid():N}.secret");
        await File.WriteAllBytesAsync(path, Secret);
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return path;
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
