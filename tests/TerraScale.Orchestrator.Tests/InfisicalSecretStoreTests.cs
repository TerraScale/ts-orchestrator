using System.Net;
using System.Runtime.Versioning;
using System.Text;
using TerraScale.Orchestrator.Security;

namespace TerraScale.Orchestrator.Tests;

[SupportedOSPlatform("linux")]
public sealed class InfisicalSecretStoreTests
{
    [Test]
    public async Task ConfigurationRequiresACompleteSecureUniversalAuthIdentity()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();

        var configuration = fixture.Configuration();

        await Assert.That(configuration!.Server).IsEqualTo(new Uri("http://127.0.0.1:8080/"));
        await Assert.That(configuration.ProjectId).IsEqualTo("project-1");
        await Assert.That(configuration.Environment).IsEqualTo("prod");
        await Assert.That(configuration.SecretPath).IsEqualTo("/orchestrator");
        await Assert.That(InfisicalConfiguration.Resolve(
                null, "project-1", "prod", null, fixture.ClientId, fixture.ClientSecret, " ")!
            .OrganizationSlug).IsNull();
        await Assert.That(() => InfisicalConfiguration.Resolve(
                null, "project-1", null, null, fixture.ClientId, fixture.ClientSecret))
            .Throws<ArgumentException>();
        await Assert.That(() => InfisicalConfiguration.Resolve(
                "http://infisical.example", "project-1", "prod", "/", fixture.ClientId, fixture.ClientSecret))
            .Throws<ArgumentException>();

        File.SetUnixFileMode(fixture.ClientSecret, UnixFileMode.UserRead | UnixFileMode.OtherRead);
        await Assert.That(() => fixture.Configuration()).Throws<ArgumentException>();
    }

    [Test]
    public async Task V4ClientAuthenticatesAndSupportsSecretCrudWithoutLeakingValues()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        var requests = new List<(HttpMethod Method, string Path, string Query, string? Authorization)>();
        using var handler = new Handler(request =>
        {
            requests.Add((
                request.Method,
                request.RequestUri!.AbsolutePath,
                request.RequestUri.Query,
                request.Headers.Authorization?.ToString()));
            if (request.RequestUri.AbsolutePath == "/api/v1/auth/universal-auth/login")
            {
                var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
                Require(body.Contains("client-id", StringComparison.Ordinal));
                Require(body.Contains("client-secret", StringComparison.Ordinal));
                return Json("{\"accessToken\":\"access-token\",\"expiresIn\":3600,\"accessTokenMaxTTL\":7200}");
            }
            Require(request.Headers.Authorization?.ToString() == "Bearer access-token");
            return (request.Method.Method, request.RequestUri.AbsolutePath) switch
            {
                ("GET", "/api/v4/secrets") => Json("""
                    {"secrets":[{"secretKey":"LOCAL","version":2,"secretPath":"/orchestrator"}],
                     "imports":[{"secretPath":"/imported","secrets":[
                       {"secretKey":"LOCAL","version":1},
                       {"secretKey":"IMPORTED","version":3}]}]}
                    """),
                ("GET", "/api/v4/secrets/API_KEY") => Json("""
                    {"secret":{"secretKey":"API_KEY","secretValue":"sentinel-secret-value","version":4,"secretPath":"/orchestrator"}}
                    """),
                ("POST", "/api/v4/secrets/NEW") => Secret("NEW", 1),
                ("PATCH", "/api/v4/secrets/NEW") => Secret("NEW", 2),
                ("DELETE", "/api/v4/secrets/NEW") => Secret("NEW", 2),
                ("GET", "/api/v4/secrets/DENIED") => Json(
                    "{\"message\":\"sentinel-secret-value\"}",
                    HttpStatusCode.Forbidden),
                ("GET", "/api/v4/secrets/BAD_PATH") => Json(
                    "{\"secret\":{\"secretKey\":\"BAD_PATH\",\"secretValue\":\"sentinel-secret-value\",\"version\":1,\"secretPath\":\"/bad\\npath\"}}"),
                _ => throw new InvalidOperationException("Unexpected Infisical request."),
            };
        });
        await using var store = InfisicalSecretStore.Create(fixture.Configuration()!, handler);

        var listed = await store.ListAsync();
        var fetched = await store.GetAsync("API_KEY");
        var created = await store.CreateAsync("NEW", "created-value");
        var updated = await store.UpdateAsync("NEW", "updated-value");
        var deleted = await store.DeleteAsync("NEW");
        var denied = await Assert.That(async () => await store.GetAsync("DENIED"))
            .Throws<InvalidOperationException>();
        var badPath = await Assert.That(async () => await store.GetAsync("BAD_PATH"))
            .Throws<InvalidDataException>();

        await Assert.That(listed.Select(value => value.Name).ToArray()).IsEquivalentTo(["LOCAL", "IMPORTED"]);
        await Assert.That(listed.Single(value => value.Name == "IMPORTED").Path).IsEqualTo("/imported");
        await Assert.That(fetched.Value).IsEqualTo("sentinel-secret-value");
        await Assert.That(fetched.ToString()).DoesNotContain("sentinel-secret-value");
        await Assert.That(created.Version).IsEqualTo(1);
        await Assert.That(updated.Version).IsEqualTo(2);
        await Assert.That(deleted.Version).IsEqualTo(2);
        await Assert.That(denied!.Message).DoesNotContain("sentinel-secret-value");
        await Assert.That(badPath!.Message).DoesNotContain("sentinel-secret-value");
        await Assert.That(requests.Count(request =>
            request.Path == "/api/v1/auth/universal-auth/login")).IsEqualTo(1);
        await Assert.That(requests.Single(request => request.Path == "/api/v4/secrets").Query)
            .Contains("viewSecretValue=false");
    }

    [Test]
    public async Task StartupSecretsMaterializeExistingFileSettingsOwnerPrivately()
    {
        if (!OperatingSystem.IsLinux()) return;
        using var fixture = new Fixture();
        using var handler = new Handler(request => request.RequestUri!.AbsolutePath switch
        {
            "/api/v1/auth/universal-auth/login" =>
                Json("{\"accessToken\":\"access-token\",\"expiresIn\":3600,\"accessTokenMaxTTL\":7200}"),
            "/api/v4/secrets" => Json("""
                {"secrets":[
                  {"secretKey":"TS_ORCH_CELL","secretValue":"fra","version":1,"secretPath":"/orchestrator"},
                  {"secretKey":"TS_ORCH_FORGEJO_API_TOKEN_FILE","secretValue":"private-token-value","version":1,"secretPath":"/orchestrator"}
                ],"imports":[]}
                """),
            _ => throw new InvalidOperationException("Unexpected Infisical request."),
        });
        await using var store = InfisicalSecretStore.Create(fixture.Configuration()!, handler);

        var environment = await InfisicalSecretEnvironment.LoadAsync(store, CancellationToken.None);
        var tokenFile = environment.GetValue("TS_ORCH_FORGEJO_API_TOKEN_FILE")!;

        await Assert.That(environment.GetValue("TS_ORCH_CELL")).IsEqualTo("fra");
        await Assert.That(tokenFile).IsNotEqualTo("private-token-value");
        await Assert.That(await File.ReadAllTextAsync(tokenFile)).IsEqualTo("private-token-value");
        await Assert.That(File.GetUnixFileMode(tokenFile))
            .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);

        environment.Dispose();
        await Assert.That(File.Exists(tokenFile)).IsFalse();
    }

    [Test]
    public async Task CliRequiresExplicitFilesAndExactDeleteConfirmation()
    {
        await Assert.That(InfisicalCli.Parse(["list"]).Action).IsEqualTo(InfisicalCliAction.List);
        await Assert.That(InfisicalCli.Parse(["get", "API_KEY", "--output", "/tmp/key"]).Action)
            .IsEqualTo(InfisicalCliAction.Get);
        await Assert.That(() => InfisicalCli.Parse(["delete", "API_KEY", "--confirm", "OTHER"]))
            .Throws<ArgumentException>();
        await Assert.That(() => InfisicalCli.Parse(["create", "API_KEY", "literal-value"]))
            .Throws<ArgumentException>();
    }

    private static HttpResponseMessage Secret(string name, int version) => Json(
        $"{{\"secret\":{{\"secretKey\":\"{name}\",\"version\":{version},\"secretPath\":\"/orchestrator\"}}}}");

    private static HttpResponseMessage Json(string value, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(value, Encoding.UTF8, "application/json")
    };

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Infisical request assertion failed.");
    }

    private sealed class Handler(Func<HttpRequestMessage, HttpResponseMessage> handle) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => Task.FromResult(handle(request));
    }

    private sealed class Fixture : IDisposable
    {
        internal Fixture()
        {
            Root = Path.Combine(Path.GetTempPath(), $"infisical-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
            ClientId = Path.Combine(Root, "client-id");
            ClientSecret = Path.Combine(Root, "client-secret");
            File.WriteAllText(ClientId, "client-id");
            File.WriteAllText(ClientSecret, "client-secret");
            File.SetUnixFileMode(ClientId, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            File.SetUnixFileMode(ClientSecret, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        internal string Root { get; }
        internal string ClientId { get; }
        internal string ClientSecret { get; }

        internal InfisicalConfiguration? Configuration() => InfisicalConfiguration.Resolve(
            "http://127.0.0.1:8080",
            "project-1",
            "prod",
            "/orchestrator",
            ClientId,
            ClientSecret);

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
