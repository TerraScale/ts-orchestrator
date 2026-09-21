using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Oci.SecretsService.Models;
using Oci.SecretsService.Requests;
using Oci.SecretsService.Responses;
using Oci.Common;
using Oci.Common.Auth;
using Oci.SecretsService;
using TerraScale.Orchestrator.Bootstrap.Secrets;

namespace TerraScale.Orchestrator.Tests;

public sealed class OciBootstrapSecretsTests
{
    private const string SecretId = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaexample";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("test credential material");
    private static readonly string Digest = Convert.ToHexStringLower(SHA256.HashData(Secret));
    private const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    [Test]
    public async Task Real_sdk_sends_signed_pinned_version_request_and_decodes_the_wire_response()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var key = RSA.Create(2048);
            var keyFile = Path.Combine(root.FullName, "synthetic.pem");
            await File.WriteAllTextAsync(keyFile, key.ExportRSAPrivateKeyPem());
            File.SetUnixFileMode(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var configuration = Path.Combine(root.FullName, "oci-config");
            await File.WriteAllTextAsync(configuration, $"""
                [DEFAULT]
                user=ocid1.user.oc1..synthetic
                tenancy=ocid1.tenancy.oc1..synthetic
                fingerprint=00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
                region=sa-saopaulo-1
                key_file={keyFile}
                """);
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var server = ServeSecretAsync(listener, timeout.Token);
            using var client = new SecretsClient(new ConfigFileAuthenticationDetailsProvider(configuration, "DEFAULT"),
                new ClientConfiguration { TimeoutMillis = 5000 }, $"http://127.0.0.1:{port}");
            using var source = new OciVaultSecretSource((request, token) => client.GetSecretBundle(request, cancellationToken: token));
            var bytes = await source.ReadAsync(new("nats.nk", SecretId, 7, Digest), timeout.Token);
            var requestText = await server.WaitAsync(timeout.Token);
            await Assert.That(requestText).Contains($"GET /20190301/secretbundles/{SecretId}?versionNumber=7 HTTP/1.1");
            await Assert.That(requestText.ToLowerInvariant()).Contains("authorization: signature ");
            await Assert.That(bytes).IsEquivalentTo(Secret);
        }
        finally { root.Delete(recursive: true); }
    }

    private static async Task<string> ServeSecretAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        using var socket = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        var request = new StringBuilder();
        while (await reader.ReadLineAsync(cancellationToken) is { Length: > 0 } line)
        {
            request.AppendLine(line);
            if (request.Length > 16 * 1024) throw new InvalidDataException("Oversized local SDK test request.");
        }
        var body = JsonSerializer.SerializeToUtf8Bytes(new
        {
            secretId = SecretId,
            versionNumber = 7,
            secretBundleContent = new { contentType = "BASE64", content = Convert.ToBase64String(Secret) }
        });
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n"), cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        return request.ToString();
    }

    [Test]
    public async Task Sdk_request_pins_the_version_and_checks_response_identity()
    {
        GetSecretBundleRequest? request = null;
        using var source = new OciVaultSecretSource((value, _) =>
        {
            request = value;
            return Task.FromResult(Response(SecretId, 7, Convert.ToBase64String(Secret)));
        });
        var bytes = await source.ReadAsync(new("nats.nk", SecretId, 7, Digest), CancellationToken.None);
        await Assert.That(request!.VersionNumber).IsEqualTo(7);
        await Assert.That(request.SecretId).IsEqualTo(SecretId);
        await Assert.That(bytes).IsEquivalentTo(Secret);
    }

    [Test]
    [Arguments("wrong-id", 7, "dGVzdA==")]
    [Arguments(SecretId, 8, "dGVzdA==")]
    [Arguments(SecretId, 7, "not base64")]
    [Arguments(SecretId, 7, "")]
    public async Task Sdk_response_rejects_wrong_version_identity_or_encoding(string id, long version, string content)
    {
        using var source = new OciVaultSecretSource((_, _) => Task.FromResult(Response(id, version, content)));
        await Assert.That(async () => { _ = await source.ReadAsync(new("nats.nk", SecretId, 7, Digest), CancellationToken.None); })
            .Throws<InvalidDataException>();
    }

    [Test]
    [Arguments("../escape")]
    [Arguments("/absolute")]
    [Arguments("a/b")]
    [Arguments(".")]
    [Arguments("nats key")]
    public async Task Manifest_rejects_paths_outside_the_bundle(string name)
    {
        await Assert.That(() => ParseManifest(new OciSecretFile(name, SecretId, 7, Digest))).Throws<InvalidDataException>();
    }

    [Test]
    public async Task Manifest_rejects_latest_duplicates_and_foreign_region_references()
    {
        await Assert.That(() => ParseManifest(new OciSecretFile("nats.nk", SecretId, 0, Digest))).Throws<InvalidDataException>();
        await Assert.That(() => ParseManifest(new OciSecretFile("nats.nk", SecretId.Replace("sa-saopaulo-1", "us-sanjose-1"), 7, Digest)))
            .Throws<InvalidDataException>();
        await Assert.That(() => ParseManifest(new OciSecretFile("nats.nk", SecretId, 7, Digest), new("nats.nk", SecretId, 8, Digest)))
            .Throws<InvalidDataException>();
        await Assert.That(() => OciSecretManifest.Parse(Encoding.UTF8.GetBytes(
            """{"schemaVersion":1,"schemaVersion":2,"region":"GRU","files":[]}"""))).Throws<JsonException>();
    }

    [Test]
    public async Task Cli_installs_private_verified_bundle_and_restart_is_idempotent()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        try
        {
            var arguments = await WriteInputs(root.FullName);
            var source = new Source();
            using var output = new StringWriter();
            using var error = new StringWriter();
            var result = await OciBootstrapSecretsCli.ExecuteAsync(arguments, CancellationToken.None,
                _ => source, output, error);
            var installed = Path.Combine(root.FullName, "bundle", "nats.nk");
            await Assert.That(result).IsEqualTo(0);
            await Assert.That(await File.ReadAllBytesAsync(installed)).IsEquivalentTo(Secret);
            await Assert.That(File.GetUnixFileMode(installed)).IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            await Assert.That(File.GetUnixFileMode(Path.GetDirectoryName(installed)!)).IsEqualTo(PrivateDirectory);
            await Assert.That(source.LastBytes!.All(value => value == 0)).IsTrue();
            await Assert.That(source.Disposed).IsTrue();
            result = await OciBootstrapSecretsCli.ExecuteAsync(arguments, CancellationToken.None,
                _ => throw new InvalidOperationException("Restart must verify the installed bundle before consulting Vault."), output, error);
            await Assert.That(result).IsEqualTo(0);
            await Assert.That(output.ToString()).DoesNotContain(Encoding.UTF8.GetString(Secret));
            await Assert.That(error.ToString()).IsEqualTo(string.Empty);
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Failure_never_publishes_partial_credentials_or_logs_secret_errors(bool wrongDigest)
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        try
        {
            var args = await WriteInputs(root.FullName, twoFiles: true);
            var source = new Source { FailSecond = !wrongDigest, WrongSecondDigest = wrongDigest };
            using var error = new StringWriter();
            var code = await OciBootstrapSecretsCli.ExecuteAsync(args, CancellationToken.None,
                _ => source, TextWriter.Null, error);
            await Assert.That(code).IsEqualTo(1);
            await Assert.That(Directory.Exists(Path.Combine(root.FullName, "bundle"))).IsFalse();
            await Assert.That(Directory.GetDirectories(root.FullName, ".oci-secrets-*").Length).IsEqualTo(0);
            await Assert.That(source.LastBytes!.All(value => value == 0)).IsTrue();
            await Assert.That(error.ToString()).DoesNotContain(Encoding.UTF8.GetString(Secret));
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    public async Task Existing_modified_or_foreign_bundle_is_not_overwritten()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        try
        {
            var args = await WriteInputs(root.FullName);
            var output = Path.Combine(root.FullName, "bundle");
            Directory.CreateDirectory(output, PrivateDirectory);
            var path = Path.Combine(output, "nats.nk");
            await File.WriteAllTextAsync(path, "foreign credentials");
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            var code = await OciBootstrapSecretsCli.ExecuteAsync(args, CancellationToken.None,
                _ => throw new InvalidOperationException("Must not fetch when existing material is invalid."),
                TextWriter.Null, TextWriter.Null);
            await Assert.That(code).IsEqualTo(1);
            await Assert.That(await File.ReadAllTextAsync(path)).IsEqualTo("foreign credentials");
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    public async Task Unsupported_region_bad_arguments_permissions_and_links_fail_before_authentication()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        try
        {
            var args = await WriteInputs(root.FullName);
            var manifestPath = args[1];
            var manifest = await File.ReadAllTextAsync(manifestPath);
            await File.WriteAllTextAsync(manifestPath, manifest.Replace("GRU", "SFO").Replace("sa-saopaulo-1", "us-sanjose-1"));
            var factories = 0;
            IOciVaultSecretSource Factory(string _) { factories++; return new Source(); }
            await Assert.That(await OciBootstrapSecretsCli.ExecuteAsync(args, CancellationToken.None, Factory, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
            await File.WriteAllTextAsync(manifestPath, manifest);
            await Assert.That(await OciBootstrapSecretsCli.ExecuteAsync([.. args, "extra"], CancellationToken.None, Factory, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
            var link = Path.Combine(root.FullName, "linked");
            Directory.CreateSymbolicLink(link, root.FullName);
            args[5] = Path.Combine(link, "bundle");
            await Assert.That(await OciBootstrapSecretsCli.ExecuteAsync(args, CancellationToken.None, Factory, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
            args[5] = Path.Combine(root.FullName, "bundle");
            File.SetUnixFileMode(root.FullName, PrivateDirectory | UnixFileMode.GroupRead);
            await Assert.That(await OciBootstrapSecretsCli.ExecuteAsync(args, CancellationToken.None, Factory, TextWriter.Null, TextWriter.Null)).IsEqualTo(1);
            await Assert.That(factories).IsEqualTo(0);
        }
        finally { root.Delete(recursive: true); }
    }

    [Test]
    public async Task Cancelled_installation_does_not_fetch_or_publish()
    {
        if (!OperatingSystem.IsLinux()) return;
        var root = PrivateRoot();
        try
        {
            var args = await WriteInputs(root.FullName);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            var calls = 0;
            var code = await OciBootstrapSecretsCli.ExecuteAsync(args, cancelled.Token,
                _ => { calls++; return new Source(); }, TextWriter.Null, TextWriter.Null);
            await Assert.That(code).IsEqualTo(1);
            await Assert.That(calls).IsEqualTo(0);
            await Assert.That(Directory.Exists(Path.Combine(root.FullName, "bundle"))).IsFalse();
        }
        finally { root.Delete(recursive: true); }
    }

    private static OciSecretManifest ParseManifest(params OciSecretFile[] files) =>
        OciSecretManifest.Parse(JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, region = "GRU", files },
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));

    private static GetSecretBundleResponse Response(string id, long version, string content) => new()
    {
        SecretBundle = new SecretBundle
        {
            SecretId = id,
            VersionNumber = version,
            SecretBundleContent = new Base64SecretBundleContentDetails { Content = content }
        }
    };

    private static DirectoryInfo PrivateRoot()
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var root = Directory.CreateTempSubdirectory("ts-orch-vault-");
        File.SetUnixFileMode(root.FullName, PrivateDirectory);
        return root;
    }

    private static async Task<string[]> WriteInputs(string root, bool twoFiles = false)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException();
        var files = new List<OciSecretFile> { new("nats.nk", SecretId, 7, Digest) };
        if (twoFiles) files.Add(new("client.key", SecretId, 7, Digest));
        var path = Path.Combine(root, "manifest.json");
        await File.WriteAllBytesAsync(path, JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, region = "GRU", files },
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var intent = Path.Combine(root, "intent.json");
        await File.WriteAllTextAsync(intent, """
            {"schemaVersion":1,"generation":1,"bootstrapRegion":"GRU","regions":[{"cell":"GRU","ociRegion":"sa-saopaulo-1"}]}
            """);
        File.SetUnixFileMode(intent, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return ["--manifest", path, "--region-intent", intent, "--output", Path.Combine(root, "bundle")];
    }

    private sealed class Source : IOciVaultSecretSource
    {
        internal bool FailSecond { get; init; }
        internal bool WrongSecondDigest { get; init; }
        internal bool Disposed { get; private set; }
        internal byte[]? LastBytes { get; private set; }
        private int reads;

        public Task<byte[]> ReadAsync(OciSecretFile file, CancellationToken cancellationToken)
        {
            reads++;
            if (reads == 2 && FailSecond) throw new IOException(Encoding.UTF8.GetString(Secret));
            LastBytes = reads == 2 && WrongSecondDigest ? [1, 2, 3] : [.. Secret];
            return Task.FromResult(LastBytes);
        }

        public void Dispose() => Disposed = true;
    }
}
