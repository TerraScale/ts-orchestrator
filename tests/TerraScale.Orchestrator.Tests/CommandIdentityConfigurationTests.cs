using System.Runtime.Versioning;
using System.Security.Cryptography;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class CommandIdentityConfigurationTests
{
    [Test]
    public async Task RunAndCheckOpenConfiguredSignerAndRotatingTrustBeforeConnecting()
    {
        if (!OperatingSystem.IsLinux()) return;
        var directory = Path.Combine(Path.GetTempPath(), $"ts-command-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var signing = WriteKey(directory, "signing");
            var previous = WriteKey(directory, "previous");
            var values = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["TS_ORCH_COMMAND_SIGNING_KEY_FILE"] = signing.Private,
                ["TS_ORCH_COMMAND_TRUST_KEY_FILES"] =
                    string.Join(Path.PathSeparator, signing.Public, previous.Public),
            };

            var options = OrchestratorOptions.Parse(
                ["check"],
                name => values.GetValueOrDefault(name));
            using var runtime = options.CommandIdentity!.Open();

            await Assert.That(options.CommandIdentity.SigningKeyFile).IsEqualTo(signing.Private);
            await Assert.That(options.CommandIdentity.TrustKeyFiles)
                .IsEquivalentTo([signing.Public, previous.Public]);
            await Assert.That(runtime.Signer).IsNotNull();
            await Assert.That(runtime.Verifier).IsNotNull();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task EmptyDuplicateAndOversizedTrustListsFailDuringOptionParsing()
    {
        var separator = Path.PathSeparator;
        var invalid = new[]
        {
            $"/trust/one{separator}",
            $"/trust/one{separator}/trust/one",
            string.Join(separator, Enumerable.Range(1, 5).Select(index => $"/trust/{index}")),
        };

        foreach (var value in invalid)
            await Assert.That(() => OrchestratorOptions.Parse(
                    ["run"],
                    name => name == "TS_ORCH_COMMAND_TRUST_KEY_FILES" ? value : null))
                .Throws<ArgumentException>();
    }

    [SupportedOSPlatform("linux")]
    private static KeyFiles WriteKey(string directory, string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePath = Path.Combine(directory, $"{name}-private.pem");
        var publicPath = Path.Combine(directory, $"{name}-public.pem");
        File.WriteAllText(privatePath, key.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(publicPath, key.ExportSubjectPublicKeyInfoPem());
        File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return new(privatePath, publicPath);
    }

    private sealed record KeyFiles(string Private, string Public);
}
