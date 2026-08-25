using System.Security.Cryptography;
using TerraScale.Orchestrator.Development;

namespace TerraScale.Orchestrator.Tests;

public sealed class DevelopmentCommandIdentityTests
{
    [Test]
    public async Task CreateWritesMatchingP256SigningAndTrustKeys()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-command-identity-{Guid.NewGuid():N}");
        try
        {
            var identity = DevelopmentCommandIdentity.Create(directory);
            using var signer = ECDsa.Create();
            using var verifier = ECDsa.Create();
            signer.ImportFromPem(await File.ReadAllTextAsync(identity.PrivateKeyFile));
            verifier.ImportFromPem(await File.ReadAllTextAsync(identity.PublicKeyFile));
            var payload = "development-command"u8.ToArray();
            var signature = signer.SignData(payload, HashAlgorithmName.SHA256);

            await Assert.That(verifier.KeySize).IsEqualTo(256);
            await Assert.That(verifier.VerifyData(payload, signature, HashAlgorithmName.SHA256)).IsTrue();
            if (!OperatingSystem.IsWindows())
            {
                await Assert.That(File.GetUnixFileMode(identity.PrivateKeyFile))
                    .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await Assert.That(File.GetUnixFileMode(identity.PublicKeyFile))
                    .IsEqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
