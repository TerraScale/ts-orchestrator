using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Tests;

public sealed class NatsFileResolutionTests
{
    [Test]
    public async Task NKeyResolutionRejectsSymlinkedFilesAndAncestors()
    {
        if (!OperatingSystem.IsLinux()) return;

        var directory = CreateTemporaryDirectory("nats-nkey-resolution");
        try
        {
            var target = Path.Combine(directory, "seed.nk");
            await File.WriteAllTextAsync(target, NATS.Client.Core.NKeys.CreateUserSeed());
            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var fileLink = Path.Combine(directory, "seed-link.nk");
            File.CreateSymbolicLink(fileLink, target);
            await Assert.That(() => NatsCredentialFile.Resolve(fileLink, "NKEY_FILE"))
                .Throws<ArgumentException>();

            var directoryLink = Path.Combine(directory, "directory-link");
            File.CreateSymbolicLink(directoryLink, directory);
            await Assert.That(() => NatsCredentialFile.Resolve(
                    Path.Combine(directoryLink, "seed.nk"), "NKEY_FILE"))
                .Throws<ArgumentException>();

            var actualDirectory = Path.Combine(directory, "directory");
            Directory.CreateDirectory(actualDirectory);
            await Assert.That(() => NatsCredentialFile.Resolve(actualDirectory, "NKEY_FILE"))
                .Throws<ArgumentException>();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task CredentialResolutionRejectsSymlinkedFiles()
    {
        if (!OperatingSystem.IsLinux()) return;

        var directory = CreateTemporaryDirectory("nats-credentials-resolution");
        try
        {
            var seed = NATS.Client.Core.NKeys.CreateUserSeed();
            var target = Path.Combine(directory, "user.creds");
            await File.WriteAllTextAsync(target, $"""
                -----BEGIN USER NKEY SEED-----
                {seed}
                ------END USER NKEY SEED------
                """);
            File.SetUnixFileMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var link = Path.Combine(directory, "user-link.creds");
            File.CreateSymbolicLink(link, target);
            await Assert.That(() => NatsAuthenticationFiles.FromCredentialsFile(link, "TEST_NATS"))
                .Throws<ArgumentException>();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Test]
    public async Task TlsResolutionRejectsSymlinkedFilesAndUnsafePublicPermissions()
    {
        if (!OperatingSystem.IsLinux()) return;

        var directory = CreateTemporaryDirectory("nats-tls-resolution");
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request = new CertificateRequest("CN=nats-test", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var ca = Path.Combine(directory, "ca.pem");
            var certificatePath = Path.Combine(directory, "certificate.pem");
            var keyPath = Path.Combine(directory, "key.pem");
            await File.WriteAllTextAsync(ca, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(certificatePath, certificate.ExportCertificatePem());
            await File.WriteAllTextAsync(keyPath, key.ExportPkcs8PrivateKeyPem());
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            var certificateLink = Path.Combine(directory, "certificate-link.pem");
            File.CreateSymbolicLink(certificateLink, certificatePath);
            await Assert.That(() => NatsTlsFiles.Resolve(ca, certificateLink, keyPath, "TEST_NATS_TLS"))
                .Throws<ArgumentException>();

            File.SetUnixFileMode(ca, UnixFileMode.UserRead | UnixFileMode.OtherWrite);
            await Assert.That(() => NatsTlsFiles.Resolve(ca, certificatePath, keyPath, "TEST_NATS_TLS"))
                .Throws<ArgumentException>();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTemporaryDirectory(string name)
    {
        var directory = Path.Combine(Path.GetTempPath(), $"ts-orch-{name}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }
}
