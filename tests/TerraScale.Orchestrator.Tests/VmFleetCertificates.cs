using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TerraScale.Orchestrator.Tests;

/// <summary>Ephemeral identities for one isolated VM region, generated afresh for every run.</summary>
internal static class VmFleetCertificates
{
    internal static void Create(string directory, int subnet)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("The VM fleet requires Linux.");
        Directory.CreateDirectory(directory);
        using var authorityKey = RSA.Create(2048);
        var authorityRequest = new CertificateRequest(
            "CN=vm-fleet-ca", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        authorityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var authority = authorityRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
        File.WriteAllText(Path.Combine(directory, "ca.crt"), authority.ExportCertificatePem());

        string[] members = ["vm-node-1", "as-node-1", "as-node-2", "observer"];
        for (var index = 0; index < members.Length; index++)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(
                $"CN={members[index]}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") }, true));
            var names = new SubjectAlternativeNameBuilder();
            names.AddIpAddress(IPAddress.Parse($"10.{subnet}.0.{10 + index}"));
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.Create(authority,
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1),
                RandomNumberGenerator.GetBytes(16));
            File.WriteAllText(Path.Combine(directory, members[index] + ".crt"), certificate.ExportCertificatePem());
            var keyPath = Path.Combine(directory, members[index] + ".key");
            using var keyFile = new FileStream(keyPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            using var writer = new StreamWriter(keyFile);
            writer.Write(key.ExportPkcs8PrivateKeyPem());
        }
    }
}
