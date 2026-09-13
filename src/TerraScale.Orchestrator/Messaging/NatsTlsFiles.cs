using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TerraScale.Orchestrator.Messaging;

public sealed record NatsTlsFiles(string CaFile, string CertificateFile, string KeyFile)
{
    public static NatsTlsFiles? Resolve(
        string? caFile,
        string? certificateFile,
        string? keyFile,
        string optionPrefix)
    {
        var supplied = new[] { caFile, certificateFile, keyFile }.Count(value => !string.IsNullOrWhiteSpace(value));
        if (supplied == 0) return null;
        if (supplied != 3)
        {
            throw new ArgumentException($"{optionPrefix} requires CA, certificate, and key files together.");
        }
        if (caFile is null || certificateFile is null || keyFile is null)
        {
            throw new ArgumentException($"{optionPrefix} requires non-empty CA, certificate, and key file paths.");
        }
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("NATS TLS credential files require Linux file permissions.");
        }

        var ca = ResolvePublic(caFile, $"{optionPrefix} CA");
        var certificate = ResolvePublic(certificateFile, $"{optionPrefix} certificate");
        var key = ResolvePrivate(keyFile, $"{optionPrefix} key");
        try
        {
            using var identity = X509Certificate2.CreateFromPemFile(certificate, key);
            using var authority = X509CertificateLoader.LoadCertificateFromFile(ca);
            if (!identity.HasPrivateKey || authority.Extensions.OfType<X509BasicConstraintsExtension>()
                    .SingleOrDefault()?.CertificateAuthority != true)
            {
                throw new ArgumentException($"{optionPrefix} files do not contain a usable identity and CA.");
            }
        }
        catch (CryptographicException exception)
        {
            throw new ArgumentException($"{optionPrefix} files are not valid matching PEM credentials.", exception);
        }
        return new NatsTlsFiles(ca, certificate, key);
    }

    internal bool SameIdentity(NatsTlsFiles other)
    {
        using var first = X509CertificateLoader.LoadCertificateFromFile(CertificateFile);
        using var second = X509CertificateLoader.LoadCertificateFromFile(other.CertificateFile);
        return first.PublicKey.ExportSubjectPublicKeyInfo().AsSpan()
            .SequenceEqual(second.PublicKey.ExportSubjectPublicKeyInfo());
    }

    internal bool HasSubjectPublicKeyInfo(byte[] subjectPublicKeyInfo)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(CertificateFile);
        return certificate.PublicKey.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(subjectPublicKeyInfo);
    }

    private static string ResolvePublic(string value, string optionName)
    {
        return NatsFileResolver.Resolve(value, optionName, 65_536, ownerPrivate: false);
    }

    private static string ResolvePrivate(string value, string optionName)
    {
        return NatsFileResolver.Resolve(value, optionName, 65_536, ownerPrivate: true);
    }
}
