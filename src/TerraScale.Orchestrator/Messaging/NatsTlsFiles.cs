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
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("NATS TLS credential files require Linux file permissions.");
        }

        var ca = ResolvePublic(caFile!, $"{optionPrefix} CA");
        var certificate = ResolvePublic(certificateFile!, $"{optionPrefix} certificate");
        var key = ResolvePrivate(keyFile!, $"{optionPrefix} key");
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

    private static string ResolvePublic(string value, string optionName)
    {
        var path = Path.GetFullPath(value);
        var file = new FileInfo(path);
        if (!file.Exists || file.Length is < 1 or > 65_536)
        {
            throw new ArgumentException($"{optionName} must identify a bounded existing PEM file.");
        }
        return path;
    }

    private static string ResolvePrivate(string value, string optionName)
    {
        if (!OperatingSystem.IsLinux())
        {
            throw new PlatformNotSupportedException("NATS TLS credential files require Linux file permissions.");
        }
        var path = ResolvePublic(value, optionName);
        var mode = File.GetUnixFileMode(path);
        if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                     UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
        {
            throw new ArgumentException($"{optionName} must be private to the current user.");
        }
        return path;
    }
}
