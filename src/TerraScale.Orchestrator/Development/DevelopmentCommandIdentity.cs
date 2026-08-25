using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Development;

internal sealed record DevelopmentCommandIdentity(
    string PrivateKeyFile,
    string PublicKeyFile)
{
    internal static DevelopmentCommandIdentity Create(string dataDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDirectory);
        var directory = Path.Combine(Path.GetFullPath(dataDirectory), "command-identity");
        Directory.CreateDirectory(directory);

        var privateKeyFile = Path.Combine(directory, "command-signing-key.pem");
        var publicKeyFile = Path.Combine(directory, "command-trust-key.pem");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        WriteRestricted(privateKeyFile, key.ExportPkcs8PrivateKeyPem());
        WriteRestricted(publicKeyFile, key.ExportSubjectPublicKeyInfoPem());
        return new(privateKeyFile, publicKeyFile);
    }

    private static void WriteRestricted(string path, string contents)
    {
        File.WriteAllText(path, contents);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
