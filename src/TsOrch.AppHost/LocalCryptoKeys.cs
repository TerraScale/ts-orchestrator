using System.Buffers.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TsOrch.AppHost;

internal sealed record class LocalCryptoKeys(
    string PinSigningKey,
    string PlacementPublishKeys,
    string TopologyPublishKeys,
    string PlacementPrivateKey,
    string TopologyPrivateKey,
    string AllowedSshKeys,
    string SessionSecret)
{
    private const string SshKeyType = "ssh-ed25519 ";

    public static LocalCryptoKeys Generate(string? sshPublicKeyPath)
    {
        var pin = PrivateJwk();
        var placement = PrivateJwk();
        var topology = PrivateJwk();
        return new LocalCryptoKeys(
            Serialize(pin),
            PublicJwks(placement),
            PublicJwks(topology),
            Serialize(placement),
            Serialize(topology),
            AllowedSshKey(sshPublicKeyPath),
            Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)));
    }

    public static string DefaultSshPublicKeyPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "id_ed25519.pub");

    public string WriteWorkerEnvFile(string directory, IReadOnlyList<KeyValuePair<string, string>> settings)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(settings);
        Directory.CreateDirectory(directory);
        IReadOnlyList<KeyValuePair<string, string>> secrets =
        [
            new("SESSION_SECRET", SessionSecret),
            new("PIN_SIGNING_KEY", PinSigningKey),
            new("PLACEMENT_PUBLISH_KEYS", PlacementPublishKeys),
            new("TOPOLOGY_PUBLISH_KEYS", TopologyPublishKeys),
            new("ALLOWED_SSH_KEYS", AllowedSshKeys),
        ];
        var builder = new StringBuilder();
        foreach (var (name, value) in settings.Concat(secrets))
        {
            builder.Append(EnvLine(name, value));
        }

        var envFile = Path.Combine(directory, "worker.env");
        WritePrivateFile(envFile, builder.ToString());
        WritePrivateFile(Path.Combine(directory, "placement-publish.jwk"), PlacementPrivateKey);
        WritePrivateFile(Path.Combine(directory, "topology-publish.jwk"), TopologyPrivateKey);
        return envFile;
    }

    private static EcJwk PrivateJwk()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(includePrivateParameters: true);
        if (parameters.Q.X is not { } x || parameters.Q.Y is not { } y || parameters.D is not { } d)
        {
            throw new UnreachableException("A freshly generated P-256 key must export X, Y and D.");
        }

        return new EcJwk("EC", "P-256", Base64Url.EncodeToString(x), Base64Url.EncodeToString(y), Base64Url.EncodeToString(d));
    }

    private static string PublicJwks(EcJwk key) =>
        JsonSerializer.Serialize(new EcJwkSet([key with { D = null }]), AppHostJsonContext.Default.EcJwkSet);

    private static string Serialize(EcJwk key) => JsonSerializer.Serialize(key, AppHostJsonContext.Default.EcJwk);

    private static string AllowedSshKey(string? sshPublicKeyPath)
    {
        if (sshPublicKeyPath is null || !File.Exists(sshPublicKeyPath))
        {
            return string.Empty;
        }

        var line = File.ReadAllText(sshPublicKeyPath).Trim();
        return line.StartsWith(SshKeyType, StringComparison.Ordinal) && !line.Contains('\n', StringComparison.Ordinal)
            ? line
            : throw new ArgumentException($"'{sshPublicKeyPath}' must hold exactly one ssh-ed25519 public key.", nameof(sshPublicKeyPath));
    }

    private static string EnvLine(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (value.AsSpan().IndexOfAny("'\r\n$") >= 0)
        {
            throw new ArgumentException($"Worker setting {name} cannot contain quotes, newlines or '$'.", nameof(value));
        }

        return $"{name}='{value}'\n";
    }

    private static void WritePrivateFile(string path, string content)
    {
        if (OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The TsOrch local fleet runs on Linux or macOS only.");
        }

        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        };
        using (var stream = new FileStream(path, options))
        using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            writer.Write(content);
        }

        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
}
