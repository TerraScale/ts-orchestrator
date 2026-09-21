using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;
using TerraScale.Orchestrator.Nodes;

namespace TerraScale.Orchestrator.Bootstrap.Secrets;

/// <summary>Public, immutable references for one credential bundle; never secret values.</summary>
internal sealed record OciSecretManifest(int SchemaVersion, string Region, OciSecretFile[] Files)
{
    internal const int MaximumManifestBytes = 32 * 1024;
    internal const int MaximumSecretBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };

    internal static OciSecretManifest Load(string path)
    {
        var resolved = NatsFileResolver.Resolve(path, "OCI secret manifest", MaximumManifestBytes, ownerPrivate: false);
        using var stream = File.OpenRead(resolved);
        var bytes = new byte[MaximumManifestBytes + 1];
        var length = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
        return Parse(bytes.AsSpan(0, length));
    }

    internal static OciSecretManifest Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaximumManifestBytes)
            throw new InvalidDataException("The OCI secret manifest exceeds its bounds.");
        var manifest = JsonSerializer.Deserialize<OciSecretManifest>(bytes, JsonOptions);
        if (manifest is not { SchemaVersion: 1, Files.Length: >= 1 and <= 32 } ||
            !TerraScaleRegion.IsValid(manifest.Region))
            throw new InvalidDataException("The OCI secret manifest has an unsupported shape.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        var prefix = $"ocid1.vaultsecret.oc1.{TerraScaleRegion.OciName(manifest.Region)}.";
        foreach (var file in manifest.Files)
        {
            if (file is null || !ValidFileName(file.Name) || !names.Add(file.Name) ||
                file.Version < 1 || file.SecretId is null || file.SecretId.Length > 256 ||
                !file.SecretId.StartsWith(prefix, StringComparison.Ordinal) ||
                file.SecretId.Length <= prefix.Length ||
                file.SecretId.Any(static character => character is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-')) ||
                file.Sha256 is not { Length: 64 } ||
                file.Sha256.Any(static character => character is not (>= 'a' and <= 'f' or >= '0' and <= '9')))
                throw new InvalidDataException("The OCI secret manifest has an invalid file reference.");
        }
        return manifest;
    }

    internal static bool ValidFileName(string? value) => value is { Length: >= 1 and <= 64 } &&
        value[0] is >= 'a' and <= 'z' && value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_');

    internal static void VerifyContent(OciSecretFile file, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 1 or > MaximumSecretBytes ||
            !CryptographicOperations.FixedTimeEquals(SHA256.HashData(bytes), Convert.FromHexString(file.Sha256)))
            throw new InvalidDataException("The pinned OCI secret content did not verify.");
    }
}

internal sealed record OciSecretFile(string Name, string SecretId, long Version, string Sha256);
