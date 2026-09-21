using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TerraScale.Orchestrator.Messaging;

namespace TerraScale.Orchestrator.Bootstrap.Founding;

/// <summary>A separate, finite authority for the GRU seed before regional NATS exists.</summary>
internal sealed record OciFoundingPlan(
    int SchemaVersion,
    string Purpose,
    string BootstrapId,
    long RegionIntentGeneration,
    string Region,
    string SeedInstanceId,
    string CompartmentId,
    string AvailabilityDomain,
    string SeedFaultDomain,
    string SubnetId,
    string[] NetworkSecurityGroupIds,
    string ImageId,
    int Ocpus,
    int MemoryGb,
    DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt,
    OciFoundingPeer[] Peers)
{
    internal const string GrantPurpose = "terrascale-oci-gru-founding-peers-v1";
    internal const int MaximumDocumentBytes = 128 * 1024;
    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 8
    };

    internal static VerifiedOciFoundingPlan Load(string path, string trustKeyPath, OciRegionIntent intent)
    {
        var envelope = JsonSerializer.Deserialize<SignedPlan>(ReadFile(path, "founding grant", MaximumDocumentBytes), JsonOptions)
            ?? throw new InvalidDataException("The founding grant is empty.");
        var bytes = Convert.FromBase64String(envelope.Payload);
        if (bytes.Length is < 1 or > 96 * 1024 || Convert.ToBase64String(bytes) != envelope.Payload)
            throw new InvalidDataException("The founding grant payload is invalid.");
        using var key = ECDsa.Create();
        var publicKey = Encoding.UTF8.GetString(ReadFile(trustKeyPath, "founding trust key", 8 * 1024));
        if (!publicKey.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
            publicKey.Contains("PRIVATE KEY", StringComparison.Ordinal))
            throw new InvalidDataException("Founding trust must contain only a public key.");
        key.ImportFromPem(publicKey);
        BootstrapTrustBundleKey.RequireP256(key);
        var signature = Convert.FromBase64String(envelope.Signature);
        if (signature.Length != 64 || Convert.ToBase64String(signature) != envelope.Signature ||
            !key.VerifyData(SigningBytes(bytes), signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new InvalidDataException("The founding grant signature is invalid.");
        var plan = JsonSerializer.Deserialize<OciFoundingPlan>(bytes, JsonOptions)
            ?? throw new InvalidDataException("The founding plan is empty.");
        plan.Validate(intent);
        return new(plan, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    internal static byte[] SigningBytes(ReadOnlySpan<byte> payload)
    {
        var prefix = Encoding.UTF8.GetBytes(GrantPurpose + "\n");
        var result = new byte[prefix.Length + payload.Length];
        prefix.CopyTo(result, 0);
        payload.CopyTo(result.AsSpan(prefix.Length));
        return result;
    }

    internal void Validate(OciRegionIntent intent)
    {
        if (SchemaVersion != 1 || Purpose != GrantPurpose || Region != "GRU" ||
            RegionIntentGeneration != intent.Generation ||
            BootstrapId is not { Length: 32 } || BootstrapId.Any(c => c is not (>= '0' and <= '9' or >= 'a' and <= 'f')) ||
            !RegionalOcid(SeedInstanceId, "instance") || !RegionalOcid(SubnetId, "subnet") || !RegionalOcid(ImageId, "image") ||
            !Ocid(CompartmentId, "ocid1.compartment.oc1..") ||
            string.IsNullOrWhiteSpace(AvailabilityDomain) || AvailabilityDomain.Length > 128 ||
            !AvailabilityDomain.EndsWith(":SA-SAOPAULO-1-AD-1", StringComparison.Ordinal) ||
            !FaultDomain(SeedFaultDomain) || Ocpus is < 1 or > 4 || MemoryGb < Ocpus || MemoryGb > Ocpus * 16 ||
            NotBefore == default || ExpiresAt <= NotBefore || ExpiresAt - NotBefore > TimeSpan.FromHours(1) ||
            Peers is not { Length: 2 } || NetworkSecurityGroupIds is not { Length: >= 1 and <= 5 } ||
            NetworkSecurityGroupIds.Distinct(StringComparer.Ordinal).Count() != NetworkSecurityGroupIds.Length ||
            NetworkSecurityGroupIds.Any(id => !RegionalOcid(id, "networksecuritygroup")))
            throw new InvalidDataException("The founding grant exceeds its fixed GRU peer authority.");
        intent.RequireCell(Region);
        var slots = new HashSet<string>(StringComparer.Ordinal);
        var addresses = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal) { SeedFaultDomain };
        foreach (var peer in Peers)
        {
            if (peer is null || peer.Slot is not ("peer-1" or "peer-2") || !slots.Add(peer.Slot) ||
                !PrivateIpv4(peer.PrivateIp) || !addresses.Add(peer.PrivateIp) ||
                !FaultDomain(peer.FaultDomain) || !domains.Add(peer.FaultDomain) ||
                peer.BootstrapSha256 is not { Length: 64 } ||
                peer.BootstrapSha256.Any(c => c is not (>= 'a' and <= 'f' or >= '0' and <= '9')) ||
                peer.BootstrapBase64 is not { Length: >= 1 and <= 43692 })
                throw new InvalidDataException("The founding peer binding is invalid.");
            var bootstrap = Convert.FromBase64String(peer.BootstrapBase64);
            var text = new UTF8Encoding(false, true).GetString(bootstrap);
            if (bootstrap.Length is < 1 or > 32 * 1024 || Convert.ToBase64String(bootstrap) != peer.BootstrapBase64 ||
                Convert.ToHexStringLower(SHA256.HashData(bootstrap)) != peer.BootstrapSha256 ||
                !(text.StartsWith("#cloud-config", StringComparison.Ordinal) || text.StartsWith("#!", StringComparison.Ordinal)) ||
                text.Contains("PRIVATE KEY-----", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("BEGIN USER NKEY SEED", StringComparison.OrdinalIgnoreCase) ||
                text.Contains("BEGIN NATS USER JWT", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("The founding bootstrap is not a pinned public artifact.");
        }
    }

    internal void RequireCreateWindow(DateTimeOffset now)
    {
        if (now < NotBefore || now >= ExpiresAt)
            throw new InvalidOperationException("The founding create authority is outside its validity window.");
    }

    internal static byte[] ReadFile(string path, string name, int limit)
    {
        using var stream = File.OpenRead(NatsFileResolver.Resolve(path, name, limit, ownerPrivate: false));
        var bytes = new byte[limit + 1];
        try
        {
            var length = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            if (length is < 1 || length > limit) throw new InvalidDataException("The founding input exceeds its bound.");
            return bytes[..length];
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static bool RegionalOcid(string? value, string type) => Ocid(value, $"ocid1.{type}.oc1.sa-saopaulo-1.");
    private static bool Ocid(string? value, string prefix) => value is { Length: <= 256 } &&
        value.Length > prefix.Length && value.StartsWith(prefix, StringComparison.Ordinal) &&
        value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');
    private static bool FaultDomain(string? value) => value is "FAULT-DOMAIN-1" or "FAULT-DOMAIN-2" or "FAULT-DOMAIN-3";
    private static bool PrivateIpv4(string? value)
    {
        if (!IPAddress.TryParse(value, out var address) || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
            address.ToString() != value) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168;
    }

    internal sealed record SignedPlan(string Payload, string Signature);
}

internal sealed record OciFoundingPeer(string Slot, string PrivateIp, string FaultDomain, string BootstrapBase64, string BootstrapSha256);
internal sealed record VerifiedOciFoundingPlan(OciFoundingPlan Plan, string Digest);
