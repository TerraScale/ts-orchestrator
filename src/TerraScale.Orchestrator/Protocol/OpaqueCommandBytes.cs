using System.Security.Cryptography;

namespace TerraScale.Orchestrator.Protocol;

public sealed class OpaquePayload : IEquatable<OpaquePayload>
{
    private readonly byte[] _bytes;

    private OpaquePayload(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();

    public int Length => _bytes.Length;

    public ReadOnlySpan<byte> Bytes => _bytes;

    internal ReadOnlyMemory<byte> Memory => _bytes;

    public static OpaquePayload CopyFrom(ReadOnlySpan<byte> bytes) => new(bytes);

    public bool Equals(OpaquePayload? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    public override bool Equals(object? obj) => Equals(obj as OpaquePayload);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    public override string ToString() => "<opaque-payload>";
}

public sealed class PayloadDigest : IEquatable<PayloadDigest>
{
    private readonly byte[] _bytes;

    private PayloadDigest(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();

    public int Length => _bytes.Length;

    public ReadOnlySpan<byte> Bytes => _bytes;

    public bool IsValid => _bytes.Length > 0;

    public static bool TryCopyFrom(ReadOnlySpan<byte> bytes, out PayloadDigest? result)
    {
        result = bytes.IsEmpty ? null : new PayloadDigest(bytes);
        return result is not null;
    }

    public bool Equals(PayloadDigest? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    public override bool Equals(object? obj) => Equals(obj as PayloadDigest);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    public override string ToString() => "<payload-digest>";
}

public sealed class OpaqueSignature : IEquatable<OpaqueSignature>
{
    private readonly byte[] _bytes;

    private OpaqueSignature(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();

    public int Length => _bytes.Length;

    public ReadOnlySpan<byte> Bytes => _bytes;

    public bool IsValid => _bytes.Length > 0;

    public static bool TryCopyFrom(ReadOnlySpan<byte> bytes, out OpaqueSignature? result)
    {
        result = bytes.IsEmpty ? null : new OpaqueSignature(bytes);
        return result is not null;
    }

    public bool Equals(OpaqueSignature? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);

    public override bool Equals(object? obj) => Equals(obj as OpaqueSignature);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    public override string ToString() => "<opaque-signature>";
}
