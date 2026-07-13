using System.Security.Cryptography;

namespace TerraScale.Orchestrator.ControlPlane.Snapshots;

public sealed class SnapshotStateDigest : IEquatable<SnapshotStateDigest>
{
    private readonly byte[] _bytes;
    private SnapshotStateDigest(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();
    public int Length => _bytes.Length;
    public ReadOnlySpan<byte> Bytes => _bytes;
    public bool IsValid => _bytes.Length > 0;
    public static bool TryCopyFrom(ReadOnlySpan<byte> bytes, int maximumLength, out SnapshotStateDigest? result)
    {
        result = maximumLength > 0 && !bytes.IsEmpty && bytes.Length <= maximumLength
            ? new SnapshotStateDigest(bytes)
            : null;
        return result is not null;
    }
    public bool Equals(SnapshotStateDigest? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);
    public override bool Equals(object? obj) => Equals(obj as SnapshotStateDigest);
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }
    public override string ToString() => "<snapshot-state-digest>";
}

public sealed class SnapshotSignature : IEquatable<SnapshotSignature>
{
    private readonly byte[] _bytes;
    private SnapshotSignature(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();
    public int Length => _bytes.Length;
    public ReadOnlySpan<byte> Bytes => _bytes;
    public bool IsValid => _bytes.Length > 0;
    public static bool TryCopyFrom(ReadOnlySpan<byte> bytes, int maximumLength, out SnapshotSignature? result)
    {
        result = maximumLength > 0 && !bytes.IsEmpty && bytes.Length <= maximumLength
            ? new SnapshotSignature(bytes)
            : null;
        return result is not null;
    }
    public bool Equals(SnapshotSignature? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(_bytes, other._bytes);
    public override bool Equals(object? obj) => Equals(obj as SnapshotSignature);
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }
    public override string ToString() => "<snapshot-signature>";
}
