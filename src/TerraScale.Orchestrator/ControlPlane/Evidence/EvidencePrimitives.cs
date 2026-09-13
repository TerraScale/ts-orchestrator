using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Evidence;

internal static class EvidenceRules
{
    internal static bool ValidId(string? value, int maximumLength) => maximumLength > 0 && value is { Length: > 0 } && value.Length <= maximumLength
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '/' or ':');

    internal static bool TryCreateIdentity<T>(string? value, int maximumLength, Func<string, T> factory,
        [NotNullWhen(true)] out T? identity)
        where T : class
    {
        if (value is null || !ValidId(value, maximumLength))
        {
            identity = null;
            return false;
        }

        identity = factory(value);
        return true;
    }
}

public abstract record EvidenceIdentity
{
    private protected EvidenceIdentity(string value) => Value = value;
    public string Value { get; }
    public override string ToString() => "<evidence-identity>";
}

public sealed record EvidenceTreeId : EvidenceIdentity
{
    private EvidenceTreeId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceTreeId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceDependencyLockId : EvidenceIdentity
{
    private EvidenceDependencyLockId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceDependencyLockId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceSchemaId : EvidenceIdentity
{
    private EvidenceSchemaId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceSchemaId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceTestBinaryId : EvidenceIdentity
{
    private EvidenceTestBinaryId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceTestBinaryId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceArtifactId : EvidenceIdentity
{
    private EvidenceArtifactId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceArtifactId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceSuiteId : EvidenceIdentity
{
    private EvidenceSuiteId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceSuiteId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceTraceId : EvidenceIdentity
{
    private EvidenceTraceId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceTraceId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceFuzzTargetId : EvidenceIdentity
{
    private EvidenceFuzzTargetId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceFuzzTargetId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceCorpusId : EvidenceIdentity
{
    private EvidenceCorpusId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceCorpusId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceL0CId : EvidenceIdentity
{
    private EvidenceL0CId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceL0CId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceApproverId : EvidenceIdentity
{
    private EvidenceApproverId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceApproverId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceSigningProfileId : EvidenceIdentity
{
    private EvidenceSigningProfileId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceSigningProfileId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceSigningIdentityId : EvidenceIdentity
{
    private EvidenceSigningIdentityId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceSigningIdentityId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceSignatureId : EvidenceIdentity
{
    private EvidenceSignatureId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceSignatureId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceManifestId : EvidenceIdentity
{
    private EvidenceManifestId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceManifestId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed record EvidenceExclusionId : EvidenceIdentity
{
    private EvidenceExclusionId(string value) : base(value) { }
    public static bool TryCreate(string? value, int maximumLength, [NotNullWhen(true)] out EvidenceExclusionId? identity) =>
        EvidenceRules.TryCreateIdentity(value, maximumLength, static valid => new(valid), out identity);
}

public sealed class EvidenceSha256 : IEquatable<EvidenceSha256>
{
    private readonly byte[] _bytes;
    private EvidenceSha256(byte[] bytes) => _bytes = bytes;
    public static bool TryCreate(ReadOnlySpan<byte> bytes, [NotNullWhen(true)] out EvidenceSha256? digest) { digest = bytes.Length == 32 ? new(bytes.ToArray()) : null; return digest is not null; }
    public byte[] CopyBytes() => _bytes.ToArray();
    public bool Equals(EvidenceSha256? other) => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);
    public override bool Equals(object? obj) => obj is EvidenceSha256 other && Equals(other);
    public override int GetHashCode() { var hash = new HashCode(); foreach (var value in _bytes) hash.Add(value); return hash.ToHashCode(); }
    public override string ToString() => "<sha256>";
}

public readonly record struct EvidenceCount
{
    private EvidenceCount(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out EvidenceCount count) { count = value > 0 ? new(value) : default; return count.IsValid; }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
public readonly record struct EvidencePercentage
{
    private EvidencePercentage(ushort value) => Value = value;
    public ushort Value { get; }
    public bool IsValid => Value <= 100;
    public static bool TryCreate(ushort value, out EvidencePercentage percentage) { percentage = value <= 100 ? new(value) : default; return value <= 100; }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
public readonly record struct EvidenceNonNegativeCount
{
    private EvidenceNonNegativeCount(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => true;
    public static bool TryCreate(ulong value, out EvidenceNonNegativeCount count) { count = new(value); return true; }
}
public readonly record struct EvidenceDurationSeconds
{
    private EvidenceDurationSeconds(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out EvidenceDurationSeconds duration) { duration = value > 0 ? new(value) : default; return duration.IsValid; }
}
public readonly record struct EvidenceGeneration
{
    private EvidenceGeneration(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out EvidenceGeneration generation) { generation = value > 0 ? new(value) : default; return generation.IsValid; }
}
public readonly record struct EvidenceSequence
{
    private EvidenceSequence(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out EvidenceSequence sequence) { sequence = value > 0 ? new(value) : default; return sequence.IsValid; }
}

public enum EvidenceLane { Unknown = 0, Feature = 1, Full = 2 }
public enum EvidenceExecutionKind { Unknown = 0, Cold = 1, ContentAddressedReuse = 2 }
public enum EvidenceDomain { Unknown = 0, Control = 1, Scheduling = 2, Messaging = 3, Compute = 4, Storage = 5, TerraBase = 6, Security = 7, Delivery = 8, Observability = 9, Networking = 10, Budgets = 11, Provisioning = 12, Runtime = 13 }
public enum EvidenceArchitecture { Unknown = 0, LinuxX64 = 1, LinuxArm64 = 2 }
public enum EvidenceResult { Unknown = 0, Passed = 1, Failed = 2 }
public enum EvidenceExclusionKind { Unknown = 0, GeneratedCode = 1, TrivialWiring = 2, Safety = 3, Authorization = 4, Durability = 5, Deletion = 6, StateTransition = 7, Validation = 8, Ownership = 9, Fencing = 10, Retry = 11, Compensation = 12, AdapterClassification = 13 }
public enum EvidenceChangeKind { Unknown = 0, None = 1, ShardOnly = 2, SharedContract = 3, Security = 4, Toolchain = 5, ColdFirstCandidate = 6 }
public enum EvidenceGateTarget { Unknown = 0, DependencyConformance = 1, L1SCredentialRelease = 2 }
public enum EvidenceAction { Unknown = 0, Hold = 1, AllowDependencyConformance = 2, AllowL1SCredentialRelease = 3 }
public enum EvidenceCode { Unknown = 0, Allowed = 1, InvalidInput = 2, WrongSubject = 3, MissingDomain = 4, DuplicateDomain = 5, ThresholdNotMet = 6, ForbiddenExclusion = 7, SafetyMutantSurvived = 8, ResultFailed = 9, InvalidArchitecture = 10, ReuseDenied = 11, FullExecutionRequired = 12, FeatureLaneCannotRelease = 13, WrongSigningProfile = 14, WrongSigningIdentity = 15, WrongSignature = 16, StaleGeneration = 17, FutureGeneration = 18, StaleExpiry = 19, FutureExpiry = 20, Expired = 21, InvalidSignature = 22, SignatureVerificationFailed = 23, ArithmeticOverflow = 24 }

public sealed class EvidenceOpaqueSignature
{
    private readonly byte[] _bytes;
    public EvidenceOpaqueSignature(ReadOnlySpan<byte> bytes, int maximumBytes) { IsValid = maximumBytes > 0 && bytes.Length > 0 && bytes.Length <= maximumBytes; _bytes = IsValid ? bytes.ToArray() : []; }
    public bool IsValid { get; }
    public byte[] CopyBytes() => _bytes.ToArray();
    public override string ToString() => "<opaque-signature>";
}

internal static class EvidenceCollections
{
    internal static ImmutableArray<T> CopyBounded<T>(IEnumerable<T?>? source, int maximum, out bool valid) where T : class
    {
        var values = Snapshot(source, maximum, true, out valid); valid = valid && values.All(x => x is not null);
        return values.Where(x => x is not null).Cast<T>().ToImmutableArray();
    }
    internal static ImmutableArray<T> Snapshot<T>(IEnumerable<T>? source, int maximum, bool requireNonEmpty, out bool valid)
    {
        var builder = ImmutableArray.CreateBuilder<T>(); valid = false;
        if (source is null || maximum <= 0) return builder.ToImmutable();
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (builder.Count == maximum) return builder.ToImmutable();
                builder.Add(enumerator.Current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException) { return builder.ToImmutable(); }
        valid = !requireNonEmpty || builder.Count > 0; return builder.ToImmutable();
    }
}

