using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Snapshots;

internal static class SnapshotIdentityRules
{
    public static bool IsValid(string? value, int maximumLength)
    {
        if (maximumLength <= 0 || string.IsNullOrEmpty(value) || value.Length > maximumLength)
        {
            return false;
        }

        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character))
            {
                return false;
            }

            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    return false;
                }

                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                return false;
            }
        }

        return true;
    }
}

public readonly record struct SnapshotAuthorityId
{
    private SnapshotAuthorityId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out SnapshotAuthorityId result)
    {
        result = SnapshotIdentityRules.IsValid(value, maximumLength) ? new SnapshotAuthorityId(value!) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct SnapshotStreamId
{
    private SnapshotStreamId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out SnapshotStreamId result)
    {
        result = SnapshotIdentityRules.IsValid(value, maximumLength) ? new SnapshotStreamId(value!) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct SnapshotId
{
    private SnapshotId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out SnapshotId result)
    {
        result = SnapshotIdentityRules.IsValid(value, maximumLength) ? new SnapshotId(value!) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct SnapshotSchemaId
{
    private SnapshotSchemaId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out SnapshotSchemaId result)
    {
        result = SnapshotIdentityRules.IsValid(value, maximumLength) ? new SnapshotSchemaId(value!) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct SnapshotSigningKeyId
{
    private SnapshotSigningKeyId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out SnapshotSigningKeyId result)
    {
        result = SnapshotIdentityRules.IsValid(value, maximumLength) ? new SnapshotSigningKeyId(value!) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct SnapshotEpoch
{
    private SnapshotEpoch(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out SnapshotEpoch result)
    {
        result = value > 0 ? new SnapshotEpoch(value) : default;
        return result.IsValid;
    }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

public readonly record struct SnapshotStreamSequence
{
    private SnapshotStreamSequence(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out SnapshotStreamSequence result)
    {
        result = value > 0 ? new SnapshotStreamSequence(value) : default;
        return result.IsValid;
    }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

public readonly record struct SnapshotGeneration
{
    private SnapshotGeneration(ulong value) => Value = value;
    public ulong Value { get; }
    public bool IsValid => Value > 0;
    public static bool TryCreate(ulong value, out SnapshotGeneration result)
    {
        result = value > 0 ? new SnapshotGeneration(value) : default;
        return result.IsValid;
    }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
