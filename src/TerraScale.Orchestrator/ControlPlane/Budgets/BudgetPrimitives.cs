using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Budgets;

/// <summary>Technical caller-input snapshot limits; these are not monetary, capacity, or approval policy.</summary>
public static class BudgetTechnicalInputLimits
{
    public const int MaximumEvidenceCount = 4_096;
    public const int MaximumNodeClassPolicyCount = 4_096;
}

internal static class BudgetInputSnapshot
{
    internal static bool TryCopy<T>(IEnumerable<T>? source, int maximum, out T[] snapshot)
    {
        snapshot = [];
        if (source is null || maximum < 0) return false;
        var values = new List<T>(Math.Min(maximum, 256));
        try
        {
            using var enumerator = source.GetEnumerator();
            while (enumerator.MoveNext())
            {
                if (values.Count == maximum) return false;
                values.Add(enumerator.Current);
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException and not AccessViolationException)
        {
            return false;
        }
        snapshot = values.ToArray();
        return true;
    }
}

internal static class BudgetIdentityRules
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

public readonly record struct BudgetCellId
{
    private BudgetCellId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out BudgetCellId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new BudgetCellId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct BudgetNodeClassId
{
    private BudgetNodeClassId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out BudgetNodeClassId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new BudgetNodeClassId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct BudgetCostCenterId
{
    private BudgetCostCenterId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out BudgetCostCenterId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new BudgetCostCenterId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct BudgetResourceId
{
    private BudgetResourceId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out BudgetResourceId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new BudgetResourceId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct PriceEvidenceId
{
    private PriceEvidenceId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out PriceEvidenceId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new PriceEvidenceId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

public readonly record struct BudgetApprovalId
{
    private BudgetApprovalId(string value) => Value = value;
    public string? Value { get; }
    public bool IsValid => Value is not null;
    public static bool TryCreate(string? value, int maximumLength, out BudgetApprovalId result)
    {
        result = value is { } validValue && BudgetIdentityRules.IsValid(validValue, maximumLength) ? new BudgetApprovalId(validValue) : default;
        return result.IsValid;
    }
    public override string ToString() => Value ?? string.Empty;
}

/// <summary>Non-negative fixed-point base units. Unit scale belongs to the explicit policy schema.</summary>
public readonly record struct BudgetQuantity
{
    private BudgetQuantity(long value) => Value = value;
    public long Value { get; }
    public bool IsValid => Value >= 0;
    public static bool TryCreate(long value, out BudgetQuantity result)
    {
        result = value >= 0 ? new BudgetQuantity(value) : default;
        return value >= 0;
    }
    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}

[Flags]
public enum BudgetDimension
{
    None = 0,
    Cpu = 1 << 0,
    Memory = 1 << 1,
    Storage = 1 << 2,
    Iops = 1 << 3,
    Throughput = 1 << 4,
    PublicIp = 1 << 5,
    LoadBalancerBackend = 1 << 6,
    HourlySpend = 1 << 7,
    DailySpend = 1 << 8,
    All = Cpu | Memory | Storage | Iops | Throughput | PublicIp | LoadBalancerBackend | HourlySpend | DailySpend,
}

public sealed class BudgetVector : IEquatable<BudgetVector>
{
    public BudgetVector(
        BudgetQuantity cpu, BudgetQuantity memory, BudgetQuantity storage, BudgetQuantity iops,
        BudgetQuantity throughput, BudgetQuantity publicIp, BudgetQuantity loadBalancerBackend,
        BudgetQuantity hourlySpend, BudgetQuantity dailySpend)
    {
        Cpu = cpu;
        Memory = memory;
        Storage = storage;
        Iops = iops;
        Throughput = throughput;
        PublicIp = publicIp;
        LoadBalancerBackend = loadBalancerBackend;
        HourlySpend = hourlySpend;
        DailySpend = dailySpend;
    }

    public BudgetQuantity Cpu { get; }
    public BudgetQuantity Memory { get; }
    public BudgetQuantity Storage { get; }
    public BudgetQuantity Iops { get; }
    public BudgetQuantity Throughput { get; }
    public BudgetQuantity PublicIp { get; }
    public BudgetQuantity LoadBalancerBackend { get; }
    public BudgetQuantity HourlySpend { get; }
    public BudgetQuantity DailySpend { get; }
    public bool IsValid => Cpu.IsValid && Memory.IsValid && Storage.IsValid && Iops.IsValid
        && Throughput.IsValid && PublicIp.IsValid && LoadBalancerBackend.IsValid
        && HourlySpend.IsValid && DailySpend.IsValid;

    public static BudgetVector Zero { get; } = new(default, default, default, default, default, default, default, default, default);

    internal bool TryAdd(BudgetVector other, out BudgetVector? result) =>
        TryCombine(other, true, out result);

    internal bool TrySubtract(BudgetVector other, out BudgetVector? result) =>
        TryCombine(other, false, out result);

    internal BudgetDimension ExceededBy(BudgetVector maximum)
    {
        var dimensions = BudgetDimension.None;
        if (Cpu.Value > maximum.Cpu.Value) dimensions |= BudgetDimension.Cpu;
        if (Memory.Value > maximum.Memory.Value) dimensions |= BudgetDimension.Memory;
        if (Storage.Value > maximum.Storage.Value) dimensions |= BudgetDimension.Storage;
        if (Iops.Value > maximum.Iops.Value) dimensions |= BudgetDimension.Iops;
        if (Throughput.Value > maximum.Throughput.Value) dimensions |= BudgetDimension.Throughput;
        if (PublicIp.Value > maximum.PublicIp.Value) dimensions |= BudgetDimension.PublicIp;
        if (LoadBalancerBackend.Value > maximum.LoadBalancerBackend.Value) dimensions |= BudgetDimension.LoadBalancerBackend;
        if (HourlySpend.Value > maximum.HourlySpend.Value) dimensions |= BudgetDimension.HourlySpend;
        if (DailySpend.Value > maximum.DailySpend.Value) dimensions |= BudgetDimension.DailySpend;
        return dimensions;
    }

    internal bool IsStorageSafetyDomainIncrease =>
        Storage.Value > 0
        && Cpu.Value == 0
        && Memory.Value == 0
        && PublicIp.Value == 0
        && LoadBalancerBackend.Value == 0;

    private bool TryCombine(BudgetVector other, bool add, out BudgetVector? result)
    {
        Span<long> values = stackalloc long[9];
        var left = Values();
        var right = other.Values();
        for (var index = 0; index < values.Length; index++)
        {
            try
            {
                values[index] = add ? checked(left[index] + right[index]) : checked(left[index] - right[index]);
            }
            catch (OverflowException)
            {
                result = null;
                return false;
            }
            if (values[index] < 0)
            {
                result = null;
                return false;
            }
        }
        result = From(values);
        return true;
    }

    private long[] Values() =>
        [Cpu.Value, Memory.Value, Storage.Value, Iops.Value, Throughput.Value, PublicIp.Value,
            LoadBalancerBackend.Value, HourlySpend.Value, DailySpend.Value];

    private static BudgetVector From(ReadOnlySpan<long> values)
    {
        return new(
            Quantity(values[0]), Quantity(values[1]), Quantity(values[2]),
            Quantity(values[3]), Quantity(values[4]), Quantity(values[5]),
            Quantity(values[6]), Quantity(values[7]), Quantity(values[8]));
    }

    private static BudgetQuantity Quantity(long value)
    {
        BudgetQuantity.TryCreate(value, out var result);
        return result;
    }

    public bool Equals(BudgetVector? other) => other is not null && Values().SequenceEqual(other.Values());
    public override bool Equals(object? obj) => Equals(obj as BudgetVector);
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var value in Values()) hash.Add(value);
        return hash.ToHashCode();
    }
    public override string ToString() => string.Create(CultureInfo.InvariantCulture,
        $"cpu={Cpu.Value};memory={Memory.Value};storage={Storage.Value};iops={Iops.Value};throughput={Throughput.Value};publicIp={PublicIp.Value};lbBackend={LoadBalancerBackend.Value};hourly={HourlySpend.Value};daily={DailySpend.Value}");
}
