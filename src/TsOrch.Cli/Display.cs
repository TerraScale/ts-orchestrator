using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using static System.FormattableString;

namespace TsOrch.Cli;

internal static class Display
{
    public static string Time(long unixMilliseconds) =>
        DateTimeOffset.FromUnixTimeMilliseconds(unixMilliseconds).ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static string Age(TimeProvider timeProvider, long unixMilliseconds)
    {
        if (unixMilliseconds <= 0)
        {
            return "never";
        }

        var age = timeProvider.GetUtcNow() - DateTimeOffset.FromUnixTimeMilliseconds(unixMilliseconds);
        return age switch
        {
            { TotalSeconds: < 0 } => "now",
            { TotalSeconds: < 120 } => Invariant($"{(int)age.TotalSeconds}s ago"),
            { TotalMinutes: < 120 } => Invariant($"{(int)age.TotalMinutes}m ago"),
            { TotalHours: < 48 } => Invariant($"{(int)age.TotalHours}h ago"),
            _ => Invariant($"{(int)age.TotalDays}d ago"),
        };
    }

    public static string Fixed(double value, int decimals = 1) =>
        value.ToString(decimals switch
        {
            0 => "F0",
            1 => "F1",
            _ => "F2",
        }, CultureInfo.InvariantCulture);

    public static string Integer(long value) => value.ToString(CultureInfo.InvariantCulture);

    public static string Rate(long bytesPerSecond) => bytesPerSecond switch
    {
        < 1024 => Invariant($"{bytesPerSecond}B/s"),
        < 1024 * 1024 => Invariant($"{bytesPerSecond / 1024.0:F1}K/s"),
        < 1024L * 1024 * 1024 => Invariant($"{bytesPerSecond / (1024.0 * 1024):F1}M/s"),
        _ => Invariant($"{bytesPerSecond / (1024.0 * 1024 * 1024):F1}G/s"),
    };

    public static string List(IReadOnlyList<string> values) => values.Count == 0 ? "-" : string.Join(',', values);
}

internal static class WireNameExtensions
{
    extension(HealthState value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.HealthState);
    }

    extension(PoolKind value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.PoolKind);
    }

    extension(CpuArch value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.CpuArch);
    }

    extension(NodeStatus value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.NodeStatus);
    }

    extension(PlacementMode value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.PlacementMode);
    }

    extension(PriorityTier value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.PriorityTier);
    }

    extension(RolloutPhase value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.RolloutPhase);
    }

    extension(EventKind value)
    {
        public string WireName => EventKindJsonConverter.WireName(value);
    }

    extension(OperatorRole value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.OperatorRole);
    }

    extension(ApplyOutcome value)
    {
        public string WireName => Encode(value, CliJsonContext.Default.ApplyOutcome);
    }

    private static string Encode<T>(T value, JsonTypeInfo<T> typeInfo) => JsonSerializer.Serialize(value, typeInfo).Trim('"');
}
