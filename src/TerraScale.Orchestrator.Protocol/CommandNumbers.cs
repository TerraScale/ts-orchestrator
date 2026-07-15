namespace TerraScale.Orchestrator.Protocol;

public readonly record struct ProtocolRevision
{
    private ProtocolRevision(long value) => Value = value;

    public long Value { get; }

    public bool IsValid => Value > 0;

    public static bool TryCreate(long value, out ProtocolRevision result) =>
        Positive(value, out result);

    private static bool Positive(long value, out ProtocolRevision result)
    {
        result = value > 0 ? new ProtocolRevision(value) : default;
        return value > 0;
    }

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

public readonly record struct DesiredGeneration
{
    private DesiredGeneration(long value) => Value = value;

    public long Value { get; }

    public bool IsValid => Value > 0;

    public static bool TryCreate(long value, out DesiredGeneration result)
    {
        result = value > 0 ? new DesiredGeneration(value) : default;
        return value > 0;
    }

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

public readonly record struct WriterEpoch
{
    private WriterEpoch(long value) => Value = value;

    public long Value { get; }

    public bool IsValid => Value > 0;

    public static bool TryCreate(long value, out WriterEpoch result)
    {
        result = value > 0 ? new WriterEpoch(value) : default;
        return value > 0;
    }

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}

public readonly record struct DeliveryAttempt
{
    private DeliveryAttempt(long value) => Value = value;

    public long Value { get; }

    public bool IsValid => Value > 0;

    public static bool TryCreate(long value, out DeliveryAttempt result)
    {
        result = value > 0 ? new DeliveryAttempt(value) : default;
        return value > 0;
    }

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
