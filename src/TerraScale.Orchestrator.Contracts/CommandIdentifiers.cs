namespace TerraScale.Orchestrator.Contracts;

internal static class CommandIdentifierRules
{
    public static bool IsValid(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.AsSpan().IndexOf('\0') < 0;
}

public readonly record struct CellId
{
    private readonly string? _value;

    private CellId(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsValid => CommandIdentifierRules.IsValid(_value);

    public static bool TryCreate(string? value, out CellId result)
    {
        if (!CommandIdentifierRules.IsValid(value))
        {
            result = default;
            return false;
        }

        result = new CellId(value!);
        return true;
    }

    public override string ToString() => Value;
}

public readonly record struct AggregateId
{
    private readonly string? _value;

    private AggregateId(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsValid => CommandIdentifierRules.IsValid(_value);

    public static bool TryCreate(string? value, out AggregateId result)
    {
        if (!CommandIdentifierRules.IsValid(value))
        {
            result = default;
            return false;
        }

        result = new AggregateId(value!);
        return true;
    }

    public override string ToString() => Value;
}

public readonly record struct OperationId
{
    private readonly string? _value;

    private OperationId(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsValid => CommandIdentifierRules.IsValid(_value);

    public static bool TryCreate(string? value, out OperationId result)
    {
        if (!CommandIdentifierRules.IsValid(value))
        {
            result = default;
            return false;
        }

        result = new OperationId(value!);
        return true;
    }

    public override string ToString() => Value;
}

public readonly record struct IdempotencyKey
{
    private readonly string? _value;

    private IdempotencyKey(string value) => _value = value;

    public string Value => _value ?? string.Empty;

    public bool IsValid => CommandIdentifierRules.IsValid(_value);

    public static bool TryCreate(string? value, out IdempotencyKey result)
    {
        if (!CommandIdentifierRules.IsValid(value))
        {
            result = default;
            return false;
        }

        result = new IdempotencyKey(value!);
        return true;
    }

    public override string ToString() => Value;
}
