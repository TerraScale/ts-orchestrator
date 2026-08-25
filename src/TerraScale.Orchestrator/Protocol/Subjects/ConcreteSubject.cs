namespace TerraScale.Orchestrator.Protocol.Subjects;

public sealed class ConcreteSubject : IEquatable<ConcreteSubject>, IComparable<ConcreteSubject>
{
    private readonly string[] _tokens;

    private ConcreteSubject(string value, string[] tokens)
    {
        Value = value;
        _tokens = tokens;
    }

    public string Value { get; }

    public int TokenCount => _tokens.Length;

    internal ReadOnlySpan<string> Tokens => _tokens;

    public static bool TryParse(
        string? value,
        SubjectGrammarLimits? limits,
        out ConcreteSubject? result,
        out SubjectGrammarError error)
    {
        if (!SubjectGrammarParser.TryTokenize(value, limits, out var tokens, out error))
        {
            result = null;
            return false;
        }

        if (value is null)
        {
            result = null;
            error = SubjectGrammarError.Empty;
            return false;
        }

        if (tokens.Any(static token => token.Contains('*', StringComparison.Ordinal)
            || token.Contains('>', StringComparison.Ordinal)))
        {
            result = null;
            error = SubjectGrammarError.WildcardNotAllowed;
            return false;
        }

        result = new ConcreteSubject(value, tokens);
        return true;
    }

    public bool Equals(ConcreteSubject? other) =>
        other is not null && StringComparer.Ordinal.Equals(Value, other.Value);

    public override bool Equals(object? obj) => Equals(obj as ConcreteSubject);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public int CompareTo(ConcreteSubject? other) =>
        other is null ? 1 : StringComparer.Ordinal.Compare(Value, other.Value);

    public override string ToString() => Value;
}
