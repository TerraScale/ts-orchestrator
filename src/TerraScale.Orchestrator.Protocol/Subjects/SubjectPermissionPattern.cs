namespace TerraScale.Orchestrator.Protocol.Subjects;

public sealed class SubjectPermissionPattern : IEquatable<SubjectPermissionPattern>, IComparable<SubjectPermissionPattern>
{
    private readonly string[] _tokens;

    private SubjectPermissionPattern(string value, string[] tokens)
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
        out SubjectPermissionPattern? result,
        out SubjectGrammarError error)
    {
        if (!SubjectGrammarParser.TryTokenize(value, limits, out var tokens, out error))
        {
            result = null;
            return false;
        }

        for (var index = 0; index < tokens.Length; index++)
        {
            var token = tokens[index];
            if (token == ">")
            {
                if (index != tokens.Length - 1)
                {
                    result = null;
                    error = SubjectGrammarError.TerminalWildcardMustBeFinal;
                    return false;
                }

                continue;
            }

            if (token == "*")
            {
                continue;
            }

            if (token.Contains('*', StringComparison.Ordinal)
                || token.Contains('>', StringComparison.Ordinal))
            {
                result = null;
                error = SubjectGrammarError.InvalidWildcard;
                return false;
            }
        }

        result = new SubjectPermissionPattern(value!, tokens);
        return true;
    }

    public bool Matches(ConcreteSubject? subject)
    {
        if (subject is null)
        {
            return false;
        }

        var patternTokens = Tokens;
        var subjectTokens = subject.Tokens;
        var terminalWildcard = patternTokens[^1] == ">";
        if (terminalWildcard)
        {
            if (subjectTokens.Length < patternTokens.Length)
            {
                return false;
            }
        }
        else if (subjectTokens.Length != patternTokens.Length)
        {
            return false;
        }

        var literalCount = terminalWildcard ? patternTokens.Length - 1 : patternTokens.Length;
        for (var index = 0; index < literalCount; index++)
        {
            var patternToken = patternTokens[index];
            if (patternToken != "*"
                && !StringComparer.Ordinal.Equals(patternToken, subjectTokens[index]))
            {
                return false;
            }
        }

        return true;
    }

    public bool Equals(SubjectPermissionPattern? other) =>
        other is not null && StringComparer.Ordinal.Equals(Value, other.Value);

    public override bool Equals(object? obj) => Equals(obj as SubjectPermissionPattern);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    public int CompareTo(SubjectPermissionPattern? other) =>
        other is null ? 1 : StringComparer.Ordinal.Compare(Value, other.Value);

    public override string ToString() => Value;
}
