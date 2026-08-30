namespace TerraScale.Orchestrator.Contracts.StableIdentifiers;

public enum StableIdentifierKind
{
    Requirement = 1,
    Invariant = 2,
    SecurityRule = 3,
    StateMachine = 4,
    StableError = 5,
}

/// <summary>
/// Closed format rules for the permanent stable contract identifiers defined
/// by the GOAL.md "Stable contract identifiers" tables. Requirement, invariant,
/// and security-rule identifiers carry a three-digit zero-padded numeric
/// suffix; state-machine and stable-error identifiers carry uppercase
/// dash-separated word suffixes.
/// </summary>
internal static class StableIdentifierFormat
{
    public const string RequirementPrefix = "REQ-ORCH-";
    public const string InvariantPrefix = "INV-ORCH-";
    public const string SecurityRulePrefix = "SEC-ORCH-";
    public const string StateMachinePrefix = "SM-ORCH-";
    public const string StableErrorPrefix = "ERR-ORCH-";

    public static bool IsNumericSuffixId(string? value, string prefix)
    {
        if (value is null || value.Length != prefix.Length + 3 ||
            !value.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var suffix = value.AsSpan(prefix.Length);
        for (var index = 0; index < suffix.Length; index++)
        {
            if (suffix[index] is < '0' or > '9')
            {
                return false;
            }
        }

        return true;
    }

    public static bool IsNamedSuffixId(string? value, string prefix)
    {
        if (value is null || !value.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        var suffix = value.AsSpan(prefix.Length);
        if (suffix.IsEmpty)
        {
            return false;
        }

        var tokenStart = true;
        for (var index = 0; index < suffix.Length; index++)
        {
            var character = suffix[index];
            if (character == '-')
            {
                if (tokenStart)
                {
                    return false;
                }

                tokenStart = true;
                continue;
            }

            var isUppercaseLetter = character is >= 'A' and <= 'Z';
            var isDigit = character is >= '0' and <= '9';
            if (!isUppercaseLetter && !isDigit)
            {
                return false;
            }

            if (tokenStart && !isUppercaseLetter)
            {
                return false;
            }

            tokenStart = false;
        }

        return !tokenStart;
    }
}
