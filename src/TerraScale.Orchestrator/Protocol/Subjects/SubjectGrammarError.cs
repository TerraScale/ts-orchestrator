namespace TerraScale.Orchestrator.Protocol.Subjects;

public enum SubjectGrammarError
{
    None = 0,
    InvalidLimits,
    Empty,
    SubjectTooLong,
    TooManyTokens,
    EmptyToken,
    TokenTooLong,
    WhitespaceNotAllowed,
    ControlCharacterNotAllowed,
    InvalidUnicodeScalarSequence,
    WildcardNotAllowed,
    InvalidWildcard,
    TerminalWildcardMustBeFinal,
}

internal static class SubjectGrammarParser
{
    public static bool TryTokenize(
        string? value,
        SubjectGrammarLimits? limits,
        out string[] tokens,
        out SubjectGrammarError error)
    {
        tokens = [];
        if (limits is null)
        {
            error = SubjectGrammarError.InvalidLimits;
            return false;
        }

        if (string.IsNullOrEmpty(value))
        {
            error = SubjectGrammarError.Empty;
            return false;
        }

        if (value.Length > limits.MaximumSubjectLength)
        {
            error = SubjectGrammarError.SubjectTooLong;
            return false;
        }

        var tokenCount = 1;
        var tokenLength = 0;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (character == '.')
            {
                if (tokenLength == 0)
                {
                    error = SubjectGrammarError.EmptyToken;
                    return false;
                }

                if (tokenCount >= limits.MaximumTokenCount)
                {
                    error = SubjectGrammarError.TooManyTokens;
                    return false;
                }

                tokenCount++;
                tokenLength = 0;
                continue;
            }

            if (char.IsWhiteSpace(character))
            {
                error = SubjectGrammarError.WhitespaceNotAllowed;
                return false;
            }

            if (char.IsControl(character))
            {
                error = SubjectGrammarError.ControlCharacterNotAllowed;
                return false;
            }

            var characterWidth = 1;
            if (char.IsHighSurrogate(character))
            {
                if (index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1]))
                {
                    error = SubjectGrammarError.InvalidUnicodeScalarSequence;
                    return false;
                }

                characterWidth = 2;
                index++;
            }
            else if (char.IsLowSurrogate(character))
            {
                error = SubjectGrammarError.InvalidUnicodeScalarSequence;
                return false;
            }

            if (tokenLength > limits.MaximumTokenLength - characterWidth)
            {
                error = SubjectGrammarError.TokenTooLong;
                return false;
            }

            tokenLength += characterWidth;
        }

        if (tokenLength == 0)
        {
            error = SubjectGrammarError.EmptyToken;
            return false;
        }

        tokens = value.Split('.');
        error = SubjectGrammarError.None;
        return true;
    }
}

