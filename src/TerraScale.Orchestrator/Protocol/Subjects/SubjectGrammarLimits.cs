namespace TerraScale.Orchestrator.Protocol.Subjects;

public sealed class SubjectGrammarLimits
{
    private SubjectGrammarLimits(
        int maximumSubjectLength,
        int maximumTokenCount,
        int maximumTokenLength,
        int maximumPermissionPatternCount)
    {
        MaximumSubjectLength = maximumSubjectLength;
        MaximumTokenCount = maximumTokenCount;
        MaximumTokenLength = maximumTokenLength;
        MaximumPermissionPatternCount = maximumPermissionPatternCount;
    }

    public int MaximumSubjectLength { get; }

    public int MaximumTokenCount { get; }

    public int MaximumTokenLength { get; }

    public int MaximumPermissionPatternCount { get; }

    public static bool TryCreate(
        int maximumSubjectLength,
        int maximumTokenCount,
        int maximumTokenLength,
        int maximumPermissionPatternCount,
        out SubjectGrammarLimits? result)
    {
        if (maximumSubjectLength <= 0
            || maximumTokenCount <= 0
            || maximumTokenLength <= 0
            || maximumPermissionPatternCount <= 0
            || maximumTokenLength > maximumSubjectLength)
        {
            result = null;
            return false;
        }

        result = new SubjectGrammarLimits(
            maximumSubjectLength,
            maximumTokenCount,
            maximumTokenLength,
            maximumPermissionPatternCount);
        return true;
    }
}

