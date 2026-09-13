using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

internal static class SubjectTestData
{
    public static SubjectGrammarLimits Limits(
        int maximumSubjectLength = 128,
        int maximumTokenCount = 16,
        int maximumTokenLength = 32,
        int maximumPermissionPatternCount = 16)
    {
        SubjectGrammarLimits.TryCreate(
            maximumSubjectLength,
            maximumTokenCount,
            maximumTokenLength,
            maximumPermissionPatternCount,
            out var result);
        return result!;
    }

    public static ConcreteSubject Subject(string value, SubjectGrammarLimits? limits = null)
    {
        ConcreteSubject.TryParse(value, limits ?? Limits(), out var result, out _);
        return result!;
    }

    public static SubjectPermissionPattern Pattern(string value, SubjectGrammarLimits? limits = null)
    {
        SubjectPermissionPattern.TryParse(value, limits ?? Limits(), out var result, out _);
        return result!;
    }
}

