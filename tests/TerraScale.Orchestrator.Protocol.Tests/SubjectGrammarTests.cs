using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class SubjectGrammarTests
{
    [Test]
    public async Task Limits_are_explicit_and_reject_invalid_values()
    {
        var invalid = new[]
        {
            (0, 1, 1, 1),
            (1, 0, 1, 1),
            (1, 1, 0, 1),
            (1, 1, 1, 0),
            (-1, 1, 1, 1),
            (1, -1, 1, 1),
            (1, 1, -1, 1),
            (1, 1, 1, -1),
            (int.MinValue, int.MaxValue, int.MaxValue, int.MaxValue),
            (4, 1, 5, 1),
        };

        foreach (var (length, tokenCount, tokenLength, patternCount) in invalid)
        {
            await Assert.That(SubjectGrammarLimits.TryCreate(
                length, tokenCount, tokenLength, patternCount, out var limits)).IsFalse();
            await Assert.That(limits).IsNull();
        }

        await Assert.That(SubjectGrammarLimits.TryCreate(7, 3, 3, 4, out var valid)).IsTrue();
        await Assert.That(valid!.MaximumSubjectLength).IsEqualTo(7);
        await Assert.That(valid.MaximumTokenCount).IsEqualTo(3);
        await Assert.That(valid.MaximumTokenLength).IsEqualTo(3);
        await Assert.That(valid.MaximumPermissionPatternCount).IsEqualTo(4);
    }

    [Test]
    public async Task Concrete_subject_accepts_exact_boundaries_and_preserves_case()
    {
        var limits = SubjectTestData.Limits(
            maximumSubjectLength: 7,
            maximumTokenCount: 3,
            maximumTokenLength: 3);

        await Assert.That(ConcreteSubject.TryParse("Abc.d.e", limits, out var subject, out var error)).IsTrue();
        await Assert.That(error).IsEqualTo(SubjectGrammarError.None);
        await Assert.That(subject!.Value).IsEqualTo("Abc.d.e");
        await Assert.That(subject.TokenCount).IsEqualTo(3);
        await Assert.That(subject.ToString()).IsEqualTo("Abc.d.e");
        await Assert.That(subject).IsNotEqualTo(SubjectTestData.Subject("abc.d.e", limits));
    }

    [Test]
    public async Task Concrete_subject_rejects_fuzz_like_malformed_corpus()
    {
        var limits = SubjectTestData.Limits();
        string?[] malformed =
        [
            null, "", ".", "alpha.", ".alpha", "alpha..beta",
            "alpha beta", "alpha\tbeta", "alpha\rbeta", "alpha\nbeta",
            "alpha\0beta", "alpha\u0001beta", "*", ">", "alpha.*", "alpha.>",
            "alpha*beta", "alpha>beta", "alpha.>.beta", " alpha", "alpha ",
            "alpha.\uD800", "alpha.\uDC00", "alpha.\uD800x", "alpha.x\uDC00",
        ];

        foreach (var value in malformed)
        {
            await Assert.That(ConcreteSubject.TryParse(value, limits, out var subject, out var error)).IsFalse();
            await Assert.That(subject).IsNull();
            await Assert.That(error).IsNotEqualTo(SubjectGrammarError.None);
        }
    }

    [Test]
    public async Task Concrete_subject_accepts_well_formed_surrogate_pairs_only()
    {
        var limits = SubjectTestData.Limits();

        await Assert.That(ConcreteSubject.TryParse("alpha.\U0001F680", limits, out var subject, out var error)).IsTrue();
        await Assert.That(error).IsEqualTo(SubjectGrammarError.None);
        await Assert.That(subject!.Value).IsEqualTo("alpha.\U0001F680");

        foreach (var malformed in new[] { "\uD800", "\uDC00", "x\uD800", "\uDC00x" })
        {
            await Assert.That(ConcreteSubject.TryParse(malformed, limits, out _, out var malformedError)).IsFalse();
            await Assert.That(malformedError).IsEqualTo(SubjectGrammarError.InvalidUnicodeScalarSequence);
            await Assert.That(SubjectPermissionPattern.TryParse(malformed, limits, out _, out var patternError)).IsFalse();
            await Assert.That(patternError).IsEqualTo(SubjectGrammarError.InvalidUnicodeScalarSequence);
        }
    }

    [Test]
    public async Task Concrete_subject_limit_failures_are_typed_and_deterministic()
    {
        var lengthLimits = SubjectTestData.Limits(maximumSubjectLength: 5, maximumTokenLength: 5);
        var tokenCountLimits = SubjectTestData.Limits(maximumTokenCount: 2);
        var tokenLengthLimits = SubjectTestData.Limits(maximumSubjectLength: 20, maximumTokenLength: 3);

        await Assert.That(ConcreteSubject.TryParse("abcdef", lengthLimits, out _, out var lengthError)).IsFalse();
        await Assert.That(lengthError).IsEqualTo(SubjectGrammarError.SubjectTooLong);
        await Assert.That(ConcreteSubject.TryParse("a.b.c", tokenCountLimits, out _, out var countError)).IsFalse();
        await Assert.That(countError).IsEqualTo(SubjectGrammarError.TooManyTokens);
        await Assert.That(ConcreteSubject.TryParse("abcd.x", tokenLengthLimits, out _, out var tokenError)).IsFalse();
        await Assert.That(tokenError).IsEqualTo(SubjectGrammarError.TokenTooLong);
        await Assert.That(ConcreteSubject.TryParse("a..b", SubjectTestData.Limits(), out _, out var emptyError)).IsFalse();
        await Assert.That(emptyError).IsEqualTo(SubjectGrammarError.EmptyToken);
    }

    [Test]
    public async Task Parser_rejects_missing_limit_policy()
    {
        await Assert.That(ConcreteSubject.TryParse("alpha.beta", null, out _, out var subjectError)).IsFalse();
        await Assert.That(subjectError).IsEqualTo(SubjectGrammarError.InvalidLimits);
        await Assert.That(SubjectPermissionPattern.TryParse("alpha.*", null, out _, out var patternError)).IsFalse();
        await Assert.That(patternError).IsEqualTo(SubjectGrammarError.InvalidLimits);
    }
}

