using TerraScale.Orchestrator.Protocol.Subjects;

namespace TerraScale.Orchestrator.Protocol.Tests;

public class SubjectPatternTests
{
    [Test]
    public async Task Permission_patterns_accept_only_whole_token_wildcards()
    {
        foreach (var value in new[] { "*", ">", "alpha.*.gamma", "alpha.>", "*.beta.>" })
        {
            await Assert.That(SubjectPermissionPattern.TryParse(
                value, SubjectTestData.Limits(), out var pattern, out var error)).IsTrue();
            await Assert.That(error).IsEqualTo(SubjectGrammarError.None);
            await Assert.That(pattern!.Value).IsEqualTo(value);
        }
    }

    [Test]
    public async Task Permission_patterns_reject_embedded_nonterminal_and_injected_wildcards()
    {
        var malformed = new[]
        {
            "alpha*", "*alpha", "alpha*beta", "alpha>", ">alpha", "alpha>beta",
            "alpha.>.beta", "alpha.>.*", "alpha..*", "alpha.*.", "alpha. >",
            "alpha.*suffix", "alpha.>suffix", "alpha.\0.*",
        };

        foreach (var value in malformed)
        {
            await Assert.That(SubjectPermissionPattern.TryParse(
                value, SubjectTestData.Limits(), out var pattern, out var error)).IsFalse();
            await Assert.That(pattern).IsNull();
            await Assert.That(error).IsNotEqualTo(SubjectGrammarError.None);
        }
    }

    [Test]
    public async Task Literal_and_single_token_matching_is_case_sensitive_and_exact()
    {
        var literal = SubjectTestData.Pattern("Alpha.beta");
        var wildcard = SubjectTestData.Pattern("alpha.*.gamma");

        await Assert.That(literal.Matches(SubjectTestData.Subject("Alpha.beta"))).IsTrue();
        await Assert.That(literal.Matches(SubjectTestData.Subject("alpha.beta"))).IsFalse();
        await Assert.That(literal.Matches(SubjectTestData.Subject("Alpha.beta.extra"))).IsFalse();
        await Assert.That(wildcard.Matches(SubjectTestData.Subject("alpha.beta.gamma"))).IsTrue();
        await Assert.That(wildcard.Matches(SubjectTestData.Subject("alpha.beta.delta"))).IsFalse();
        await Assert.That(wildcard.Matches(SubjectTestData.Subject("alpha.beta.extra.gamma"))).IsFalse();
        await Assert.That(wildcard.Matches(null)).IsFalse();
    }

    [Test]
    public async Task Terminal_wildcard_matches_one_or_more_tokens_only()
    {
        var scoped = SubjectTestData.Pattern("alpha.>");
        var all = SubjectTestData.Pattern(">");

        await Assert.That(scoped.Matches(SubjectTestData.Subject("alpha"))).IsFalse();
        await Assert.That(scoped.Matches(SubjectTestData.Subject("alpha.beta"))).IsTrue();
        await Assert.That(scoped.Matches(SubjectTestData.Subject("alpha.beta.gamma"))).IsTrue();
        await Assert.That(scoped.Matches(SubjectTestData.Subject("Alpha.beta"))).IsFalse();
        await Assert.That(all.Matches(SubjectTestData.Subject("one"))).IsTrue();
        await Assert.That(all.Matches(SubjectTestData.Subject("one.two"))).IsTrue();
    }

    [Test]
    public async Task Matcher_treats_regex_metacharacters_as_literal_text()
    {
        var pattern = SubjectTestData.Pattern("alpha.[x]+(y).$");

        await Assert.That(pattern.Matches(SubjectTestData.Subject("alpha.[x]+(y).$"))).IsTrue();
        await Assert.That(pattern.Matches(SubjectTestData.Subject("alpha.xxy.$"))).IsFalse();
    }
}

