// Port of tests/TerraScale.Orchestrator.Protocol.Tests/SubjectPatternTests.cs.
package protocol

import "testing"

func TestPermissionPatternsAcceptOnlyWholeTokenWildcards(t *testing.T) {
	for _, value := range []string{"*", ">", "alpha.*.gamma", "alpha.>", "*.beta.>"} {
		pattern, err := SubjectPermissionPatternTryParse(value, defaultTestLimits())
		if err != SubjectGrammarErrorNone {
			t.Fatalf("pattern %q rejected: %v", value, err)
		}

		if pattern.Value() != value {
			t.Fatalf("pattern value = %q", pattern.Value())
		}
	}
}

func TestPermissionPatternsRejectEmbeddedNonterminalAndInjectedWildcards(t *testing.T) {
	malformed := []string{
		"alpha*", "*alpha", "alpha*beta", "alpha>", ">alpha", "alpha>beta",
		"alpha.>.beta", "alpha.>.*", "alpha..*", "alpha.*.", "alpha. >",
		"alpha.*suffix", "alpha.>suffix", "alpha.\x00.*",
	}

	for _, value := range malformed {
		pattern, err := SubjectPermissionPatternTryParse(value, defaultTestLimits())
		if pattern != nil || err == SubjectGrammarErrorNone {
			t.Fatalf("pattern %q accepted", value)
		}
	}
}

func TestLiteralAndSingleTokenMatchingIsCaseSensitiveAndExact(t *testing.T) {
	literal := testPattern("Alpha.beta", defaultTestLimits())
	wildcard := testPattern("alpha.*.gamma", defaultTestLimits())

	if !literal.Matches(testConcreteSubject("Alpha.beta", defaultTestLimits())) {
		t.Fatal("literal must match itself")
	}

	if literal.Matches(testConcreteSubject("alpha.beta", defaultTestLimits())) {
		t.Fatal("literal matching must be case sensitive")
	}

	if literal.Matches(testConcreteSubject("Alpha.beta.extra", defaultTestLimits())) {
		t.Fatal("literal must not match longer subjects")
	}

	if !wildcard.Matches(testConcreteSubject("alpha.beta.gamma", defaultTestLimits())) {
		t.Fatal("wildcard must match one token")
	}

	if wildcard.Matches(testConcreteSubject("alpha.beta.delta", defaultTestLimits())) {
		t.Fatal("wildcard must not match a different literal")
	}

	if wildcard.Matches(testConcreteSubject("alpha.beta.extra.gamma", defaultTestLimits())) {
		t.Fatal("wildcard must not span multiple tokens")
	}

	if wildcard.Matches(nil) {
		t.Fatal("pattern must not match a nil subject")
	}
}

func TestTerminalWildcardMatchesOneOrMoreTokensOnly(t *testing.T) {
	scoped := testPattern("alpha.>", defaultTestLimits())
	all := testPattern(">", defaultTestLimits())

	if scoped.Matches(testConcreteSubject("alpha", defaultTestLimits())) {
		t.Fatal("terminal wildcard requires at least one more token")
	}

	if !scoped.Matches(testConcreteSubject("alpha.beta", defaultTestLimits())) {
		t.Fatal("terminal wildcard must match one token")
	}

	if !scoped.Matches(testConcreteSubject("alpha.beta.gamma", defaultTestLimits())) {
		t.Fatal("terminal wildcard must match many tokens")
	}

	if scoped.Matches(testConcreteSubject("Alpha.beta", defaultTestLimits())) {
		t.Fatal("terminal wildcard matching must be case sensitive")
	}

	if !all.Matches(testConcreteSubject("one", defaultTestLimits())) ||
		!all.Matches(testConcreteSubject("one.two", defaultTestLimits())) {
		t.Fatal("bare terminal wildcard must match everything")
	}
}

func TestMatcherTreatsRegexMetacharactersAsLiteralText(t *testing.T) {
	pattern := testPattern("alpha.[x]+(y).$", defaultTestLimits())

	if !pattern.Matches(testConcreteSubject("alpha.[x]+(y).$", defaultTestLimits())) {
		t.Fatal("metacharacters must match literally")
	}

	if pattern.Matches(testConcreteSubject("alpha.xxy.$", defaultTestLimits())) {
		t.Fatal("metacharacters must not acquire regex meaning")
	}
}
