package protocol

import "testing"

// limits mirrors SubjectTestData.Limits.
func testLimits(maximumSubjectLength, maximumTokenCount, maximumTokenLength, maximumPermissionPatternCount int) *SubjectGrammarLimits {
	limits, ok := SubjectGrammarLimitsTryCreate(
		maximumSubjectLength, maximumTokenCount, maximumTokenLength, maximumPermissionPatternCount)
	if !ok {
		panic("test limits are invalid")
	}

	return limits
}

func defaultTestLimits() *SubjectGrammarLimits {
	return testLimits(128, 16, 32, 16)
}

// fuzzLimits mirrors the private Limits() fixture of DeterministicProtocolFuzzTests.
func fuzzLimits() *SubjectGrammarLimits {
	return testLimits(64, 8, 16, 16)
}

func testConcreteSubject(value string, limits *SubjectGrammarLimits) *ConcreteSubject {
	subject, _ := ConcreteSubjectTryParse(value, limits)
	return subject
}

func testPattern(value string, limits *SubjectGrammarLimits) *SubjectPermissionPattern {
	pattern, _ := SubjectPermissionPatternTryParse(value, limits)
	return pattern
}

func TestLimitsAreExplicitAndRejectInvalidValues(t *testing.T) {
	invalid := [][4]int{
		{0, 1, 1, 1},
		{1, 0, 1, 1},
		{1, 1, 0, 1},
		{1, 1, 1, 0},
		{-1, 1, 1, 1},
		{1, -1, 1, 1},
		{1, 1, -1, 1},
		{1, 1, 1, -1},
		{-1 << 31, 1<<31 - 1, 1<<31 - 1, 1<<31 - 1},
		{4, 1, 5, 1},
	}

	for _, values := range invalid {
		limits, ok := SubjectGrammarLimitsTryCreate(values[0], values[1], values[2], values[3])
		if ok || limits != nil {
			t.Fatalf("limits accepted %v", values)
		}
	}

	valid, ok := SubjectGrammarLimitsTryCreate(7, 3, 3, 4)
	if !ok || valid.MaximumSubjectLength != 7 || valid.MaximumTokenCount != 3 ||
		valid.MaximumTokenLength != 3 || valid.MaximumPermissionPatternCount != 4 {
		t.Fatal("valid limits rejected or wrong field values")
	}
}

func TestConcreteSubjectAcceptsExactBoundariesAndPreservesCase(t *testing.T) {
	limits := testLimits(7, 3, 3, 16)

	subject, err := ConcreteSubjectTryParse("Abc.d.e", limits)
	if err != SubjectGrammarErrorNone {
		t.Fatalf("error = %v", err)
	}

	if subject.Value() != "Abc.d.e" || subject.TokenCount() != 3 || subject.String() != "Abc.d.e" {
		t.Fatalf("subject = %v", subject)
	}

	if subject.Equal(testConcreteSubject("abc.d.e", limits)) {
		t.Fatal("subject equality must be case sensitive")
	}
}

func TestConcreteSubjectRejectsFuzzLikeMalformedCorpus(t *testing.T) {
	limits := defaultTestLimits()
	malformed := []string{
		"", ".", "alpha.", ".alpha", "alpha..beta",
		"alpha beta", "alpha\tbeta", "alpha\rbeta", "alpha\nbeta",
		"alpha\x00beta", "alpha\x01beta", "*", ">", "alpha.*", "alpha.>",
		"alpha*beta", "alpha>beta", "alpha.>.beta", " alpha", "alpha ",
		"alpha.\xed\xa0\x80", "alpha.\xed\xb0\x80", "alpha.\xed\xa0\x80x", "alpha.x\xed\xb0\x80",
	}

	for _, value := range malformed {
		subject, err := ConcreteSubjectTryParse(value, limits)
		if subject != nil || err == SubjectGrammarErrorNone {
			t.Fatalf("subject accepted %q", value)
		}
	}
}

func TestConcreteSubjectAcceptsValidUtf8Only(t *testing.T) {
	limits := defaultTestLimits()

	subject, err := ConcreteSubjectTryParse("alpha.\U0001F680", limits)
	if err != SubjectGrammarErrorNone || subject.Value() != "alpha.\U0001F680" {
		t.Fatalf("valid UTF-8 rejected: %v", err)
	}

	for _, malformed := range []string{"\xed\xa0\x80", "\xed\xb0\x80", "x\xed\xa0\x80", "\xed\xb0\x80x"} {
		if _, err := ConcreteSubjectTryParse(malformed, limits); err != SubjectGrammarErrorInvalidUnicodeScalarSequence {
			t.Fatalf("invalid UTF-8 %q must be InvalidUnicodeScalarSequence, got %v", malformed, err)
		}

		if _, err := SubjectPermissionPatternTryParse(malformed, limits); err != SubjectGrammarErrorInvalidUnicodeScalarSequence {
			t.Fatalf("invalid UTF-8 %q must be InvalidUnicodeScalarSequence for patterns, got %v", malformed, err)
		}
	}
}

func TestConcreteSubjectBoundsUseV1UTF16CodeUnits(t *testing.T) {
	if _, err := ConcreteSubjectTryParse("\U0001F680", testLimits(2, 1, 2, 1)); err != SubjectGrammarErrorNone {
		t.Fatalf("non-BMP scalar at the v1 code-unit bound was rejected: %v", err)
	}

	if _, err := ConcreteSubjectTryParse("\U0001F680", testLimits(1, 1, 1, 1)); err != SubjectGrammarErrorSubjectTooLong {
		t.Fatalf("subject bound error = %v", err)
	}

	if _, err := ConcreteSubjectTryParse("\U0001F680", testLimits(2, 1, 1, 1)); err != SubjectGrammarErrorTokenTooLong {
		t.Fatalf("token bound error = %v", err)
	}
}

func TestConcreteSubjectLimitFailuresAreTypedAndDeterministic(t *testing.T) {
	lengthLimits := testLimits(5, 16, 5, 16)
	tokenCountLimits := testLimits(128, 2, 32, 16)
	tokenLengthLimits := testLimits(20, 16, 3, 16)

	if _, err := ConcreteSubjectTryParse("abcdef", lengthLimits); err != SubjectGrammarErrorSubjectTooLong {
		t.Fatalf("error = %v", err)
	}

	if _, err := ConcreteSubjectTryParse("a.b.c", tokenCountLimits); err != SubjectGrammarErrorTooManyTokens {
		t.Fatalf("error = %v", err)
	}

	if _, err := ConcreteSubjectTryParse("abcd.x", tokenLengthLimits); err != SubjectGrammarErrorTokenTooLong {
		t.Fatalf("error = %v", err)
	}

	if _, err := ConcreteSubjectTryParse("a..b", defaultTestLimits()); err != SubjectGrammarErrorEmptyToken {
		t.Fatalf("error = %v", err)
	}
}

func TestParserRejectsMissingLimitPolicy(t *testing.T) {
	if _, err := ConcreteSubjectTryParse("alpha.beta", nil); err != SubjectGrammarErrorInvalidLimits {
		t.Fatalf("subject error = %v", err)
	}

	if _, err := SubjectPermissionPatternTryParse("alpha.*", nil); err != SubjectGrammarErrorInvalidLimits {
		t.Fatalf("pattern error = %v", err)
	}
}
