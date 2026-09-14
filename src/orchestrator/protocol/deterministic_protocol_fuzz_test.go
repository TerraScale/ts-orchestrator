// Port of tests/TerraScale.Orchestrator.Protocol.Tests/Fuzz/DeterministicProtocolFuzzTests.cs.
// The .NET iterator-fault fixtures and the reflection-based
// PublicParserAndValidatorInventory test are skipped (no Go equivalent); every
// deterministic property loop is ported. Culture-independence loops are
// dropped because Go formatting is culture-free by construction.
package protocol

import (
	"strconv"
	"testing"
	"time"
)

const casesPerFamily = 10000

type deterministicGenerator struct {
	state uint64
}

func (g *deterministicGenerator) next() uint64 {
	g.state += 0x9E3779B97F4A7C15
	value := g.state
	value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9
	value = (value ^ (value >> 27)) * 0x94D049BB133111EB
	return value ^ (value >> 31)
}

func (g *deterministicGenerator) nextInt(exclusiveMaximum int) int {
	return int(g.next() % uint64(exclusiveMaximum))
}

func (g *deterministicGenerator) fill(destination []byte) {
	for index := range destination {
		destination[index] = byte(g.next())
	}
}

type fuzzSummary struct {
	cases     int
	accepted  int
	rejected  int
	diversity int
	digest    uint64
}

type subjectSummary struct {
	subjectCases    int
	patternCases    int
	subjectAccepted int
	subjectRejected int
	patternAccepted int
	patternRejected int
	subjectErrors   int
	patternErrors   int
	digest          uint64
}

type policySummary struct {
	cases    int
	accepted int
	rejected int
	reasons  int
	digest   uint64
}

type envelopeSummary struct {
	cases    int
	accepted int
	rejected int
	errors   int
	digest   uint64
}

type decisionSummary struct {
	cases   int
	allowed int
	denied  int
	reasons int
	digest  uint64
}

func fuzzMix(digest uint64, value int64) uint64 {
	return (digest^uint64(value))*1099511628211 + 1469598103934665603
}

func fuzzRequire(condition bool, family string, seed int64, t *testing.T) {
	t.Helper()
	if !condition {
		t.Fatalf("Deterministic fuzz invariant failed: %s, seed %d.", family, seed)
	}
}

func TestNumericAndOpaqueFactoriesRunTenThousandDeterministicBoundedCasesPerFamily(t *testing.T) {
	numericFirst := runNumericFuzz(0x11C0FFEE)
	numericReplay := runNumericFuzz(0x11C0FFEE)
	opaqueFirst := runOpaqueFuzz(0x22C0FFEE)
	opaqueReplay := runOpaqueFuzz(0x22C0FFEE)

	if numericFirst != numericReplay || opaqueFirst != opaqueReplay {
		t.Fatal("fuzz runs must be deterministic")
	}

	if numericFirst.cases != casesPerFamily || numericFirst.accepted == 0 || numericFirst.rejected == 0 ||
		numericFirst.diversity <= 5000 {
		t.Fatalf("numeric summary = %+v", numericFirst)
	}

	if opaqueFirst.cases != casesPerFamily || opaqueFirst.accepted == 0 || opaqueFirst.rejected == 0 ||
		opaqueFirst.diversity <= 9000 {
		t.Fatalf("opaque summary = %+v", opaqueFirst)
	}
}

func runNumericFuzz(seed uint64) fuzzSummary {
	generator := &deterministicGenerator{state: seed}
	accepted, rejected := 0, 0
	digest := uint64(0)
	values := map[int64]struct{}{}
	for index := 0; index < casesPerFamily; index++ {
		// Fidelity note: the C# source writes `index % 7 switch { 0 => 0, ... }`,
		// which C# binds as `index % (7 switch { ... })` — the switch input is the
		// constant 7, which always falls to the `_` arm. The value is therefore
		// index modulo one huge generator draw, which equals index for this range;
		// the `_` arm (and only it) advances the generator every iteration. The
		// port reproduces that behavior exactly, including the digest.
		divisor := int64(generator.next()&uint64(1<<63-1)) + 1
		value := int64(index) % divisor

		expected := value > 0
		protocolRevision, protocolOk := ProtocolRevisionTryCreate(value)
		generation, generationOk := DesiredGenerationTryCreate(value)
		epoch, epochOk := WriterEpochTryCreate(value)
		attempt, attemptOk := DeliveryAttemptTryCreate(value)
		results := []bool{protocolOk, generationOk, epochOk, attemptOk}
		for _, result := range results {
			if result != expected {
				return fuzzSummary{}
			}
		}

		if !expected {
			if protocolRevision.IsValid() || generation.IsValid() || epoch.IsValid() || attempt.IsValid() {
				return fuzzSummary{}
			}
		} else if protocolRevision.Value != value || generation.Value != value || epoch.Value != value || attempt.Value != value {
			return fuzzSummary{}
		}

		if expected {
			accepted++
		} else {
			rejected++
		}

		values[value] = struct{}{}
		if expected {
			digest = fuzzMix(digest, value)
		} else {
			digest = fuzzMix(digest, int64(index))
		}
	}

	return fuzzSummary{cases: casesPerFamily, accepted: accepted, rejected: rejected, diversity: len(values), digest: digest}
}

func runOpaqueFuzz(seed uint64) fuzzSummary {
	generator := &deterministicGenerator{state: seed}
	accepted, rejected := 0, 0
	digest := uint64(0)
	shapes := map[[3]int]struct{}{}
	for index := 0; index < casesPerFamily; index++ {
		length := index % 257
		source := make([]byte, length)
		generator.fill(source)
		original := append([]byte(nil), source...)
		payload := OpaquePayloadCopyFrom(source)
		payloadDigest, digestOk := PayloadDigestTryCopyFrom(source)
		signature, signatureOk := OpaqueSignatureTryCopyFrom(source)
		if length > 0 {
			source[0] ^= 0xff
		}

		if !payloadDigestIsValid(payload, original) {
			return fuzzSummary{}
		}

		if digestOk != (length > 0) || signatureOk != (length > 0) {
			return fuzzSummary{}
		}

		if payload.String() != "<opaque-payload>" ||
			(digestOk && payloadDigest.String() != "<payload-digest>") ||
			(signatureOk && signature.String() != "<opaque-signature>") {
			return fuzzSummary{}
		}

		if length > 1 {
			truncated := OpaquePayloadCopyFrom(original[:length-1])
			extended := OpaquePayloadCopyFrom(append(append([]byte(nil), original...), 0))
			if payload.Equal(truncated) || payload.Equal(extended) {
				return fuzzSummary{}
			}
		}

		if digestOk {
			accepted++
		} else {
			rejected++
		}

		first, last := 0, 0
		if length > 0 {
			first = int(original[0])
			last = int(original[length-1])
		}

		shapes[[3]int{length, first, last}] = struct{}{}
		if length == 0 {
			digest = fuzzMix(digest, 0)
		} else {
			digest = fuzzMix(digest, int64(first+length))
		}
	}

	return fuzzSummary{cases: casesPerFamily, accepted: accepted, rejected: rejected, diversity: len(shapes), digest: digest}
}

func payloadDigestIsValid(payload OpaquePayload, original []byte) bool {
	if len(payload.Bytes()) != len(original) {
		return false
	}

	for index := range original {
		if payload.Bytes()[index] != original[index] {
			return false
		}
	}

	return true
}

func TestSubjectAndPatternParsersRunTenThousandDeterministicCases(t *testing.T) {
	first := runSubjectFuzz(0x33C0FFEE)
	replay := runSubjectFuzz(0x33C0FFEE)
	if first != replay {
		t.Fatal("subject fuzz must be deterministic")
	}

	if first.subjectCases != casesPerFamily || first.patternCases != casesPerFamily ||
		first.subjectAccepted <= 1000 || first.subjectRejected <= 1000 ||
		first.patternAccepted <= 1000 || first.patternRejected <= 1000 ||
		first.subjectErrors != 6 || first.patternErrors != 5 {
		t.Fatalf("subject summary = %+v", first)
	}
}

func runSubjectFuzz(seed uint64) subjectSummary {
	generator := &deterministicGenerator{state: seed}
	limits := fuzzLimits()
	subjectAccepted, subjectRejected := 0, 0
	patternAccepted, patternRejected := 0, 0
	subjectErrors := map[SubjectGrammarError]struct{}{}
	patternErrors := map[SubjectGrammarError]struct{}{}
	digest := uint64(0)
	for index := 0; index < casesPerFamily; index++ {
		token := "a" + strconv.Itoa(generator.nextInt(1000))
		var subjectText string
		var expectedSubjectError SubjectGrammarError
		switch index % 8 {
		case 0:
			subjectText = token + ".b"
			expectedSubjectError = SubjectGrammarErrorNone
		case 1:
			subjectText = token + ".*"
			expectedSubjectError = SubjectGrammarErrorWildcardNotAllowed
		case 2:
			subjectText = "a..b"
			expectedSubjectError = SubjectGrammarErrorEmptyToken
		case 3:
			subjectText = string(bytesOf('x', 65))
			expectedSubjectError = SubjectGrammarErrorSubjectTooLong
		case 4:
			subjectText = "a. b"
			expectedSubjectError = SubjectGrammarErrorWhitespaceNotAllowed
		case 5:
			subjectText = "a.\xed\xa0\x80"
			expectedSubjectError = SubjectGrammarErrorInvalidUnicodeScalarSequence
		case 6:
			subjectText = "alpha.\U0001F680"
			expectedSubjectError = SubjectGrammarErrorNone
		default:
			subjectText = string(bytesOf('x', 16)) + ".z"
			expectedSubjectError = SubjectGrammarErrorNone
		}

		subject, subjectError := ConcreteSubjectTryParse(subjectText, limits)
		replaySubject, replayError := ConcreteSubjectTryParse(subjectText, limits)
		if subjectError != replayError || subjectError != expectedSubjectError ||
			(subject != nil) != (replaySubject != nil) ||
			(subject != nil && !subject.Equal(replaySubject)) {
			return subjectSummary{}
		}

		if subject != nil {
			subjectAccepted++
		} else {
			subjectRejected++
		}

		subjectErrors[subjectError] = struct{}{}

		var patternText string
		var expectedPatternError SubjectGrammarError
		switch index % 8 {
		case 0:
			patternText = token + ".*"
			expectedPatternError = SubjectGrammarErrorNone
		case 1:
			patternText = token + ".>"
			expectedPatternError = SubjectGrammarErrorNone
		case 2:
			patternText = "a.>.b"
			expectedPatternError = SubjectGrammarErrorTerminalWildcardMustBeFinal
		case 3:
			patternText = "a.**"
			expectedPatternError = SubjectGrammarErrorInvalidWildcard
		case 4:
			patternText = "a..b"
			expectedPatternError = SubjectGrammarErrorEmptyToken
		case 5:
			patternText = string(bytesOf('x', 65))
			expectedPatternError = SubjectGrammarErrorSubjectTooLong
		case 6:
			patternText = "alpha.\U0001F680"
			expectedPatternError = SubjectGrammarErrorNone
		default:
			patternText = ">"
			expectedPatternError = SubjectGrammarErrorNone
		}

		pattern, patternError := SubjectPermissionPatternTryParse(patternText, limits)
		replayPattern, replayPatternError := SubjectPermissionPatternTryParse(patternText, limits)
		if patternError != replayPatternError || patternError != expectedPatternError ||
			(pattern != nil) != (replayPattern != nil) ||
			(pattern != nil && !pattern.Equal(replayPattern)) {
			return subjectSummary{}
		}

		if pattern != nil {
			if pattern.Matches(nil) {
				return subjectSummary{}
			}

			patternAccepted++
		} else {
			patternRejected++
		}

		patternErrors[patternError] = struct{}{}
		digest = fuzzMix(digest, int64(subjectError)<<16|int64(patternError))
	}

	return subjectSummary{
		subjectCases: casesPerFamily, patternCases: casesPerFamily,
		subjectAccepted: subjectAccepted, subjectRejected: subjectRejected,
		patternAccepted: patternAccepted, patternRejected: patternRejected,
		subjectErrors: len(subjectErrors), patternErrors: len(patternErrors), digest: digest,
	}
}

func bytesOf(fill byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = fill
	}

	return result
}

func TestLimitAndPermissionPolicyValidatorsRunTenThousandPermutationStableCases(t *testing.T) {
	first := runPolicyFuzz(0x44C0FFEE)
	replay := runPolicyFuzz(0x44C0FFEE)
	if first != replay {
		t.Fatal("policy fuzz must be deterministic")
	}

	if first.cases != casesPerFamily || first.accepted <= 1000 || first.rejected <= 1000 || first.reasons != 5 {
		t.Fatalf("policy summary = %+v", first)
	}
}

func runPolicyFuzz(seed uint64) policySummary {
	generator := &deterministicGenerator{state: seed}
	accepted, rejected := 0, 0
	digest := uint64(0)
	reasons := map[SubjectPermissionPolicyError]struct{}{}
	for index := 0; index < casesPerFamily; index++ {
		maxSubject := generator.nextInt(80) + 1
		maxToken := generator.nextInt(20) + 1
		tokenLimit := maxToken
		if index%9 == 0 {
			tokenLimit = maxSubject + 1
		}

		shouldCreateLimits := tokenLimit <= maxSubject
		limits, limitsOk := SubjectGrammarLimitsTryCreate(maxSubject, 8, tokenLimit, 3)
		if limitsOk != shouldCreateLimits {
			return policySummary{}
		}

		if !limitsOk {
			rejected++
			digest = fuzzMix(digest, int64(index))
			continue
		}

		fixed := fuzzLimits()
		alpha := testPattern("alpha"+strconv.Itoa(index%10)+".*", fixed)
		beta := testPattern("beta.*", fixed)
		blocked := testPattern("blocked.>", fixed)
		var allow []*SubjectPermissionPattern
		var deny []*SubjectPermissionPattern
		var expectedError SubjectPermissionPolicyError
		switch index % 5 {
		case 0:
			allow = []*SubjectPermissionPattern{alpha, beta}
			deny = []*SubjectPermissionPattern{blocked}
			expectedError = SubjectPermissionPolicyErrorNone
		case 1:
			allow = []*SubjectPermissionPattern{alpha, alpha}
			expectedError = SubjectPermissionPolicyErrorDuplicatePattern
		case 2:
			allow = []*SubjectPermissionPattern{alpha}
			deny = []*SubjectPermissionPattern{alpha}
			expectedError = SubjectPermissionPolicyErrorPatternInAllowAndDeny
		case 3:
			allow = []*SubjectPermissionPattern{alpha, beta, blocked}
			deny = []*SubjectPermissionPattern{testPattern("extra.*", fixed)}
			expectedError = SubjectPermissionPolicyErrorTooManyPatterns
		default:
			allow = []*SubjectPermissionPattern{alpha, nil}
			expectedError = SubjectPermissionPolicyErrorNullPattern
		}

		policy, policyError := SubjectPermissionPolicyTryCreate(allow, deny, limits)
		replayPolicy, replayError := SubjectPermissionPolicyTryCreate(reversedPatterns(allow), reversedPatterns(deny), limits)
		if policyError != replayError || policyError != expectedError ||
			(policyError == SubjectPermissionPolicyErrorNone) != (policy != nil) {
			return policySummary{}
		}

		reasons[policyError] = struct{}{}
		if policy != nil {
			if !patternsEqual(policy.AllowPatterns(), replayPolicy.AllowPatterns()) ||
				!patternsEqual(policy.DenyPatterns(), replayPolicy.DenyPatterns()) {
				return policySummary{}
			}

			allowed := testConcreteSubject("alpha"+strconv.Itoa(index%10)+".one", fixed)
			if policy.Authorize(allowed).Reason != SubjectPermissionReasonAllowedByPattern ||
				policy.Authorize(testConcreteSubject("blocked.one", fixed)).Reason != SubjectPermissionReasonDeniedByPattern ||
				policy.Authorize(nil).IsAllowed() {
				return policySummary{}
			}

			accepted++
		} else {
			rejected++
		}

		digest = fuzzMix(digest, int64(policyError))
	}

	return policySummary{cases: casesPerFamily, accepted: accepted, rejected: rejected, reasons: len(reasons), digest: digest}
}

func reversedPatterns(patterns []*SubjectPermissionPattern) []*SubjectPermissionPattern {
	reversed := make([]*SubjectPermissionPattern, len(patterns))
	for index, pattern := range patterns {
		reversed[len(patterns)-1-index] = pattern
	}

	return reversed
}

func patternsEqual(left, right []*SubjectPermissionPattern) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if !left[index].Equal(right[index]) {
			return false
		}
	}

	return true
}

func TestEnvelopeValidatorRunsTenThousandCasesFailClosedAndSecretSafe(t *testing.T) {
	first := runEnvelopeFuzz(0x55C0FFEE)
	replay := runEnvelopeFuzz(0x55C0FFEE)
	if first != replay {
		t.Fatal("envelope fuzz must be deterministic")
	}

	if first.cases != casesPerFamily || first.accepted == 0 || first.rejected <= 5000 || first.errors != 15 {
		t.Fatalf("envelope summary = %+v", first)
	}
}

func runEnvelopeFuzz(seed uint64) envelopeSummary {
	generator := &deterministicGenerator{state: seed}
	accepted, rejected := 0, 0
	digest := uint64(0)
	errors := map[CommandValidationError]struct{}{}
	for index := 0; index < casesPerFamily; index++ {
		category := index % 15
		envelope := validEnvelope()
		context := validContext()
		expected := CommandValidationErrorNone
		switch category {
		case 1:
			envelope = CommandEnvelope{}
			expected = CommandValidationErrorMalformedEnvelope
		case 2:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(3)) })
			expected = CommandValidationErrorUnsupportedProtocolVersion
		case 3:
			envelope = validEnvelope(
				func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(time.Minute)) },
				func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-time.Minute)) })
			expected = CommandValidationErrorInvalidValidityWindow
		case 4:
			envelope = validEnvelope(
				func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(3 * time.Minute)) },
				func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(4 * time.Minute)) })
			expected = CommandValidationErrorNotYetValid
		case 5:
			envelope = validEnvelope(
				func(o *validEnvelopeOption) { o.issuedAt = ptrOf(protocolNow.Add(-4 * time.Minute)) },
				func(o *validEnvelopeOption) { o.expiresAt = ptrOf(protocolNow.Add(-3 * time.Minute)) })
			expected = CommandValidationErrorExpired
		case 6:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.cell = ptrOf(testCell("sfo")) })
			expected = CommandValidationErrorWrongCell
		case 7:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.aggregate = ptrOf(testAggregate("allocation/other")) })
			expected = CommandValidationErrorWrongAggregateIdentity
		case 8:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.generation = ptrOf(testGeneration(9)) })
			expected = CommandValidationErrorStaleGeneration
		case 9:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.epoch = ptrOf(testEpoch(6)) })
			expected = CommandValidationErrorStaleWriterEpoch
		case 10:
			envelope = validEnvelope(func(o *validEnvelopeOption) { o.payload = ptrOf(OpaquePayloadCopyFrom([]byte{1, 2, 3})) })
			expected = CommandValidationErrorPayloadDigestMismatch
		case 11:
			context = validContext(func(o *validContextOption) { o.signatureVerifier = newTestSignatureVerifier(false, false) })
			expected = CommandValidationErrorInvalidSignature
		case 12:
			context = validContext(func(o *validContextOption) {
				o.digestVerifier = outcomeDigestVerifier{outcome: VerificationOutcome(7)}
			})
			expected = CommandValidationErrorPayloadDigestVerificationFailed
		case 13:
			context = validContext(func(o *validContextOption) {
				o.signatureVerifier = outcomeSignatureVerifier{outcome: VerificationOutcome(7)}
			})
			expected = CommandValidationErrorSignatureVerificationFailed
		case 14:
			context = nil
			expected = CommandValidationErrorInvalidValidationContext
		}

		now := protocolNow.Add(time.Duration(generator.nextInt(3)-1) * 100)
		result := CommandEnvelopeValidator.Validate(&envelope, context, now)
		replay := CommandEnvelopeValidator.Validate(&envelope, context, now)
		if !result.Equal(replay) || result.Error != expected ||
			result.IsValid() != (expected == CommandValidationErrorNone) {
			return envelopeSummary{}
		}

		if (result.Acceptance != nil) != result.IsValid() {
			return envelopeSummary{}
		}

		if result.IsValid() {
			accepted++
		} else {
			rejected++
		}

		errors[result.Error] = struct{}{}
		digest = fuzzMix(digest, int64(result.Error))
	}

	return envelopeSummary{cases: casesPerFamily, accepted: accepted, rejected: rejected, errors: len(errors), digest: digest}
}

func TestPatternMatchingAndAuthorizationRunTenThousandExactDecisionCases(t *testing.T) {
	first := runDecisionFuzz(0x66C0FFEE)
	replay := runDecisionFuzz(0x66C0FFEE)
	if first != replay {
		t.Fatal("decision fuzz must be deterministic")
	}

	if first.cases != casesPerFamily || first.allowed <= 1000 || first.denied <= 1000 || first.reasons != 5 {
		t.Fatalf("decision summary = %+v", first)
	}
}

func runDecisionFuzz(seed uint64) decisionSummary {
	generator := &deterministicGenerator{state: seed}
	allowed, denied := 0, 0
	digest := uint64(0)
	reasons := map[SubjectPermissionReason]struct{}{}
	limits := fuzzLimits()
	for index := 0; index < casesPerFamily; index++ {
		suffix := strconv.Itoa(generator.nextInt(1000))
		category := index % 7
		var pattern *SubjectPermissionPattern
		switch category {
		case 0:
			pattern = testPattern("alpha"+suffix+".value", limits)
		case 1:
			pattern = testPattern("alpha"+suffix+".*", limits)
		case 2:
			pattern = testPattern("alpha"+suffix+".>", limits)
		default:
			pattern = testPattern("other"+suffix+".*", limits)
		}

		var subjectText string
		switch category {
		case 0, 1:
			subjectText = "alpha" + suffix + ".value"
		case 2:
			subjectText = "alpha" + suffix + ".one.two"
		default:
			subjectText = "alpha" + suffix + ".value"
		}

		subject := testConcreteSubject(subjectText, limits)
		expectedMatch := category == 0 || category == 1 || category == 2
		if pattern.Matches(subject) != expectedMatch {
			return decisionSummary{}
		}

		var allow []*SubjectPermissionPattern
		var deny []*SubjectPermissionPattern
		switch category {
		case 3:
			allow = []*SubjectPermissionPattern{testPattern(">", limits)}
			deny = []*SubjectPermissionPattern{testPattern("alpha"+suffix+".>", limits)}
		case 4:
			allow = nil
		case 5:
			allow = []*SubjectPermissionPattern{testPattern("other"+suffix+".>", limits)}
		default:
			allow = []*SubjectPermissionPattern{testPattern("alpha"+suffix+".>", limits)}
		}

		policy, err := SubjectPermissionPolicyTryCreate(allow, deny, limits)
		if err != SubjectPermissionPolicyErrorNone {
			return decisionSummary{}
		}

		var target *ConcreteSubject
		if category != 6 {
			target = subject
		}

		decision := policy.Authorize(target)
		var expectedReason SubjectPermissionReason
		switch category {
		case 0, 1, 2:
			expectedReason = SubjectPermissionReasonAllowedByPattern
		case 3:
			expectedReason = SubjectPermissionReasonDeniedByPattern
		case 4:
			expectedReason = SubjectPermissionReasonDeniedEmptyAllowSet
		case 5:
			expectedReason = SubjectPermissionReasonDeniedNoAllowMatch
		default:
			expectedReason = SubjectPermissionReasonDeniedInvalidSubject
		}

		if decision.Reason != expectedReason ||
			decision.IsAllowed() != (expectedReason == SubjectPermissionReasonAllowedByPattern) {
			return decisionSummary{}
		}

		reasons[decision.Reason] = struct{}{}
		if decision.IsAllowed() {
			allowed++
		} else {
			denied++
		}

		digest = fuzzMix(digest, int64(decision.Reason))
	}

	return decisionSummary{cases: casesPerFamily, allowed: allowed, denied: denied, reasons: len(reasons), digest: digest}
}

func TestEmbeddedRegressionCorpusIsBoundedContentAddressedAndReplayable(t *testing.T) {
	loaded := protocolRegressionCorpusLoadEmbedded()
	if loaded.Code != CorpusLoadAccepted {
		t.Fatalf("load code = %v", loaded.Code)
	}

	if len(loaded.Entries) != 3 {
		t.Fatalf("entry count = %d", len(loaded.Entries))
	}

	for _, entry := range loaded.Entries {
		if protocolRegressionCorpusDigest(entry) != entry.Digest {
			t.Fatal("corpus digest mismatch")
		}

		replayCorpusEntry(t, entry)
	}

	collisionLeft := ProtocolCorpusEntry{Family: "family", Seed: 1, Input: "a|expected=b", Expected: "c",
		Digest: string(bytesOf('0', 64))}
	collisionRight := ProtocolCorpusEntry{Family: "family", Seed: 1, Input: "a", Expected: "b|expected=c",
		Digest: string(bytesOf('0', 64))}
	if protocolRegressionCorpusCanonical(collisionLeft) == protocolRegressionCorpusCanonical(collisionRight) {
		t.Fatal("canonical form must be collision free")
	}

	source := `{"version":1,"entries":[]}`
	if protocolRegressionCorpusLoadString(replaceFirst(source, `"entries"`, `"unknown"`)).Code != CorpusLoadInvalidSchema {
		t.Fatal("unknown member must be InvalidSchema")
	}

	if protocolRegressionCorpusLoadString(replaceFirst(source, `"version":1`, `"version":2`)).Code != CorpusLoadInvalidSchema {
		t.Fatal("wrong version must be InvalidSchema")
	}

	if protocolRegressionCorpusLoadString(`{"version":1,"version":1,"entries":[]}`).Code != CorpusLoadInvalidSchema {
		t.Fatal("duplicate version member must be InvalidSchema")
	}

	repeated := ""
	for index := 0; index < 65; index++ {
		if index > 0 {
			repeated += ","
		}

		repeated += "{}"
	}

	if protocolRegressionCorpusLoadString(`{"version":1,"entries":[`+repeated+`]}`).Code != CorpusLoadInvalidSchema {
		t.Fatal("entry overflow must be InvalidSchema")
	}

	if protocolRegressionCorpusLoadString(`{"version":1,"entries":[[[[[[[[[[]]]]]]]]]]}`).Code != CorpusLoadInvalidJson {
		t.Fatal("deep nesting must be InvalidJson")
	}

	tampered := `{"version":1,"entries":[{"family":"concrete-subject","seed":17,` +
		`"input":"a..b","expected":"EmptyToken","digest":"` + string(bytesOf('0', 64)) + `"}]}`
	if protocolRegressionCorpusLoadString(tampered).Code != CorpusLoadInvalidDigest {
		t.Fatal("tampered digest must be InvalidDigest")
	}

	if protocolRegressionCorpusLoadString(string(bytesOf('x', 32769))).Code != CorpusLoadTooLarge {
		t.Fatal("oversized corpus must be TooLarge")
	}

	if protocolRegressionCorpusLoadString("{").Code != CorpusLoadInvalidJson {
		t.Fatal("truncated corpus must be InvalidJson")
	}
}

func replaceFirst(value, old, new string) string {
	for index := 0; index+len(old) <= len(value); index++ {
		if value[index:index+len(old)] == old {
			return value[:index] + new + value[index+len(old):]
		}
	}

	return value
}

func replayCorpusEntry(t *testing.T, entry ProtocolCorpusEntry) {
	t.Helper()
	repetitions := int(entry.Seed%7) + 2
	for replay := 0; replay < repetitions; replay++ {
		switch entry.Family {
		case "concrete-subject":
			_, subjectError := ConcreteSubjectTryParse(entry.Input, fuzzLimits())
			if subjectError == SubjectGrammarErrorNone || subjectError.String() != entry.Expected {
				t.Fatalf("corpus subject replay mismatch at seed %d", entry.Seed)
			}
		case "permission-pattern":
			_, patternError := SubjectPermissionPatternTryParse(entry.Input, fuzzLimits())
			if patternError == SubjectGrammarErrorNone || patternError.String() != entry.Expected {
				t.Fatalf("corpus pattern replay mismatch at seed %d", entry.Seed)
			}
		case "command-envelope":
			revision, parsed := parseCorpusProtocolRevision(entry.Input)
			if !parsed {
				t.Fatalf("corpus envelope mutation must parse at seed %d", entry.Seed)
			}

			envelope := validEnvelope(func(o *validEnvelopeOption) { o.protocol = ptrOf(testProtocol(revision)) })
			result := CommandEnvelopeValidator.Validate(&envelope, validContext(), protocolNow)
			if result.Error.String() != entry.Expected {
				t.Fatalf("corpus envelope replay mismatch at seed %d: %v", entry.Seed, result.Error)
			}
		default:
			t.Fatalf("unknown bounded corpus family %q", entry.Family)
		}
	}
}

func parseCorpusProtocolRevision(input string) (int64, bool) {
	const prefix = "protocol:"
	if len(input) <= len(prefix) || input[:len(prefix)] != prefix {
		return 0, false
	}

	value, err := strconv.ParseInt(input[len(prefix):], 10, 64)
	if err != nil || value <= 0 {
		return 0, false
	}

	return value, true
}
