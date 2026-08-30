// Port of src/TerraScale.Orchestrator/Protocol/Subjects/SubjectGrammarLimits.cs.
package protocol

// SubjectGrammarLimits is the bounded subject-grammar policy: maximum subject
// length, token count, token length, and permission-pattern count. The zero
// value is not a valid policy.
type SubjectGrammarLimits struct {
	MaximumSubjectLength          int
	MaximumTokenCount             int
	MaximumTokenLength            int
	MaximumPermissionPatternCount int
}

// SubjectGrammarLimitsTryCreate mirrors SubjectGrammarLimits.TryCreate.
func SubjectGrammarLimitsTryCreate(
	maximumSubjectLength,
	maximumTokenCount,
	maximumTokenLength,
	maximumPermissionPatternCount int,
) (*SubjectGrammarLimits, bool) {
	if maximumSubjectLength <= 0 ||
		maximumTokenCount <= 0 ||
		maximumTokenLength <= 0 ||
		maximumPermissionPatternCount <= 0 ||
		maximumTokenLength > maximumSubjectLength {
		return nil, false
	}

	return &SubjectGrammarLimits{
		MaximumSubjectLength:          maximumSubjectLength,
		MaximumTokenCount:             maximumTokenCount,
		MaximumTokenLength:            maximumTokenLength,
		MaximumPermissionPatternCount: maximumPermissionPatternCount,
	}, true
}
