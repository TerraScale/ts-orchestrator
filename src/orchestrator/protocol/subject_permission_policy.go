// Port of src/TerraScale.Orchestrator/Protocol/Subjects/SubjectPermissionPolicy.cs.
package protocol

import (
	"sort"
	"strconv"
)

// SubjectPermissionPolicyError mirrors the SubjectPermissionPolicyError enum.
type SubjectPermissionPolicyError int

const (
	SubjectPermissionPolicyErrorNone                  SubjectPermissionPolicyError = 0
	SubjectPermissionPolicyErrorInvalidLimits         SubjectPermissionPolicyError = 1
	SubjectPermissionPolicyErrorNullPattern           SubjectPermissionPolicyError = 2
	SubjectPermissionPolicyErrorTooManyPatterns       SubjectPermissionPolicyError = 3
	SubjectPermissionPolicyErrorDuplicatePattern      SubjectPermissionPolicyError = 4
	SubjectPermissionPolicyErrorPatternInAllowAndDeny SubjectPermissionPolicyError = 5
	SubjectPermissionPolicyErrorEnumerationFailed     SubjectPermissionPolicyError = 6
)

func (e SubjectPermissionPolicyError) String() string {
	switch e {
	case SubjectPermissionPolicyErrorNone:
		return "None"
	case SubjectPermissionPolicyErrorInvalidLimits:
		return "InvalidLimits"
	case SubjectPermissionPolicyErrorNullPattern:
		return "NullPattern"
	case SubjectPermissionPolicyErrorTooManyPatterns:
		return "TooManyPatterns"
	case SubjectPermissionPolicyErrorDuplicatePattern:
		return "DuplicatePattern"
	case SubjectPermissionPolicyErrorPatternInAllowAndDeny:
		return "PatternInAllowAndDeny"
	case SubjectPermissionPolicyErrorEnumerationFailed:
		return "EnumerationFailed"
	default:
		return strconv.Itoa(int(e))
	}
}

// SubjectPermissionReason mirrors the SubjectPermissionReason enum.
type SubjectPermissionReason int

const (
	SubjectPermissionReasonUninitialized        SubjectPermissionReason = 0
	SubjectPermissionReasonAllowedByPattern     SubjectPermissionReason = 1
	SubjectPermissionReasonDeniedByPattern      SubjectPermissionReason = 2
	SubjectPermissionReasonDeniedEmptyAllowSet  SubjectPermissionReason = 3
	SubjectPermissionReasonDeniedNoAllowMatch   SubjectPermissionReason = 4
	SubjectPermissionReasonDeniedInvalidSubject SubjectPermissionReason = 5
)

func (r SubjectPermissionReason) String() string {
	switch r {
	case SubjectPermissionReasonAllowedByPattern:
		return "AllowedByPattern"
	case SubjectPermissionReasonDeniedByPattern:
		return "DeniedByPattern"
	case SubjectPermissionReasonDeniedEmptyAllowSet:
		return "DeniedEmptyAllowSet"
	case SubjectPermissionReasonDeniedNoAllowMatch:
		return "DeniedNoAllowMatch"
	case SubjectPermissionReasonDeniedInvalidSubject:
		return "DeniedInvalidSubject"
	default:
		return "Uninitialized"
	}
}

// SubjectPermissionDecision mirrors the readonly record struct of the same name.
type SubjectPermissionDecision struct {
	Reason SubjectPermissionReason
}

// IsAllowed reports whether the decision allows the subject.
func (d SubjectPermissionDecision) IsAllowed() bool {
	return d.Reason == SubjectPermissionReasonAllowedByPattern
}

func (d SubjectPermissionDecision) String() string { return d.Reason.String() }

// SubjectPermissionPolicy is one closed allow/deny permission policy over
// compiled subject permission patterns.
type SubjectPermissionPolicy struct {
	allow []*SubjectPermissionPattern
	deny  []*SubjectPermissionPattern
}

// AllowPatterns returns the canonically ordered allow list; callers must not
// mutate it.
func (p *SubjectPermissionPolicy) AllowPatterns() []*SubjectPermissionPattern {
	if p == nil {
		return nil
	}

	return p.allow
}

// DenyPatterns returns the canonically ordered deny list; callers must not
// mutate it.
func (p *SubjectPermissionPolicy) DenyPatterns() []*SubjectPermissionPattern {
	if p == nil {
		return nil
	}

	return p.deny
}

// SubjectPermissionPolicyTryCreate mirrors SubjectPermissionPolicy.TryCreate.
// A nil element stands in for the C# null pattern. The combined allow+deny
// budget is limits.MaximumPermissionPatternCount.
func SubjectPermissionPolicyTryCreate(
	allow []*SubjectPermissionPattern,
	deny []*SubjectPermissionPattern,
	limits *SubjectGrammarLimits,
) (*SubjectPermissionPolicy, SubjectPermissionPolicyError) {
	if limits == nil {
		return nil, SubjectPermissionPolicyErrorInvalidLimits
	}

	allowPatterns, err := collectPermissionPatterns(allow, limits.MaximumPermissionPatternCount)
	if err != SubjectPermissionPolicyErrorNone {
		return nil, err
	}

	remaining := limits.MaximumPermissionPatternCount - len(allowPatterns)
	denyPatterns, err := collectPermissionPatterns(deny, remaining)
	if err != SubjectPermissionPolicyErrorNone {
		return nil, err
	}

	allowSet := make(map[string]struct{}, len(allowPatterns))
	for _, pattern := range allowPatterns {
		allowSet[pattern.Value()] = struct{}{}
	}

	for _, pattern := range denyPatterns {
		if _, overlap := allowSet[pattern.Value()]; overlap {
			return nil, SubjectPermissionPolicyErrorPatternInAllowAndDeny
		}
	}

	sortPermissionPatterns(allowPatterns)
	sortPermissionPatterns(denyPatterns)
	return &SubjectPermissionPolicy{allow: allowPatterns, deny: denyPatterns}, SubjectPermissionPolicyErrorNone
}

// Authorize mirrors SubjectPermissionPolicy.Authorize: deny wins, then a
// nonempty allow list must match.
func (p *SubjectPermissionPolicy) Authorize(subject *ConcreteSubject) SubjectPermissionDecision {
	if p == nil || subject == nil {
		return SubjectPermissionDecision{Reason: SubjectPermissionReasonDeniedInvalidSubject}
	}

	for _, pattern := range p.deny {
		if pattern.Matches(subject) {
			return SubjectPermissionDecision{Reason: SubjectPermissionReasonDeniedByPattern}
		}
	}

	if len(p.allow) == 0 {
		return SubjectPermissionDecision{Reason: SubjectPermissionReasonDeniedEmptyAllowSet}
	}

	for _, pattern := range p.allow {
		if pattern.Matches(subject) {
			return SubjectPermissionDecision{Reason: SubjectPermissionReasonAllowedByPattern}
		}
	}

	return SubjectPermissionDecision{Reason: SubjectPermissionReasonDeniedNoAllowMatch}
}

func collectPermissionPatterns(
	source []*SubjectPermissionPattern,
	maximumCount int,
) ([]*SubjectPermissionPattern, SubjectPermissionPolicyError) {
	collected := make([]*SubjectPermissionPattern, 0, min(maximumCount, 16))
	unique := map[string]struct{}{}
	for _, pattern := range source {
		if len(collected) >= maximumCount {
			return nil, SubjectPermissionPolicyErrorTooManyPatterns
		}

		if pattern == nil {
			return nil, SubjectPermissionPolicyErrorNullPattern
		}

		if _, duplicate := unique[pattern.Value()]; duplicate {
			return nil, SubjectPermissionPolicyErrorDuplicatePattern
		}

		unique[pattern.Value()] = struct{}{}
		collected = append(collected, pattern)
	}

	return collected, SubjectPermissionPolicyErrorNone
}

func sortPermissionPatterns(patterns []*SubjectPermissionPattern) {
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].CompareTo(patterns[j]) < 0
	})
}
