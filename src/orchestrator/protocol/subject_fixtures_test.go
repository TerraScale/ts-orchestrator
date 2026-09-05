package protocol

import (
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"testing"
)

func fuzzLimits() *natspolicy.SubjectGrammarLimits {
	limits, ok := natspolicy.SubjectGrammarLimitsTryCreate(64, 8, 16, 16)
	if !ok {
		panic("invalid fuzz limits")
	}
	return limits
}
func testConcreteSubject(value string, limits *natspolicy.SubjectGrammarLimits) *natspolicy.ConcreteSubject {
	subject, _ := natspolicy.ConcreteSubjectTryParse(value, limits)
	return subject
}
func testPattern(value string, limits *natspolicy.SubjectGrammarLimits) *natspolicy.SubjectPermissionPattern {
	pattern, _ := natspolicy.SubjectPermissionPatternTryParse(value, limits)
	return pattern
}
func findRepositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for hops := 0; hops < 12; hops++ {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		directory = filepath.Dir(directory)
	}
	t.Fatal("Go module root not found")
	return ""
}
