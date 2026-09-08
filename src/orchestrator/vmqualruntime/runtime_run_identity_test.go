package vmqualruntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQualificationRunIdentitySurvivesReconstructionAndRejectsForeignIntent(t *testing.T) {
	config := networkTestConfig(t)
	state := filepath.Join(t.TempDir(), "state")
	first, err := retainQualificationRunIdentity(state, config)
	if err != nil {
		t.Fatal(err)
	}
	config.RunID = ""
	second, err := retainQualificationRunIdentity(state, config)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.NetworkRunID == "" || !qualificationStackRunIDPattern.MatchString(first.StackRunID) {
		t.Fatal("run identity regenerated")
	}
	config.Prefix = "foreign"
	if _, err := retainQualificationRunIdentity(state, config); err == nil {
		t.Fatal("changed network reused admitted run")
	}
	config.Prefix = "ts"
	config.RunID = "ffffffffffffffffffffffffffffffff"
	if _, err := retainQualificationRunIdentity(state, config); err == nil {
		t.Fatal("foreign explicit run reused admission")
	}
	config.RunID = ""
	if err := os.WriteFile(filepath.Join(state, "qualification-run", "identity.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := retainQualificationRunIdentity(state, config); err == nil {
		t.Fatal("corrupt identity regenerated")
	}
}
