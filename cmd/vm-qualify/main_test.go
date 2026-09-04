package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestRunRejectsUnknownCommandBeforeRuntimeIdentityResolution(t *testing.T) {
	unsetTestEnvironment(t, "TS_VM_JAILER_UID", "TS_VM_JAILER_GID", "SUDO_UID", "SUDO_GID")
	err := run(context.Background(), []string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "unknown command" {
		t.Fatalf("run error = %v", err)
	}
}

func TestRealComponentsRequiresNonRootRuntimeIdentityFirst(t *testing.T) {
	unsetTestEnvironment(t, "TS_VM_JAILER_UID", "TS_VM_JAILER_GID", "SUDO_UID", "SUDO_GID")
	config := vmqual.DefaultConfig()
	_, _, err := realComponents(context.Background(), config, false)
	if err == nil || !strings.Contains(err.Error(), "nonzero jailer UID/GID") {
		t.Fatalf("realComponents error = %v", err)
	}
}

func unsetTestEnvironment(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		value, set := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		name, value, set := name, value, set
		t.Cleanup(func() {
			if set {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}
