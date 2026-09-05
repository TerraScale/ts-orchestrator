package hostagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUseraddProvisionerUsesBoundedNoLogInitInvocation(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "useradd")
	arguments := filepath.Join(directory, "arguments")
	program := []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$USERADD_ARGUMENTS\"\n")
	if err := os.WriteFile(binary, program, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERADD_ARGUMENTS", arguments)
	provisioner := UseraddProvisioner{UseraddBinary: binary, Timeout: time.Second}
	if err := provisioner.EnsureUser(context.Background(), "root"); err == nil {
		t.Fatal("privileged component account accepted")
	}
	if err := provisioner.EnsureUser(context.Background(), "terrascale-test"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "--no-log-init\n") {
		t.Fatalf("useradd arguments omit --no-log-init: %q", data)
	}

	sleeping := filepath.Join(directory, "sleeping-useradd")
	if err := os.WriteFile(sleeping, []byte("#!/bin/sh\nkill -STOP $$\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	provisioner = UseraddProvisioner{UseraddBinary: sleeping, Timeout: 40 * time.Millisecond}
	if err := provisioner.EnsureUser(context.Background(), "terrascale-test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want context deadline exceeded", err)
	}
}
