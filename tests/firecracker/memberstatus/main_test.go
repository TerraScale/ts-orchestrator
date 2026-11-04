//go:build linux

package main

import (
	"os/exec"
	"testing"
)

func TestIsRequestedMemberSocketBindFailure(t *testing.T) {
	childErr := exec.CommandContext(t.Context(), "sh", "-c", "exit 1").Run()
	if childErr == nil {
		t.Fatal("expected a nonzero child exit")
	}
	socket := "/run/ts-member-status/control/member.sock"
	output := "terrabase-server: member-control socket bind " + socket + ": Address in use (os error 98)\n"
	if !isRequestedMemberSocketBindFailure([]byte(output), childErr, socket) {
		t.Fatal("requested member socket bind failure was not recognized")
	}
}
