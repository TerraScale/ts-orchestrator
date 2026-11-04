//go:build linux

package main

import (
	"errors"
	"os/exec"
	"testing"
)

func TestIsRequestedMemberSocketBindFailure(t *testing.T) {
	exitOne := exec.CommandContext(t.Context(), "sh", "-c", "exit 1").Run()
	exitTwo := exec.CommandContext(t.Context(), "sh", "-c", "exit 2").Run()
	if exitOne == nil || exitTwo == nil {
		t.Fatal("expected nonzero child exit codes")
	}
	socket := "/run/ts-member-status/control/member.sock"
	bindLine := "terrabase-server: member-control socket bind " + socket + ": "
	tests := []struct {
		name   string
		output string
		err    error
		want   bool
	}{
		{"guest errno wording", "startup log\n" + bindLine + "Address in use (os error 98)\n", exitOne, true},
		{"host errno wording", bindLine + "Address already in use (os error 98)\n", exitOne, true},
		{"unrelated TCP bind", "terrabase-server: replication listener bind 127.0.0.1:8080: Address already in use (os error 98)\n", exitOne, false},
		{"wrong socket path", "terrabase-server: member-control socket bind /run/other/member.sock: Address already in use (os error 98)\n", exitOne, false},
		{"wrong errno", bindLine + "Permission denied (os error 13)\n", exitOne, false},
		{"wrong exit code", bindLine + "Address already in use (os error 98)\n", exitTwo, false},
		{"no child exit", bindLine + "Address already in use (os error 98)\n", errors.New("start failed"), false},
		{"no source wording", bindLine + "(os error 98)\n", exitOne, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRequestedMemberSocketBindFailure([]byte(tt.output), tt.err, socket); got != tt.want {
				t.Fatalf("isRequestedMemberSocketBindFailure(%q, %v) = %t, want %t", tt.output, tt.err, got, tt.want)
			}
		})
	}
}
