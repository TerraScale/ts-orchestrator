//go:build linux

package execution

import (
	"testing"
)

func TestHostCPUProfileProcIntegration(t *testing.T) {
	profile, err := HostCPUProfile()
	if err != nil || !profile.valid() {
		t.Fatalf("actual CPU inventory: %+v %v", profile, err)
	}
}
