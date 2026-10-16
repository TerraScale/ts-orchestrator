//go:build linux

package execution

import (
	"strings"
	"testing"
)

func TestHostCPUProfileProcIntegration(t *testing.T) {
	profile, err := HostCPUProfile()
	if err != nil || !profile.valid() {
		t.Fatalf("actual CPU inventory: %+v %v", profile, err)
	}
}

func TestCPUProfileRequiresEveryProcessorAndCommonFeatures(t *testing.T) {
	first, err := readCPUProfile(strings.NewReader("processor: 0\nflags: sse avx sse2\n\nprocessor: 1\nflags: sse2 sse\n"), "amd64")
	if err != nil {
		t.Fatal(err)
	}
	second, err := readCPUProfile(strings.NewReader("processor: 1\nflags: sse sse2\n\nprocessor: 0\nflags: sse2 avx sse\n"), "amd64")
	if err != nil || first != second {
		t.Fatalf("feature intersection depends on ordering: %+v %+v %v", first, second, err)
	}
	for _, wire := range []string{"", "processor: 0\n", "processor: 0\nflags: sse\n\nprocessor: 1\n", "processor: 0\nflags: sse\n\nprocessor: 1\nflags: avx\n", "processor: 0\nflags: sse\nflags: avx\n"} {
		if _, err := readCPUProfile(strings.NewReader(wire), "amd64"); err == nil {
			t.Fatalf("incomplete CPU inventory accepted: %q", wire)
		}
	}
}
