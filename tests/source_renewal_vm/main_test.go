//go:build linux && amd64

package main

import (
	"bufio"
	"bytes"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/tests/source_renewal_vm/protocol"
)

func TestNewcGuestOwnershipAndPathConfinement(t *testing.T) {
	var wire bytes.Buffer
	archive := newc{out: &wire, paths: map[string]bool{}}
	if err := archive.entry("/dev/console", 0o020600, nil, 5, 1); err != nil {
		t.Fatal(err)
	}
	header := wire.String()[:110]
	for _, offset := range []int{22, 30} {
		if header[offset:offset+8] != "00000000" {
			t.Fatal("archive entry is not owned by guest root", header)
		}
	}
	for offset, want := range map[int]uint64{78: 5, 86: 1} {
		got, err := strconv.ParseUint(header[offset:offset+8], 16, 32)
		if err != nil || got != want {
			t.Fatalf("device field at %d: %d %v", offset, got, err)
		}
	}
	for _, name := range []string{".", "..", "//host", "../host", "/../host", "/dev/console", "/a/../host", "/nul\x00path"} {
		if err := archive.entry(name, 0o100600, nil, 0, 0); err == nil {
			t.Fatalf("accepted unsafe or repeated entry %q", name)
		}
	}
}

func TestQEMUHasNoHostSharingAndFixedBounds(t *testing.T) {
	s := staged{Manifest: manifest{Nice: input{Path: "/nice"}, Env: input{Path: "/env"}, QEMU: input{Path: "/qemu"}}, Kernel: input{Path: "/owned/kernel"}, Initramfs: input{Path: "/owned/guest"}}
	argv := qemuArgv(s, "/owned")
	for _, forbidden := range []string{"-netdev", "-fsdev", "-virtfs", "-drive", "-blockdev", "-device", "-daemonize", "sudo"} {
		if slices.Contains(argv, forbidden) {
			t.Fatalf("unexpected host-sharing or detached process option %s", forbidden)
		}
	}
	for key, value := range map[string]string{"-nic": "none", "-smp": "2", "-m": "8192", "-monitor": "none", "-machine": "q35,accel=kvm"} {
		i := slices.Index(argv, key)
		if i < 0 || i+1 >= len(argv) || argv[i+1] != value {
			t.Fatalf("missing fixed boundary %s %s: %v", key, value, argv)
		}
	}
	if !strings.HasPrefix(strings.Join(argv, " "), "/nice -n 19 /env -i ") {
		t.Fatal("QEMU lacks explicit low-priority empty environment", argv)
	}
}

func TestSerialCapFailsWithoutDiscardingExistingEvidence(t *testing.T) {
	log := &cappedLog{bytes: 64 << 20}
	if n, err := log.Write([]byte("overflow")); n != 0 || err == nil {
		t.Fatalf("overflow accepted: %d %v", n, err)
	}
	if size, exhausted := log.status(); size != 64<<20 || !exhausted {
		t.Fatalf("cap not retained: %d %v", size, exhausted)
	}
}

func TestGuestEvidenceRejectsEmptySkippedAndConflictingResults(t *testing.T) {
	id := strings.Repeat("a", 64)
	ready := protocol.ReadyPrefix + id + "\r\n"
	result := protocol.ResultPrefix + id + ":0\r\n"
	pass := "--- PASS: " + protocol.TestName + " (1.00s)\r\n"
	for _, test := range []struct {
		name, wire string
		want       bool
	}{
		{"exact test passed", ready + pass + result, true},
		{"empty test selection", ready + result, false},
		{"skipped test", ready + "--- SKIP: " + protocol.TestName + " (0.00s)\n" + result, false},
		{"duplicate result", ready + pass + result + result, false},
		{"conflicting failure", ready + pass + result + protocol.ResultPrefix + id + ":1\n", false},
		{"nested child pass only", ready + "    " + pass + result, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := scanGuestEvidence(bufio.NewScanner(strings.NewReader(test.wire)), id)
			if err != nil || evidence.complete() != test.want {
				t.Fatalf("evidence=%+v error=%v want complete=%v", evidence, err, test.want)
			}
		})
	}
}
