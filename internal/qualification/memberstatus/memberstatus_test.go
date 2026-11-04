//go:build linux

package memberstatus

import (
	"context"

	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
)

func nativeQualification(t *testing.T, managed bool) *Qualification {
	t.Helper()
	root := filepath.Join(t.TempDir(), "run")
	q, e := New(t.Context(), Object{"profile": nil, "source_commits": Object{}, "rust_test_name": RustTestName}, []byte("{}"), map[string]string{}, root, "")
	if e != nil {
		t.Fatal(e)
	}
	q.Managed = managed
	if e = q.PrepareDirs(); e != nil {
		t.Fatal(e)
	}
	q.IsMounted = func(string) bool { return false }
	return q
}

func TestManagedProtectedStagingUsesPrivilegedHashReadback(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged staging driver")
	}
	groups, e := os.Getgroups()
	if e != nil {
		t.Fatal(e)
	}
	if slices.Contains(groups, 65534) {
		t.Skip("driver belongs to protected guest material group")
	}
	sudo, e := Sudo()
	if e != nil {
		t.Skip(e)
	}
	if e = exec.Command(sudo, "-n", "true").Run(); e != nil {
		t.Skip("noninteractive sudo is unavailable")
	}
	q := nativeQualification(t, true)
	q.SudoPath = sudo
	t.Cleanup(func() {
		if err := exec.Command(sudo, "-n", "rm", "-rf", "--", q.MountPath).Run(); err != nil {
			t.Errorf("remove owned privileged staging fixture: %v", err)
		}
	})
	dir := MaterialPath
	source := filepath.Join(q.Stage, "server.key")
	script.Write(t, source, []byte("private fixture material"), 0600)
	q.InstallDirectory(dir, "0755", "65534")
	dest := dir + "/server.key"
	q.Install(source, dest, "0440", "65534")
	actual := q.HashStagedGuestFile("protected-hash", dest)
	if q.Err() != nil || actual != shaBytes([]byte("private fixture material")) {
		t.Fatal(actual, q.Err())
	}
	target, _ := GuestPath(q.MountPath, dest)
	if _, e = os.ReadFile(target); !os.IsPermission(e) {
		t.Fatal("unprivileged driver could read protected material", e)
	}
	q.CommandRunner.Run(t.Context(), "restore-test-permissions", []string{sudo, "-n", "chmod", "-R", "u+rwX", q.MountPath}, time.Minute, nil)
}

var _ io.Writer = (*BoundedOutput)(nil)

func TestVMStartupRoutesAPICallsAndSeparatesBoundedLogs(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "socket")
	if err := os.Mkdir(socket, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "vmm")
	// Publish readiness after writing both streams so Start cannot return
	// before the fake VM emits the output that this test verifies.
	script.Write(t, binary, []byte("#!/bin/sh\nset -eu\nprintf 'serial output\\n'\nprintf 'vmm output\\n' >&2\n: > \"$2\"\nsleep 20\n"), 0700)
	vm := &VM{Firecracker: binary, Kernel: "kernel", Image: "rootfs", ManagedVolume: "managed-volume.ext4", SocketDir: socket, Logs: logs, Events: &EventLog{Path: filepath.Join(logs, "events.json")}}
	var calls []APIRequest
	vm.API = func(ctx context.Context, method, path string, payload Object) error {
		calls = append(calls, APIRequest{method, path, payload})
		return nil
	}
	t.Cleanup(func() {
		if vm.Process != nil && !vm.Process.Reaped {
			if err := vm.Process.Stop(time.Second, true); err != nil {
				t.Error(err)
			}
		}
	})
	if e := vm.Start(t.Context()); e != nil {
		t.Fatal(e)
	}
	if len(calls) != len(vm.Requests())+1 || calls[0].Method != "GET" || calls[0].Path != "/version" {
		t.Fatal(calls)
	}
	for i, want := range vm.Requests() {
		if calls[i+1].Path != want.Path || !equal(calls[i+1].Payload, want.Payload) {
			t.Fatal(calls)
		}
	}
	if e := vm.Process.Stop(time.Second, true); e != nil {
		t.Fatal(e)
	}
	vm.ProcessGroupStopped = true
	if e := vm.FinishOutput(); e != nil {
		t.Fatal(e)
	}
	serial := string(script.Read(t, filepath.Join(logs, "guest-serial.log")))
	vmm := string(script.Read(t, filepath.Join(logs, "firecracker-vmm.log")))
	if serial != "serial output\n" || vmm != "vmm output\n" {
		t.Fatalf("serial output = %q; VMM output = %q", serial, vmm)
	}
}
