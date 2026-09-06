//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
)

func TestDeviceMapperIOFaultBuildsPrivateErrorTargetAndRemovesIt(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data.ext4")
	if err := os.WriteFile(source, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	adapter := &deviceMapperIOFault{dmPath: "/usr/sbin/dmsetup", cmd: func(_ context.Context, path string, args ...string) error {
		calls = append(calls, append([]string{path}, args...))
		return nil
	}}
	attachment, err := adapter.Prepare(context.Background(), sandboxvm.DataDriveFaultRequest{VMID: "gru-member-2", Generation: 7, SourcePath: source, StateDir: filepath.Join(root, "state"), UID: 1000, GID: 1001})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := attachment.Path(), "/dev/mapper/terrascale-vmqual-gru-member-2-io-7"; got != want {
		t.Fatalf("fault path = %q, want %q", got, want)
	}
	wantCreate := []string{"/usr/sbin/dmsetup", "create", "terrascale-vmqual-gru-member-2-io-7", "--table", "0 8 error", "--uid", "1000", "--gid", "1001", "--mode", "0600"}
	if !reflect.DeepEqual(calls, [][]string{wantCreate}) {
		t.Fatalf("create command = %#v, want %#v", calls, [][]string{wantCreate})
	}
	if err := attachment.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantRemove := []string{"/usr/sbin/dmsetup", "remove", "--retry", "terrascale-vmqual-gru-member-2-io-7"}
	if !reflect.DeepEqual(calls, [][]string{wantCreate, wantRemove}) {
		t.Fatalf("commands = %#v, want %#v", calls, [][]string{wantCreate, wantRemove})
	}
	if err := attachment.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceMapperIOFaultRejectsUnsafeSourceAndIdentity(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data.ext4")
	if err := os.WriteFile(source, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter := &deviceMapperIOFault{dmPath: "/usr/sbin/dmsetup", cmd: func(context.Context, string, ...string) error { return nil }}
	for name, request := range map[string]sandboxvm.DataDriveFaultRequest{
		"root source":      {VMID: "gru-member-2", Generation: 1, SourcePath: "/", StateDir: filepath.Join(root, "state"), UID: 1000, GID: 1000},
		"unaligned source": {VMID: "gru-member-2", Generation: 1, SourcePath: filepath.Join(root, "unaligned"), StateDir: filepath.Join(root, "state"), UID: 1000, GID: 1000},
		"unsafe VM ID":     {VMID: "../root", Generation: 1, SourcePath: source, StateDir: filepath.Join(root, "state"), UID: 1000, GID: 1000},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "unaligned source" {
				if err := os.WriteFile(request.SourcePath, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := adapter.Prepare(context.Background(), request); err == nil {
				t.Fatal("unsafe I/O-fault request was accepted")
			}
		})
	}
}
