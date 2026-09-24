//go:build linux

package host

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNativeRuntimeProbeExecutesAndReplaces(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runner")
	if err := ProbeNativeRuntime(t.Context(), stateRoot, testWorkloadIdentity); err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			t.Skipf("requires writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	root, err := nativeCgroupRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "runtime-probe-") {
			t.Fatalf("runtime probe left cgroup %s behind", entry.Name())
		}
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("remove empty runtime cgroup root: %v", err)
	}
}

func TestNativeRuntimeProbeCanceledBeforeTouchingCgroups(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runner")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ProbeNativeRuntime(ctx, stateRoot, testWorkloadIdentity); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe = %v, want context canceled", err)
	}
	if os.Geteuid() == 0 {
		root, err := nativeCgroupRoot(stateRoot)
		if err == nil {
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canceled probe touched cgroup root: %v", err)
			}
		}
	}
}

func TestNativeRuntimePrivateModesRequireProtocol(t *testing.T) {
	for _, argument := range []string{probeSupervisorArgument, probeChildArgument, workloadHelperArgument} {
		command := exec.CommandContext(t.Context(), "/proc/self/exe", argument)
		command.Env = []string{}
		err := command.Run()
		var exit *exec.ExitError
		want := 111
		if argument == workloadHelperArgument {
			want = 113
		}
		if !errors.As(err, &exit) || exit.ExitCode() != want {
			t.Fatalf("private mode %s without protocol = %v, want exit %d", argument, err, want)
		}
	}
}

func TestNativeRuntimeRejectsRootTenantBeforeTouchingCgroups(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "runner")
	if err := ProbeNativeRuntime(t.Context(), stateRoot, WorkloadIdentity{UID: 0, GID: 0}); err == nil {
		t.Fatal("probe accepted root workload identity")
	}
	if _, err := os.Stat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid identity touched state root: %v", err)
	}
}

func TestProbeSupervisorWaitDeadlineDoesNotLeaveWaitGoroutine(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	nonce := strings.Repeat("a", 32)
	command := exec.Command("/proc/self/exe", probeChildArgument)
	command.Env = []string{probeNonceEnv + "=" + nonce}
	command.ExtraFiles = []*os.File{writer}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := waitProbeSupervisor(ctx, command.Process.Pid); err != nil {
			t.Errorf("reap private probe child: %v", err)
		}
		_ = command.Process.Release()
	}()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 36)
	if _, err := io.ReadFull(reader, ack); err != nil || string(ack[:32]) != nonce {
		t.Fatalf("private child did not acknowledge userspace: %q, %v", ack, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := waitProbeSupervisor(ctx, command.Process.Pid); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait for live probe child = %v, want deadline exceeded", err)
	}
}
