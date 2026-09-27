//go:build linux

package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const nativeExtraFileTestEnv = "TERRASCALE_TEST_NATIVE_EXTRA_FILE_CASE"
const nativeTenantTargetTestEnv = "TERRASCALE_TEST_NATIVE_TENANT_TARGET_COUNT"
const nativeProtectedParentTestEnv = "TERRASCALE_TEST_NATIVE_PROTECTED_PARENT"

func TestNativeTargetExtraFileProtocol(t *testing.T) {
	if scenario := os.Getenv(nativeExtraFileTestEnv); scenario != "" {
		testNativeTargetExtraFileChild(t, scenario)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"zero", "one", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			targetPath := filepath.Join(root, "target")
			sentinelPath := filepath.Join(root, "sentinel")
			if err := os.WriteFile(targetPath, []byte("target-file"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sentinelPath, []byte("unrelated-file"), 0o600); err != nil {
				t.Fatal(err)
			}
			files := make([]*os.File, 0, 4)
			for _, path := range []string{os.DevNull, os.DevNull, targetPath, sentinelPath} {
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				files = append(files, file)
			}
			command := exec.CommandContext(t.Context(), self, "-test.run=^TestNativeTargetExtraFileProtocol$")
			command.Env = append(os.Environ(), nativeExtraFileTestEnv+"="+scenario)
			// FD 5 is deliberately present even for the zero-file request. It
			// represents an unrelated Go runtime descriptor in that case.
			command.ExtraFiles = files
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("native helper FD %s case: %v\n%s", scenario, err, output)
			}
		})
	}
}

func testNativeTargetExtraFileChild(t *testing.T, scenario string) {
	t.Helper()
	pollRead, pollWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pollRead.Close()
	defer pollWrite.Close()
	if err := pollRead.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	count := 0
	if scenario != "zero" {
		count = 1
	}
	if scenario == "missing" {
		if err := unix.Close(5); err != nil {
			t.Fatal(err)
		}
		if err := remapNativeTargetExtraFiles(count); !errors.Is(err, unix.EBADF) {
			t.Fatalf("missing inherited target FD = %v, want EBADF", err)
		}
	} else {
		if err := remapNativeTargetExtraFiles(count); err != nil {
			t.Fatal(err)
		}
		fd := 5
		if count == 1 {
			fd = 3
		}
		assertNativeTestFDContent(t, fd, "target-file")
	}
	assertNativeTestFDContent(t, 6, "unrelated-file")
	if _, err := pollWrite.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := pollRead.Read(one[:]); err != nil || one[0] != 'x' {
		t.Fatalf("Go netpoll failed after native FD handling: %q, %v", one, err)
	}
}

func assertNativeTestFDContent(t *testing.T, fd int, want string) {
	t.Helper()
	buffer := make([]byte, len(want))
	read, err := unix.Read(fd, buffer)
	if err != nil || read != len(buffer) || string(buffer) != want {
		t.Fatalf("inherited FD %d = %q after %d bytes, %v; want %q", fd, buffer, read, err, want)
	}
}

func TestNativeTargetExtraFileCountBound(t *testing.T) {
	for _, count := range []int{0, 1} {
		if err := validateNativeTargetExtraFileCount(count); err != nil {
			t.Fatalf("valid native target count %d: %v", count, err)
		}
	}
	for _, count := range []int{-1, 2} {
		if err := validateNativeTargetExtraFileCount(count); err == nil {
			t.Fatalf("accepted invalid native target count %d", count)
		}
	}
	request := nativeExecRequest{Path: "/bin/true", Args: []string{"/bin/true"},
		Identity: WorkloadIdentity{UID: 1000, GID: 1000}, ParentPID: 2}
	if validNativeExecRequest(request) {
		t.Fatal("accepted helper request without an explicit target file count")
	}
	request.ExtraFileCount = new(0)
	if !validNativeExecRequest(request) {
		t.Fatal("rejected helper request with an explicit zero target file count")
	}
	target := exec.Command("/bin/true")
	target.ExtraFiles = []*os.File{os.Stdin, os.Stdout}
	if _, _, _, err := launchNativeWorkload(t.Context(), target, nil, "/sys/fs/cgroup/test", request.Identity); err == nil || !strings.Contains(err.Error(), "at most one inherited file") {
		t.Fatalf("launcher accepted two target extra files: %v", err)
	}
}

func TestNativeWorkloadHelperExecWithDeclaredExtraFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("native helper root-to-tenant exec requires root")
	}
	if os.Getenv(nativeProtectedParentTestEnv) == "1" {
		priority, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
		if err != nil || priority != 40 { // Linux returns 20-nice.
			t.Fatalf("protected parent raw priority = %d, %v; want 40 (nice -20)", priority, err)
		}
		oom, err := os.ReadFile("/proc/self/oom_score_adj")
		if err != nil || strings.TrimSpace(string(oom)) != "-1000" {
			t.Fatalf("protected parent OOM score adjustment = %q, %v; want -1000", oom, err)
		}
		ioPriority, err := readNativeIOPriority(0)
		if err != nil || ioPriority != 2<<13 {
			t.Fatalf("protected parent I/O priority = %d, %v; want BestEffort/0", ioPriority, err)
		}
	}
	for _, count := range []int{0, 1} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			requestRead, requestWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer requestRead.Close()
			defer requestWrite.Close()
			statusRead, statusWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer statusRead.Close()
			defer statusWrite.Close()
			request := nativeExecRequest{
				Path: "/proc/self/exe", Args: []string{"/proc/self/exe", "-test.run=^TestNativeHelperTenantTarget$"},
				Env:      []string{nativeTenantTargetTestEnv + "=" + strconv.Itoa(count)},
				Identity: WorkloadIdentity{UID: 65534, GID: 65534}, ParentPID: os.Getpid(),
				ExtraFileCount: new(count),
			}
			wire, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := requestWrite.Write(wire); err != nil {
				t.Fatal(err)
			}
			if err := requestWrite.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/proc/self/exe", workloadHelperArgument)
			command.Env = []string{}
			command.ExtraFiles = []*os.File{requestRead, statusWrite}
			if count == 1 {
				path := filepath.Join(t.TempDir(), "target-extra")
				if err := os.WriteFile(path, []byte("native-target-file"), 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				command.ExtraFiles = append(command.ExtraFiles, file)
			}
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			if err := statusWrite.Close(); err != nil {
				t.Fatal(err)
			}
			if err := command.Wait(); err != nil {
				status, _ := io.ReadAll(statusRead)
				t.Fatalf("native helper count %d failed: %v; status: %s\n%s", count, err, status, output.String())
			}
			status, err := io.ReadAll(statusRead)
			if err != nil || len(status) != 0 {
				t.Fatalf("native helper count %d status %q, %v", count, status, err)
			}
		})
	}
}

func TestNativeHelperTenantTarget(t *testing.T) {
	wire, ok := os.LookupEnv(nativeTenantTargetTestEnv)
	if !ok {
		t.Skip("only the native helper execs this target")
	}
	count, err := strconv.Atoi(wire)
	if err != nil || count < 0 || count > 1 {
		t.Fatalf("invalid native helper target count %q", wire)
	}
	if os.Geteuid() != 65534 || os.Getegid() != 65534 {
		t.Fatalf("native target identity = %d:%d, want 65534:65534", os.Geteuid(), os.Getegid())
	}
	nice, err := unix.Getpriority(unix.PRIO_PROCESS, 0)
	// Linux's getpriority syscall returns 20-nice; x/sys exposes that raw value.
	if err != nil || nice != 20 {
		t.Fatalf("native target raw priority = %d, %v; want 20 (nice 0)", nice, err)
	}
	oom, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil || strings.TrimSpace(string(oom)) != "0" {
		t.Fatalf("native target OOM score adjustment = %q, %v; want 0", oom, err)
	}
	priority, err := readNativeIOPriority(0)
	if err != nil || priority != nativeIOPriorityNeutral {
		t.Fatalf("native target I/O priority = %d, %v; want BestEffort/4", priority, err)
	}
	if count == 1 {
		assertNativeTestFDContent(t, 3, "native-target-file")
	}
}

func TestNativeExecRejectsPrematureHelperDeath(t *testing.T) {
	command := exec.Command("sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer command.Wait()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(command.Process.Pid), "stat"))
		if err != nil {
			t.Fatal(err)
		}
		closing := strings.LastIndexByte(string(stat), ')')
		if closing >= 0 && strings.HasPrefix(strings.TrimSpace(string(stat[closing+1:])), "Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("killed helper did not become a zombie")
		}
		time.Sleep(time.Millisecond)
	}
	if err := verifyNativeExec(command.Process.Pid, "/nonexistent", testWorkloadIdentity); err == nil {
		t.Fatal("native exec accepted a dead helper before target exec")
	}
}
