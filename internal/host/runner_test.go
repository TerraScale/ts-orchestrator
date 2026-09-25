//go:build linux

package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

var testWorkloadIdentity = WorkloadIdentity{UID: 65534, GID: 65534}

const nativeTenantDiagnosticArgument = "--terrascale-test-native-tenant-diagnostic"

func init() {
	if len(os.Args) != 3 || os.Args[1] != nativeTenantDiagnosticArgument {
		return
	}
	runtime.LockOSThread()
	var signal int32
	_, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0, 0)
	if errno != 0 {
		os.Exit(111)
	}
	report := fmt.Sprintf("signal=%d ppid=%d tid=%d\n", signal, os.Getppid(), unix.Gettid())
	if err := os.WriteFile(os.Args[2], []byte(report), 0600); err != nil {
		os.Exit(111)
	}
	for tick := 1; ; tick++ {
		time.Sleep(100 * time.Millisecond)
		file, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			os.Exit(111)
		}
		_, _ = fmt.Fprintf(file, "tick=%d ppid=%d\n", tick, os.Getppid())
		_ = file.Close()
	}
}

func nativeTestInstallDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TS_NATIVE_TEST_ROOT")
	if base == "" {
		base = "/run"
	}
	root, err := os.MkdirTemp(base, "ts-orch-native-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chown(root, 0, int(testWorkloadIdentity.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0710); err != nil {
		t.Fatal(err)
	}
	return root
}

func nativeTestMarkerDir(t *testing.T) string {
	t.Helper()
	root := nativeTestInstallDir(t)
	if err := os.Chmod(root, 0730); err != nil {
		t.Fatal(err)
	}
	return root
}

func nativeTestReadableMarker(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(nativeTestMarkerDir(t), name)
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, int(testWorkloadIdentity.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	return path
}

func copyNativeTestExecutable(t *testing.T, path string) {
	t.Helper()
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, int(testWorkloadIdentity.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0550); err != nil {
		t.Fatal(err)
	}
}

func nativeCreatorTID(parentPID, childPID int) int {
	tasks, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(parentPID), "task"))
	if err != nil {
		return 0
	}
	want := strconv.Itoa(childPID)
	for _, task := range tasks {
		children, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(parentPID), "task", task.Name(), "children"))
		if err != nil {
			continue
		}
		for child := range strings.FieldsSeq(string(children)) {
			if child == want {
				tid, _ := strconv.Atoi(task.Name())
				return tid
			}
		}
	}
	return 0
}

func writeNativeTestExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, int(testWorkloadIdentity.GID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0550); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadCgroupMemoryMaxValidation(t *testing.T) {
	page := uint64(os.Getpagesize())
	for _, tc := range []struct {
		name  string
		limit uint64
		valid bool
	}{
		{name: "default", limit: 0, valid: true},
		{name: "finite page multiple", limit: 5 << 30, valid: true},
		{name: "subpage", limit: page - 1},
		{name: "unaligned", limit: (5 << 30) + 1},
		{name: "signed overflow", limit: uint64(1) << 63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCgroupMemoryMax(tc.limit)
			if (err == nil) != tc.valid {
				t.Fatalf("validateCgroupMemoryMax(%d) error = %v, valid = %t", tc.limit, err, tc.valid)
			}
			if tc.valid {
				return
			}
			// Invalid limits must fail before Stop or process launch, even when
			// the runner has not yet recovered or the executable is absent.
			runner := NewProcessRunner(t.TempDir(), testWorkloadIdentity)
			workload := Workload{
				Role: "terrabase", Digest: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64),
				CgroupMemoryMaxBytes: tc.limit,
			}
			if err := runner.Apply(t.Context(), workload); err == nil || !strings.Contains(err.Error(), "memory cap") {
				t.Fatalf("Apply with invalid cap should fail before runner state or launch checks: %v", err)
			}
		})
	}
}

func TestEnableCgroupMemoryControllerFailsClosed(t *testing.T) {
	parent := t.TempDir()
	if err := enableCgroupMemoryController(parent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing delegated controller file should fail: %v", err)
	}
	path := filepath.Join(parent, "cgroup.subtree_control")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := enableCgroupMemoryController(parent); err == nil || !strings.Contains(err.Error(), "does not include memory") {
		t.Fatalf("non-kernel readback must not be accepted: %v", err)
	}
}

func TestCloseKillsCgroupWhileApplyHoldsLock(t *testing.T) {
	root := t.TempDir()
	role := "terrabase"
	cgroup := filepath.Join(root, role)
	if err := os.Mkdir(cgroup, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.events"), []byte("populated 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.freeze"), []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &processRunner{cgroups: root, closing: make(chan struct{}), records: make(map[string]processRecord), commands: make(map[string]*exec.Cmd)}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Close(ctx) }()
	deadline := time.Now().Add(150 * time.Millisecond)
	for {
		data, err := os.ReadFile(filepath.Join(cgroup, "cgroup.kill"))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) == "1" {
			frozen, err := os.ReadFile(filepath.Join(cgroup, "cgroup.freeze"))
			if err != nil || string(frozen) != "1" {
				t.Fatalf("Close killed before fencing late launches: frozen=%q error=%v", frozen, err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close waited for the Apply lock before killing the cgroup")
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(cgroup, "cgroup.events"), []byte("populated 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cgroup.events", "cgroup.kill", "cgroup.freeze"} {
		if err := os.Remove(filepath.Join(cgroup, name)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Close must honor its deadline while Apply owns the lock: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not honor its deadline")
	}
	if !runnerClosing(runner.closing) {
		t.Fatal("Close did not fence new launches")
	}
}

type cancelAfterErrContext struct {
	context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (c *cancelAfterErrContext) Err() error {
	err := c.Context.Err()
	if err == nil {
		c.once.Do(c.cancel)
	}
	return err
}

func TestApplyDoesNotLaunchAfterCancellation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(root, testWorkloadIdentity).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		_ = os.Remove(filepath.Join(runner.cgroups, "terrabase"))
		_ = os.Remove(runner.cgroups)
	})
	install := nativeTestInstallDir(t)
	marker := filepath.Join(nativeTestMarkerDir(t), "started")
	script := filepath.Join(install, "workload")
	content := "#!/bin/sh\nprintf started > '" + marker + "'\nwhile :; do sleep 1; done\n"
	writeNativeTestExecutable(t, script, content)
	base, cancel := context.WithCancel(t.Context())
	ctx := &cancelAfterErrContext{Context: base, cancel: cancel}
	defer cancel()
	digest := strings.Repeat("a", 64)
	err := runner.Apply(ctx, Workload{Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: script})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply after cancellation = %v, want context canceled", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("workload launched after cancellation: marker error %v", err)
	}
	observed, err := runner.Observe(t.Context(), "terrabase")
	if err != nil || observed.Running {
		t.Fatalf("canceled workload still running: %+v, %v", observed, err)
	}
}

func TestCloseInvalidatesOpenedCgroupFD(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(root, testWorkloadIdentity).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		_ = os.Remove(runner.cgroups)
	})
	rolePath := filepath.Join(runner.cgroups, "terrabase")
	if err := os.Mkdir(rolePath, 0700); err != nil {
		t.Fatal(err)
	}
	cgroup, err := os.Open(rolePath)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := runner.Close(ctx); err != nil {
		t.Fatalf("Close did not seal an empty in-flight cgroup: %v", err)
	}
	if _, err := os.Stat(rolePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Close left role cgroup available: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "started")
	script := filepath.Join(t.TempDir(), "workload")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf started > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	started := make(chan error, 1)
	go func() { started <- cmd.Start() }()
	select {
	case err := <-started:
		if err == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("clone3 started a child through a closed role cgroup")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("clone3 blocked on a child in the frozen role cgroup")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("late child executed after Close: marker error %v", err)
	}
}

func TestNativeReplacementStartsAfterCgroupKill(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(root, testWorkloadIdentity).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		_ = os.Remove(runner.cgroups)
	})
	install := nativeTestInstallDir(t)
	marker := nativeTestReadableMarker(t, "marker")
	for version := 1; version <= 3; version++ {
		if err := os.Truncate(marker, 0); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(install, fmt.Sprintf("workload-%d", version))
		body := fmt.Sprintf("#!/bin/sh\nset -eu\nprintf '%%d\\n' %d > '%s'\nwhile :; do sleep 1; done\n", version, marker)
		writeNativeTestExecutable(t, script, body)
		digest := fmt.Sprintf("%064x", version)
		if err := runner.Apply(t.Context(), Workload{Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: script}); err != nil {
			t.Fatalf("Apply version %d: %v", version, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			observed, err := runner.Observe(t.Context(), "terrabase")
			if err != nil {
				t.Fatal(err)
			}
			data, _ := os.ReadFile(marker)
			if observed.Running && observed.Digest == digest && strings.TrimSpace(string(data)) == fmt.Sprint(version) {
				t.Logf("version %d running pid=%d", version, observed.PID)
				break
			}
			if !observed.Running || time.Now().After(deadline) {
				t.Fatalf("replacement version %d did not run: observation=%+v marker=%q", version, observed, data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestNativeWorkloadReceivesOnlyExplicitEnvironment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(root, testWorkloadIdentity).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2 and root supervisor: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		_ = os.Remove(runner.cgroups)
	})
	install := nativeTestInstallDir(t)
	marker := nativeTestReadableMarker(t, "environment")
	script := filepath.Join(install, "workload")
	writeNativeTestExecutable(t, script, "#!/bin/sh\nset -eu\nenv > '"+marker+"'\nwhile :; do sleep 1; done\n")
	t.Setenv("TS_SUPERVISOR_SECRET", "must-not-leak")
	digest := strings.Repeat("b", 64)
	if err := runner.Apply(t.Context(), Workload{Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: script, Env: map[string]string{"TS_DESIRED": "present"}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(marker)
		if err == nil && len(data) != 0 {
			environment := string(data)
			if strings.Contains(environment, "TS_SUPERVISOR_SECRET=") || !strings.Contains(environment, "TS_DESIRED=present") || !strings.Contains(environment, "PATH=/usr/bin:/bin") {
				t.Fatalf("native workload environment is unsafe: %q", environment)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native workload did not write environment: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNativeTenantWorkloadDiesWithSupervisor(t *testing.T) {
	if os.Getenv("TS_NATIVE_TENANT_DEATH_HELPER") == "1" {
		state := os.Getenv("TS_NATIVE_TENANT_STATE")
		script := os.Getenv("TS_NATIVE_TENANT_SCRIPT")
		diagnostic := os.Getenv("TS_NATIVE_TENANT_DIAGNOSTIC")
		report := os.Getenv("TS_NATIVE_TENANT_REPORT")
		runner := NewProcessRunner(state, testWorkloadIdentity).(*processRunner)
		if err := runner.Recover(t.Context()); err != nil {
			t.Fatal(err)
		}
		digest := strings.Repeat("c", 64)
		if err := runner.Apply(t.Context(), Workload{Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: script, Args: []string{diagnostic, nativeTenantDiagnosticArgument, report}}); err != nil {
			t.Fatal(err)
		}
		observation, err := runner.Observe(t.Context(), "terrabase")
		if err != nil || !observation.Running {
			t.Fatalf("tenant workload not running: %+v, %v", observation, err)
		}
		fmt.Printf("%d %s\n", observation.PID, currentStartTime(observation.PID))
		select {}
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root supervisor")
	}
	state := filepath.Join(t.TempDir(), "state")
	cgroupRoot, err := nativeCgroupRoot(state)
	if err != nil {
		if nativeTestCgroupUnavailable(err) {
			t.Skipf("requires systemd delegated writable cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	if err := prepareNativeCgroupRoot(cgroupRoot); err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			t.Skipf("requires writable delegated cgroup v2: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sealCgroup(ctx, filepath.Join(cgroupRoot, "terrabase")); err != nil {
			t.Errorf("seal tenant death cgroup: %v", err)
		}
		if err := os.Remove(cgroupRoot); err != nil {
			t.Errorf("remove tenant death cgroup root: %v", err)
		}
	})
	install := nativeTestInstallDir(t)
	script := filepath.Join(install, "workload")
	diagnostic := filepath.Join(install, "diagnostic")
	writeNativeTestExecutable(t, script, "#!/bin/sh\nexec \"$@\"\n")
	copyNativeTestExecutable(t, diagnostic)
	report := nativeTestReadableMarker(t, "parent-death")
	helper := exec.Command("/proc/self/exe", "-test.run=^TestNativeTenantWorkloadDiesWithSupervisor$")
	helper.Env = append(os.Environ(), "TS_NATIVE_TENANT_DEATH_HELPER=1", "TS_NATIVE_TENANT_STATE="+state, "TS_NATIVE_TENANT_SCRIPT="+script, "TS_NATIVE_TENANT_DIAGNOSTIC="+diagnostic, "TS_NATIVE_TENANT_REPORT="+report)
	helper.Stderr = os.Stderr
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(func() {
		killErr := helper.Process.Kill()
		waitErr := helper.Wait()
		t.Logf("supervisor stop: kill=%v wait=%v", killErr, waitErr)
	})
	defer stop()
	type reply struct {
		line string
		err  error
	}
	line := make(chan reply, 1)
	go func() {
		value, err := bufio.NewReader(stdout).ReadString('\n')
		line <- reply{value, err}
	}()
	var result reply
	select {
	case result = <-line:
	case <-time.After(10 * time.Second):
		t.Fatal("tenant helper did not report a live workload")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	var pid int
	var start string
	if n, err := fmt.Sscanf(result.line, "%d %s", &pid, &start); err != nil || n != 2 || !processRunningWithStart(pid, start) {
		t.Fatalf("tenant helper did not report a live workload: %q (%v)", result.line, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	var reportContents string
	for {
		data, err := os.ReadFile(report)
		if err == nil && len(data) != 0 {
			reportContents = strings.TrimSpace(string(data))
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tenant target did not report its post-exec parent-death signal: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var signal, parentPID, targetTID int
	if n, err := fmt.Sscanf(reportContents, "signal=%d ppid=%d tid=%d", &signal, &parentPID, &targetTID); err != nil || n != 3 {
		t.Fatalf("invalid tenant target diagnostic %q: %v", reportContents, err)
	}
	creatorTID := nativeCreatorTID(helper.Process.Pid, pid)
	t.Logf("target after exec: pid=%d tid=%d ppid=%d pdeathsig=%d creator_tid=%d supervisor=%d", pid, targetTID, parentPID, signal, creatorTID, helper.Process.Pid)
	if signal != int(syscall.SIGKILL) || parentPID != helper.Process.Pid || creatorTID == 0 {
		t.Fatal("tenant target lacks a live parent-death signal owner after exec")
	}
	stop()
	deadline = time.Now().Add(3 * time.Second)
	for processRunningWithStart(pid, start) {
		if time.Now().After(deadline) {
			status, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
			stat, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
			heartbeats, _ := os.ReadFile(report)
			t.Fatalf("tenant workload survived its supervisor: status=%q stat=%q target_report=%q", status, stat, heartbeats)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestWorkloadSurvivesCallerThreadExit(t *testing.T) {
	type launch struct {
		cmd    *exec.Cmd
		waited <-chan error
		err    error
	}
	started := make(chan launch, 1)
	callerDone := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(callerDone)
		// Exiting while locked terminates this OS thread. The workload's
		// creator must be a different thread that stays alive through Wait.
		cmd := exec.Command("sleep", "30")
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		release, waited, err := startWorkloadOnLockedThread(cmd)
		if err == nil {
			release()
		}
		started <- launch{cmd: cmd, waited: waited, err: err}
	}()
	result := <-started
	if result.err != nil {
		t.Fatal(result.err)
	}
	t.Cleanup(func() { _ = result.cmd.Process.Kill() })
	<-callerDone
	select {
	case err := <-result.waited:
		t.Fatalf("workload died when the caller thread exited: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	if err := result.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-result.waited:
	case <-time.After(2 * time.Second):
		t.Fatal("workload was not reaped")
	}
}

func TestWorkloadDiesWithOwnerProcess(t *testing.T) {
	helper := exec.Command(os.Args[0], "-test.run=^TestWorkloadParentDeathHelper$")
	helper.Env = append(os.Environ(), "TS_WORKLOAD_PARENT_DEATH_HELPER=1")
	helper.Stderr = os.Stderr
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	stopHelper := sync.OnceFunc(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	defer stopHelper()
	type lineResult struct {
		line string
		err  error
	}
	line := make(chan lineResult, 1)
	go func() {
		value, err := bufio.NewReader(stdout).ReadString('\n')
		line <- lineResult{value, err}
	}()
	var reply lineResult
	select {
	case reply = <-line:
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not start native workload")
	}
	if reply.err != nil {
		t.Fatal(reply.err)
	}
	var pid int
	var start string
	if n, err := fmt.Sscanf(reply.line, "%d %s", &pid, &start); err != nil || n != 2 || !processRunningWithStart(pid, start) {
		t.Fatalf("helper did not report a live workload: %q (%v)", reply.line, err)
	}
	defer func() {
		if processRunningWithStart(pid, start) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}()
	stopHelper()
	deadline := time.Now().Add(3 * time.Second)
	for processRunningWithStart(pid, start) {
		if time.Now().After(deadline) {
			t.Fatal("native workload survived owner process death")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestWorkloadParentDeathHelper(t *testing.T) {
	if os.Getenv("TS_WORKLOAD_PARENT_DEATH_HELPER") != "1" {
		return
	}
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	release, waited, err := startWorkloadOnLockedThread(cmd)
	if err != nil {
		t.Fatal(err)
	}
	release()
	fmt.Printf("%d %s\n", cmd.Process.Pid, currentStartTime(cmd.Process.Pid))
	if err := <-waited; err != nil {
		t.Fatal(err)
	}
}

func processRunningWithStart(pid int, start string) bool {
	if start == "" || currentStartTime(pid) != start {
		return false
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	closing := strings.LastIndexByte(string(data), ')')
	if closing < 0 {
		return false
	}
	fields := strings.Fields(string(data[closing+1:]))
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}
