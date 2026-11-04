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

func TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root supervisor in a delegated cgroup v2 service")
	}
	state := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(state, testWorkloadIdentity, "gru", "gru-1").(*processRunner)
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
	root := runner.cgroups
	if err := runner.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The runtime probe or an older host may leave this persistent root private.
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal(err)
	}
	runner = NewProcessRunner(state, testWorkloadIdentity, "gru", "gru-1").(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		t.Fatalf("Recover did not repair legacy cgroup traversal: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runner.Close(ctx); err != nil {
			t.Errorf("Close: %v", err)
		}
		if err := os.Remove(root); err != nil {
			t.Errorf("remove native runner cgroup: %v", err)
		}
	})
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	owner := info.Sys().(*syscall.Stat_t)
	if owner.Uid != 0 || owner.Gid != testWorkloadIdentity.GID || info.Mode().Perm() != 0710 {
		t.Fatalf("recovered runner cgroup owner/mode = %d:%d %04o", owner.Uid, owner.Gid, info.Mode().Perm())
	}
	unrelated := filepath.Join(root, "other-tenant")
	if err := os.Mkdir(unrelated, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(unrelated, 0, int(testWorkloadIdentity.GID-1)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unrelated, 0710); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(unrelated); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Errorf("remove unrelated cgroup: %v", err)
		}
	})
	install := nativeTestInstallDir(t)
	marker := nativeTestReadableMarker(t, "accounting")
	script := filepath.Join(install, "workload")
	content := fmt.Sprintf("#!/bin/sh\nset -eu\nIFS=: read -r _ _ membership < /proc/self/cgroup\nrole=/sys/fs/cgroup$membership\nIFS= read -r current < \"$role/memory.current\"\nIFS= read -r limit < \"$role/memory.max\"\n[ -n \"$current\" ]\n[ \"$limit\" = \"5368709120\" ]\n[ ! -w \"$role/memory.max\" ]\n[ ! -w \"$role/cgroup.procs\" ]\n[ ! -w \"$role/../cgroup.subtree_control\" ]\n[ ! -r %q ]\nprintf ok > %q\nwhile :; do sleep 1; done\n", filepath.Join(unrelated, "cgroup.procs"), marker)
	writeNativeTestExecutable(t, script, content)
	digest := strings.Repeat("a", 64)
	if err := runner.Apply(t.Context(), Workload{
		Role: "terrabase", Digest: digest, Fingerprint: digest, Executable: script,
		CgroupMemoryMaxBytes: 5 << 30,
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(marker)
		if err == nil && string(data) == "ok" {
			break
		}
		if time.Now().After(deadline) {
			observation, observeErr := runner.Observe(t.Context(), "terrabase")
			t.Fatalf("tenant could not read finite cgroup accounting or crossed cgroup boundary: marker=%q error=%v observation=%+v observe_error=%v", data, err, observation, observeErr)
		}
		time.Sleep(10 * time.Millisecond)
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

func TestNativeWorkloadReceivesOnlyExplicitEnvironment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	runner := NewProcessRunner(root, testWorkloadIdentity, "gru", "gru-1").(*processRunner)
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
			if strings.Contains(environment, "TS_SUPERVISOR_SECRET=") || !strings.Contains(environment, "TS_DESIRED=present") || !strings.Contains(environment, "PATH=/usr/bin:/bin") ||
				!strings.Contains(environment, "\nTS_NODE=gru-1\n") || !strings.Contains(environment, "\nTS_REGION=gru\n") || !strings.Contains(environment, "\nTS_SERVICE=terrabase\n") {
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
		runner := NewProcessRunner(state, testWorkloadIdentity, "gru", "gru-1").(*processRunner)
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
	diagnostic := filepath.Join(install, "0000000000XTGQJSECWR54430J")
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
