//go:build linux

package host

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

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
	runner := NewProcessRunner(root).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			t.Skipf("requires writable cgroup v2: %v", err)
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
	marker := filepath.Join(t.TempDir(), "started")
	script := filepath.Join(t.TempDir(), "workload")
	content := "#!/bin/sh\nprintf started > '" + marker + "'\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(script, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
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
	runner := NewProcessRunner(root).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			t.Skipf("requires writable cgroup v2: %v", err)
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
	runner := NewProcessRunner(root).(*processRunner)
	if err := runner.Recover(t.Context()); err != nil {
		if runner.lock != nil {
			_ = syscall.Flock(int(runner.lock.Fd()), syscall.LOCK_UN)
			_ = runner.lock.Close()
		}
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS) {
			t.Skipf("requires writable cgroup v2: %v", err)
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
	marker := filepath.Join(t.TempDir(), "marker")
	for version := 1; version <= 3; version++ {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		script := filepath.Join(t.TempDir(), "workload")
		body := fmt.Sprintf("#!/bin/sh\nset -eu\nprintf '%%d\\n' %d > '%s'\nwhile :; do sleep 1; done\n", version, marker)
		if err := os.WriteFile(script, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
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
