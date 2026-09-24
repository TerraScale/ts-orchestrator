//go:build linux

package host

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

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
