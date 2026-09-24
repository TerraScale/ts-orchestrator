//go:build linux

package host

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
