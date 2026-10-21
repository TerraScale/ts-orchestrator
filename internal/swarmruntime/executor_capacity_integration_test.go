package swarmruntime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exec after affinity is restricted so Go observes one CPU at process startup.
func TestContainerdSingleCPUAllocatable(t *testing.T) {
	if *integrationSocket == "" {
		t.Skip("runs in the containerd workflow, which passes -containerd-socket")
	}
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		t.Fatal(err)
	}
	if allowed.Count() == 0 {
		t.Fatal("runtime fixture has no allowed CPU")
	}
	cpu := 0
	for !allowed.IsSet(cpu) {
		cpu++
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	taskset, err := exec.LookPath("taskset")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, taskset, "-c", strconv.Itoa(cpu), executable,
		"-test.v", "-test.run=^TestContainerdLifecycleAgentRecovery$", "-test.timeout=2m", "-containerd-socket", *integrationSocket)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("single-CPU runtime lifecycle: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("runtime reports 1 CPU(s), 750m allocatable")) {
		t.Fatalf("fixture did not observe single-CPU capacity:\n%s", output)
	}
	t.Logf("%s", output)
}
