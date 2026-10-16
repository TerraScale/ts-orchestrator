//go:build linux

package execution

import (
	"os"
	"os/exec"
	"testing"
)

func TestRuntimeObserverHostNetworkNamespaceIntegration(t *testing.T) {
	if os.Getenv("TS_RUNTIME_NETWORK_FIXTURE") == "private" {
		parent := os.Getppid()
		if err := verifyHostNetworkNamespace(parent); err == nil {
			t.Fatal("a process in another network namespace accepted as host networking")
		}
		return
	}
	if err := verifyHostNetworkNamespace(os.Getpid()); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "sudo", "-n", "env", "TS_RUNTIME_NETWORK_FIXTURE=private", "nice", "-n", "19", "unshare", "--net", executable, "-test.run=^TestRuntimeObserverHostNetworkNamespaceIntegration$", "-test.v")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("kernel network namespace refusal: %v\n%s", err, output)
	}
}
