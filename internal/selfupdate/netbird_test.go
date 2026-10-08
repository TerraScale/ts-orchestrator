package selfupdate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNetBirdWorkerInstallAndCurrentRelease(t *testing.T) {
	deploy := filepath.Join("..", "..", "deploy", "systemd")
	for relative, contents := range map[string]string{
		NetBirdAgentUnit: NetBirdAgentService,
		"selfupdate/terrascale-orchestrator-host.service.d/65-netbird-agent.conf": NetBirdAgentHostDropin,
		"selfupdate/terrascale-netbird-enroll.service.d/zz-selfupdate.conf":       NetBirdEnrollDropin,
	} {
		data, err := os.ReadFile(filepath.Join(deploy, relative))
		if err != nil || string(data) != contents {
			t.Fatalf("%s differs from installed service: %v", relative, err)
		}
	}
	if !strings.Contains(NetBirdAgentService, "PartOf=terrascale-orchestrator-host.service") ||
		!strings.Contains(NetBirdAgentService, "current/terrascale-orchestrator") ||
		!strings.Contains(NetBirdAgentService, "ExecCondition=/bin/sh -c '") ||
		!strings.Contains(NetBirdAgentService, "exec \"$$b\" netbird agent run --help'") ||
		!strings.Contains(NetBirdAgentService, "exec \"$$b\" netbird agent run --config") {
		t.Fatal("worker does not follow host rollout or current release")
	}
	if !strings.Contains(NetBirdAgentService, "StateDirectory=terrascale-netbird-agent terrascale-orchestrator/netbird-managed\nStateDirectoryMode=0700") ||
		!strings.Contains(NetBirdAgentHostDropin, "InaccessiblePaths=-/var/lib/terrascale-netbird-agent -/var/lib/terrascale-orchestrator/netbird-managed") {
		t.Fatal("host relay can access private worker authority or rollback state")
	}
	if !strings.Contains(NetBirdAgentHostDropin, "After=terrascale-netbird-agent.service") ||
		!strings.Contains(NetBirdAgentService, "After=network-online.target terrascale-orchestrator-host-setup.service\n") {
		t.Fatal("worker private directories must exist before the host namespace starts")
	}
	systemd := t.TempDir()
	if installed, err := InstallNetBirdAgent(systemd); err != nil || installed {
		t.Fatalf("installed on unmanaged host: %v, %v", installed, err)
	}
	if err := os.WriteFile(filepath.Join(systemd, HostSetupUnit), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, want := range []bool{true, false} {
		if installed, err := InstallNetBirdAgent(systemd); err != nil || installed != want {
			t.Fatalf("InstallNetBirdAgent = %v, %v, want %v", installed, err, want)
		}
	}
	if data, err := os.ReadFile(filepath.Join(systemd, NetBirdAgentUnit)); err != nil || string(data) != NetBirdAgentService {
		t.Fatalf("worker content: %v", err)
	}
}
