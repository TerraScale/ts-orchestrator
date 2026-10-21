package deploy_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// The host-setup timer fires on every managed host together; it may start
// the host runtime but must never restart it, because a restart stops every
// supervised TerraBase member on both seats of a pair.
func TestHostSetupNeverRestartsTheHostRuntime(t *testing.T) {
	service := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-host-setup.service")))
	directives := unitDirectives(service, "Service")
	equal(t, directives["ExecStartPost"], "-/usr/bin/systemctl --no-block start terrascale-orchestrator-managed-runtime.service")
	for line := range strings.SplitSeq(service, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") && strings.Contains(line, "restart") {
			t.Fatalf("host setup restarts a unit: %q", line)
		}
	}
	timer := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-host-setup.timer"))), "Timer")
	equal(t, timer["RandomizedDelaySec"], "2h")
}

func TestOrchestratorUnitsReportReadinessAndEscalateCrashLoops(t *testing.T) {
	for unit, want := range map[string]map[string]string{
		"terrascale-orchestrator-controller.service": {"Type": "notify", "NotifyAccess": "main", "WatchdogSec": "60s",
			"TimeoutStartSec": "20min", "RestartSteps": "6", "RestartMaxDelaySec": "5min"},
		"terrascale-orchestrator-host.service": {"Type": "notify", "NotifyAccess": "main",
			"TimeoutStartSec": "3min", "RestartSteps": "6", "RestartMaxDelaySec": "5min"},
	} {
		source := string(read(t, filepath.Join(deployRoot(t), "deploy/systemd", unit)))
		service := unitDirectives(source, "Service")
		for key, value := range want {
			if service[key] != value {
				t.Fatalf("%s %s=%q, want %q", unit, key, service[key], value)
			}
		}
		section := unitDirectives(source, "Unit")
		if section["StartLimitIntervalSec"] == "" || section["StartLimitIntervalSec"] == "0" || section["StartLimitBurst"] == "" {
			t.Fatalf("%s never escalates a crash loop: %v", unit, section)
		}
	}
	host := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-host.service"))), "Service")
	if _, watchdog := host["WatchdogSec"]; watchdog {
		t.Fatal("a host watchdog would restart the runtime and stop its TerraBase members")
	}
}

func TestControllerCanCollectNodeResources(t *testing.T) {
	service := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/systemd/terrascale-orchestrator-controller.service"))), "Service")
	if service["ProcSubset"] == "pid" {
		t.Fatal("ProcSubset=pid hides /proc/stat and /proc/meminfo, dropping CPU, memory and filesystem telemetry")
	}
	equal(t, service["ProtectProc"], "invisible")
}

// ts-orch runs as root on a public host; keep its systemd sandbox in place.
func TestSingleHostUnitIsSandboxed(t *testing.T) {
	service := unitDirectives(string(read(t, filepath.Join(deployRoot(t), "deploy/m1/ts-orch.service"))), "Service")
	for key, value := range map[string]string{"UMask": "0077", "NoNewPrivileges": "yes", "ProtectSystem": "full",
		"ReadWritePaths": "/usr/local/bin", "ProtectHome": "yes", "PrivateTmp": "yes", "RestrictSUIDSGID": "yes"} {
		equal(t, service[key], value)
	}
}
