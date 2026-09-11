//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"fmt"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type localProcessProbeTransport struct {
	orchestratorActive  bool
	terrabaseActive     bool
	terrabaseConfigured bool
	systemdDegraded     bool
}

func (t *localProcessProbeTransport) credential(id string) (*guestCredential, error) {
	return &guestCredential{id: id, service: true}, nil
}

func (t *localProcessProbeTransport) request(_ context.Context, _, address string, request vmguest.Request) (vmguest.Response, error) {
	good := func(output string) vmguest.CommandResult { return vmguest.CommandResult{Stdout: []byte(output)} }
	response := vmguest.Response{SchemaVersion: vmguest.SchemaVersion}
	switch request.Operation {
	case vmguest.OperationProbe:
		state := "running"
		if t.systemdDegraded {
			state = "degraded"
		}
		response.Probe = &vmguest.ProbeResult{
			Systemd: good(state), PID1: good("/usr/lib/systemd/systemd"), CgroupV2: good("cgroup2fs"),
			Time: good("yes"), SeedDigest: good("seed-digest " + vmguest.DefaultSeedPath),
			DataMount: good("/dev/vdb ext4 /var/lib/terrascale"), Network: good(address + " routable"),
		}
	case vmguest.OperationExecute:
		if request.Path == "/usr/bin/test" && len(request.Args) == 2 && request.Args[0] == "-s" {
			result := good("")
			if !t.terrabaseConfigured {
				result.ExitCode = 1
			}
			response.Command = &result
			return response, nil
		}
		if request.Path != "/usr/bin/systemctl" || len(request.Args) != 2 || request.Args[0] != "is-active" {
			return response, fmt.Errorf("unexpected readiness command")
		}
		result := good("active")
		if request.Args[1] == "terrascale-orchestrator.service" && !t.orchestratorActive {
			result.ExitCode = 3
			result.Stdout = []byte("inactive")
		}
		if request.Args[1] == "terrascale-terrabase.service" && !t.terrabaseActive {
			result.ExitCode = 3
			result.Stdout = []byte("activating")
		}
		response.Command = &result
	default:
		return response, fmt.Errorf("unexpected readiness request")
	}
	return response, nil
}

func TestReadinessRequiresLocalOrchestratorOnEveryMember(t *testing.T) {
	for _, guest := range vmqual.LaunchGuests(vmqual.DefaultMemoryMiB) {
		t.Run(guest.ID, func(t *testing.T) {
			transport := &localProcessProbeTransport{terrabaseConfigured: true, terrabaseActive: true}
			probe := &sshGuestProbe{transport: transport, configs: make(map[string]sandboxvm.Config), seedDigests: make(map[string]string)}
			probe.Register(sandboxvm.Config{ID: guest.ID, GuestAddress: "198.18.0.10"}, "seed-digest")
			missing, err := probe.Probe(context.Background(), guest.ID)
			if err != nil || !missing.Systemd || !missing.DataDiskMounted || !missing.Network || !missing.TSNodeHealthy || missing.ServiceHealthy {
				t.Fatalf("missing local orchestrator admitted, global replica=%v: %+v, %v", guest.Control, missing, err)
			}
			transport.orchestratorActive = true
			repaired, err := probe.Probe(context.Background(), guest.ID)
			if err != nil || !repaired.ServiceHealthy {
				t.Fatalf("repaired local orchestrator was not admitted: %+v, %v", repaired, err)
			}
		})
	}
}

// The engine's launch configuration arrives from the control plane after
// initial admission, so a service guest whose engine configuration has not
// been staged yet cannot be ready; readiness requires the staged file and the
// active terrabase unit.
func TestReadinessRequiresStagedEngineConfigurationAndActiveUnit(t *testing.T) {
	transport := &localProcessProbeTransport{orchestratorActive: true, terrabaseConfigured: false, terrabaseActive: false, systemdDegraded: true}
	probe := &sshGuestProbe{transport: transport, configs: make(map[string]sandboxvm.Config), seedDigests: make(map[string]string)}
	probe.Register(sandboxvm.Config{ID: "gru-member-1", GuestAddress: "198.18.0.10"}, "seed-digest")
	pending, err := probe.Probe(context.Background(), "gru-member-1")
	if err != nil {
		t.Fatal(err)
	}
	if pending.ServiceHealthy || !pending.Systemd {
		t.Fatalf("unconfigured engine was admitted before control-plane delivery: %+v", pending)
	}
	transport.terrabaseConfigured = true
	staged, err := probe.Probe(context.Background(), "gru-member-1")
	if err != nil {
		t.Fatal(err)
	}
	if staged.ServiceHealthy {
		t.Fatal("staged engine configuration did not require the terrabase unit active")
	}
	transport.terrabaseActive = true
	running, err := probe.Probe(context.Background(), "gru-member-1")
	if err != nil {
		t.Fatal(err)
	}
	if !running.ServiceHealthy {
		t.Fatal("configured and running engine was not admitted")
	}
}
