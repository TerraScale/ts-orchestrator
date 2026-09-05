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
	orchestratorActive bool
}

func (t *localProcessProbeTransport) credential(id string) (*guestCredential, error) {
	return &guestCredential{id: id, service: true}, nil
}

func (t *localProcessProbeTransport) request(_ context.Context, _, address string, request vmguest.Request) (vmguest.Response, error) {
	good := func(output string) vmguest.CommandResult { return vmguest.CommandResult{Stdout: []byte(output)} }
	response := vmguest.Response{SchemaVersion: vmguest.SchemaVersion}
	switch request.Operation {
	case vmguest.OperationProbe:
		response.Probe = &vmguest.ProbeResult{
			Systemd: good("running"), PID1: good("/usr/lib/systemd/systemd"), CgroupV2: good("cgroup2fs"),
			Time: good("yes"), SeedDigest: good("seed-digest " + vmguest.DefaultSeedPath),
			DataMount: good("/dev/vdb ext4 /var/lib/terrascale"), Network: good(address + " routable"),
		}
	case vmguest.OperationExecute:
		if request.Path != "/usr/bin/systemctl" || len(request.Args) != 2 || request.Args[0] != "is-active" {
			return response, fmt.Errorf("unexpected readiness command")
		}
		result := good("active")
		if request.Args[1] == "terrascale-orchestrator.service" && !t.orchestratorActive {
			result.ExitCode = 3
			result.Stdout = []byte("inactive")
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
			transport := &localProcessProbeTransport{}
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
