package machines

import (
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/placement"
)

var testDigest = strings.Repeat("a", 64)

func testConfig() MachineConfig {
	return MachineConfig{
		Role: "ts-auth", Digest: testDigest, Args: []string{"serve"}, Env: map[string]string{"LOG_LEVEL": "info"},
		Resources: placement.Resources{CPU: 1, MemoryBytes: 512 << 20, DiskBytes: 1 << 30},
		Services:  []Service{{Name: "http", Port: 8080}, {Name: "admin", Port: 9090}},
		Checks: []Check{
			{Name: "ready", Type: CheckHTTP, Port: 8080, Path: "/ready"},
			{Name: "port", Type: CheckTCP, Port: 9090},
			{Name: "self", Type: CheckExec, Command: []string{"/bin/true"}},
		},
		Restart: RestartPolicy{Policy: RestartOnFailure, MaxRetries: 5},
	}
}

func testApp(name string) App {
	config := testConfig()
	// The platform app named after its role runs no host program.
	config.Checks = config.Checks[:2]
	return App{Name: name, ID: NewMachineID(), Class: ClassPlatform, Version: 1, Config: config,
		Regions: map[string]int{"gru": 3}}
}

func testMachine(app App) Machine {
	return Machine{ID: NewMachineID(), App: app.Name, AppID: app.ID, Region: "gru", Version: 1, Config: testConfig(),
		Desired: DesiredStarted}
}







func TestNewMachineIDIsValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewMachineID()
		if !entityid.Valid(id) || seen[id] {
			t.Fatalf("machine ID %q is malformed or repeated", id)
		}
		seen[id] = true
	}
}


