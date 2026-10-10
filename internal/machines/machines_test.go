package machines

import (
	"errors"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workloadspec"
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

func TestAppValidate(t *testing.T) {
	tenant := testApp("acme-db")
	tenant.Class, tenant.Tenant = ClassTenant, "0000000000NY47MDQEXMPZDJR7"
	for name, app := range map[string]App{"platform": testApp("ts-auth"), "tenant": tenant} {
		if err := app.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*App){
		"name":               func(a *App) { a.Name = "TS.auth" },
		"zero version":       func(a *App) { a.Version = 0 },
		"id":                 func(a *App) { a.ID = "" },
		"unknown class":      func(a *App) { a.Class = "shared" },
		"platform tenant":    func(a *App) { a.Tenant = "acme" },
		"tenant without one": func(a *App) { a.Class = ClassTenant },
		"oci region":         func(a *App) { a.Regions = map[string]int{"sa-saopaulo-1": 1} },
		"unknown region":     func(a *App) { a.Regions = map[string]int{"xxx": 1} },
		"negative count":     func(a *App) { a.Regions["gru"] = -1 },
		"count over max":     func(a *App) { a.Regions["gru"] = MaxMachines + 1 },
		"node pool":          func(a *App) { a.NodePool = "1pool" },
		"config":             func(a *App) { a.Config.Digest = "sha256:abc" },
	} {
		app := testApp("ts-auth")
		mutate(&app)
		if err := app.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestMachineConfigValidate(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MachineConfig){
		"role":               func(c *MachineConfig) { c.Role = "" },
		"digest":             func(c *MachineConfig) { c.Digest = strings.Repeat("A", 64) },
		"no memory":          func(c *MachineConfig) { c.Resources.MemoryBytes = 0 },
		"argument size":      func(c *MachineConfig) { c.Args = []string{strings.Repeat("x", maxArgBytes+1)} },
		"too many arguments": func(c *MachineConfig) { c.Args = make([]string, maxListed+1) },
		"env key":            func(c *MachineConfig) { c.Env = map[string]string{"BAD-KEY": "x"} },
		"service port":       func(c *MachineConfig) { c.Services[0].Port = 70000 },
		"service name twice": func(c *MachineConfig) { c.Services[1].Name = "http" },
		"service port twice": func(c *MachineConfig) { c.Services[1].Port = 8080 },
		"check name twice":   func(c *MachineConfig) { c.Checks[1].Name = "ready" },
		"check type":         func(c *MachineConfig) { c.Checks[0].Type = "grpc" },
		"http without path":  func(c *MachineConfig) { c.Checks[0].Path = "" },
		"tcp with path":      func(c *MachineConfig) { c.Checks[1].Path = "/" },
		"exec without argv":  func(c *MachineConfig) { c.Checks[2].Command = nil },
		"exec with port":     func(c *MachineConfig) { c.Checks[2].Port = 80 },
		"check interval":     func(c *MachineConfig) { c.Checks[0].IntervalSeconds = -1 },
		"restart policy":     func(c *MachineConfig) { c.Restart.Policy = "sometimes" },
		"retries on always":  func(c *MachineConfig) { c.Restart.Policy = RestartAlways },
		"retries over max":   func(c *MachineConfig) { c.Restart.MaxRetries = 101 },
		"on-failure, no max": func(c *MachineConfig) { c.Restart.MaxRetries = 0 },
	} {
		config := testConfig()
		mutate(&config)
		if err := config.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestMachineValidate(t *testing.T) {
	placed := testMachine(testApp("ts-auth"))
	placed.Host, placed.FailureDomain = "gru-1-ctl-1", "fault-domain-1"
	if err := placed.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Machine){
		"id":                     func(m *Machine) { m.ID = "machine-1" },
		"app id":                 func(m *Machine) { m.AppID = "" },
		"region":                 func(m *Machine) { m.Region = "" },
		"unknown region":         func(m *Machine) { m.Region = "xxx" },
		"zero version":           func(m *Machine) { m.Version = 0 },
		"domain without host":    func(m *Machine) { m.Host = "" },
		"upper-case domain":      func(m *Machine) { m.FailureDomain = "FAULT-DOMAIN-1" },
		"desired":                func(m *Machine) { m.Desired = "running" },
		"config":                 func(m *Machine) { m.Config.Resources.CPU = 0 },
		"host with dot (in key)": func(m *Machine) { m.Host = "gru.1" },
	} {
		machine := placed
		mutate(&machine)
		if err := machine.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestStatusValidate(t *testing.T) {
	status := Status{ID: NewMachineID(), App: "ts-auth", State: StateStarted, UpdatedAt: time.Now()}
	if err := status.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Status){
		"id":             func(s *Status) { s.ID = "x" },
		"app":            func(s *Status) { s.App = "TS" },
		"state":          func(s *Status) { s.State = "running" },
		"no update time": func(s *Status) { s.UpdatedAt = time.Time{} },
	} {
		candidate := status
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
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

func TestAppWorkloadSpec(t *testing.T) {
	stateful := testApp("store")
	stateful.Config.Role = "store"
	stateful.Config.Artifact, stateful.Config.Command = workloadspec.ArtifactTarball, []string{"bin/store"}
	stateful.Config.Lifecycle = workloadspec.Lifecycle{PreStop: []string{"bin/store", "drain"}, DrainSeconds: 45}
	stateful.Stateful = &workloadspec.Stateful{Quorum: 2}
	stateful.Regions = map[string]int{"gru": 3, "fra": 0}
	tenant := testApp("acme-web")
	tenant.Class, tenant.Tenant = ClassTenant, "0000000000NY47MDQEXMPZDJR7"
	tenant.Config.Artifact, tenant.Config.Image = workloadspec.ArtifactImage, "ghcr.io/acme/web"
	tenant.Config.Command = []string{"web"}
	tenant.Config.Lifecycle.PostStart = []string{"/bin/true"}
	single := testApp("cache")
	single.Stateful, single.Regions = &workloadspec.Stateful{}, map[string]int{"gru": 1}
	for name, app := range map[string]App{"stateful": stateful, "tenant image": tenant, "single member": single} {
		if err := app.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	// The platform app named after its role holds the role's secrets.
	secretHolder := testApp("ts-auth")
	for name, mutate := range map[string]func(*App){
		"spec":         func(a *App) { a.DependsOn = []string{a.Name} },
		"machine spec": func(a *App) { a.Config.Files = []workloadspec.File{{Path: "/proc/self"}} },
		"quorum":       func(a *App) { a.Stateful = &workloadspec.Stateful{Quorum: 3} },
		"wide update":  func(a *App) { a.Stateful, a.Update.MaxUnavailable = &workloadspec.Stateful{Quorum: 2}, 2 },
		"post-start":   func(a *App) { a.Config.Lifecycle.PostStart = []string{"/bin/true"} },
		"pre-stop":     func(a *App) { a.Config.Lifecycle.PreStop = []string{"/bin/true"} },
		"exec check":   func(a *App) { a.Config.Checks = testConfig().Checks },
		"image command": func(a *App) {
			a.Config.Artifact, a.Config.Image, a.Config.Command = workloadspec.ArtifactImage, "ghcr.io/acme/auth", []string{"sh"}
		},
	} {
		app := secretHolder
		app.Config.Lifecycle = workloadspec.Lifecycle{}
		mutate(&app)
		if err := app.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	// Programs inside the admitted tarball may run beside the secrets.
	inside := secretHolder
	inside.Config.Artifact, inside.Config.Command = workloadspec.ArtifactTarball, []string{"bin/ts-auth", "serve"}
	inside.Config.Lifecycle.PreStop = []string{"bin/ts-auth", "drain"}
	inside.Config.Checks = append(inside.Config.Checks, Check{Name: "self", Type: CheckExec, Command: []string{"bin/ts-auth", "check"}})
	if err := inside.Validate(); err != nil {
		t.Fatal(err)
	}
	// Another platform app of the role gets no secrets and may run hooks.
	sidecar := testApp("ts-auth-canary")
	sidecar.Config.Lifecycle.PreStop = []string{"/bin/true"}
	sidecar.Config.Checks = testConfig().Checks
	if err := sidecar.Validate(); err != nil {
		t.Fatal(err)
	}
}
