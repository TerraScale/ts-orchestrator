// Package machines owns the shared orchestration model: apps, the machines
// that run them and their observed status, and their store in the regional
// KV buckets TS_APPS, TS_MACHINES and TS_MACHINE_STATUS. See docs/apps-machines.md.
package machines

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workloadspec"
)

var ErrInvalid = errors.New("invalid app or machine")

var (
	tokenRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	// poolRE is the node pool name rule.
	poolRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,40}$`)
	digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	envRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

const (
	// MaxMachines bounds one app's machines in one region.
	MaxMachines = 256
	maxListed   = 64
	maxArgBytes = 4096
)

// Class separates TerraScale's own services from tenant workloads.
type Class string

const (
	ClassPlatform Class = "platform"
	ClassTenant   Class = "tenant"
)

// App is one service run as machines.
type App struct {
	Name string `json:"name"`
	// ID is set by the store at creation and names this incarnation of the
	// app: a machine of an earlier app of the same name is an orphan.
	ID     string `json:"id"`
	Class  Class  `json:"class"`
	Tenant string `json:"tenant,omitempty"`
	// Version is set by the store: 1 at creation and one more on every
	// Config change.
	Version uint64        `json:"version"`
	Config  MachineConfig `json:"config"`
	// Regions pins the app to catalog regions and holds its machine count in
	// each.
	Regions map[string]int `json:"regions,omitempty"`
	// NodePool pins the app to the hosts of one node pool.
	NodePool string `json:"node_pool,omitempty"`
	// AppSpec is the generic workload policy: placement, update strategy,
	// stateful quorum and dependencies. Changing it is not a new version.
	workloadspec.AppSpec
	// Revision is the record's KV revision: zero for a new app.
	Revision uint64 `json:"-"`
}

// Validate checks the app in isolation.
func (a App) Validate() error {
	if !tokenRE.MatchString(a.Name) || !entityid.Valid(a.ID) || a.Version == 0 {
		return fmt.Errorf("%w: app name, ID or version", ErrInvalid)
	}
	switch {
	case a.Class == ClassPlatform && a.Tenant == "":
	case a.Class == ClassTenant && entityid.Valid(a.Tenant):
	default:
		return fmt.Errorf("%w: app %s class %q needs a tenant exactly when it is a tenant app", ErrInvalid, a.Name, a.Class)
	}
	if len(a.Regions) > maxListed {
		return fmt.Errorf("%w: app %s has too many regions", ErrInvalid, a.Name)
	}
	for region, count := range a.Regions {
		if !validRegion(region) || count < 0 || count > MaxMachines {
			return fmt.Errorf("%w: app %s region %q count %d", ErrInvalid, a.Name, region, count)
		}
	}
	if a.NodePool != "" && !poolRE.MatchString(a.NodePool) {
		return fmt.Errorf("%w: app %s node pool", ErrInvalid, a.Name)
	}
	if err := a.Config.Validate(); err != nil {
		return fmt.Errorf("app %s: %w", a.Name, err)
	}
	if err := a.AppSpec.Validate(a.Name); err != nil {
		return fmt.Errorf("%w: app %s: %w", ErrInvalid, a.Name, err)
	}
	if a.Stateful != nil {
		for region, count := range a.Regions {
			if count != 0 && count-a.Update.Unavailable() < a.Stateful.Quorum {
				return fmt.Errorf("%w: app %s region %s: %d machines less %d updating at once are below quorum %d",
					ErrInvalid, a.Name, region, count, a.Update.Unavailable(), a.Stateful.Quorum)
			}
		}
	}
	// The platform app named after its role gets the role's signed profile,
	// Vault secrets included. The app is not signed, so every program it
	// starts, by command, hook or exec check, must be inside its admitted
	// tarball: no host or image program, such as /bin/sh, runs beside those
	// secrets.
	if a.Class == ClassPlatform && a.Name == a.Config.Role {
		argvs := [][]string{a.Config.Command, a.Config.Lifecycle.PostStart, a.Config.Lifecycle.PreStop}
		for _, check := range a.Config.Checks {
			argvs = append(argvs, check.Command)
		}
		for _, argv := range argvs {
			if len(argv) != 0 && !a.Config.InArtifact(argv) {
				return fmt.Errorf("%w: app %s gets its role's secrets, so it starts only programs inside its tarball, not %q",
					ErrInvalid, a.Name, argv[0])
			}
		}
	}
	return nil
}

// MachineConfig is what a host runs for one machine.
type MachineConfig struct {
	// Role and Digest name the admitted artifact.
	Role      string              `json:"role"`
	Digest    string              `json:"digest"`
	Args      []string            `json:"args,omitempty"`
	Env       map[string]string   `json:"env,omitempty"`
	Resources placement.Resources `json:"resources"`
	Services  []Service           `json:"services,omitempty"`
	Checks    []Check             `json:"checks,omitempty"`
	Restart   RestartPolicy       `json:"restart,omitzero"`
	// MachineSpec is what a host runs besides the artifact: its kind,
	// image, command, files and lifecycle hooks.
	workloadspec.MachineSpec
}

// Service is a named port a machine listens on, published for discovery.
type Service struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// CheckType selects how a health check probes a machine.
type CheckType string

const (
	CheckHTTP CheckType = "http"
	CheckTCP  CheckType = "tcp"
	CheckExec CheckType = "exec"
)

// Check is one health check. Zero intervals and timeouts take the runtime's
// defaults; GraceSeconds ignores failures right after a start.
type Check struct {
	Name            string    `json:"name"`
	Type            CheckType `json:"type"`
	Port            int       `json:"port,omitzero"`
	Path            string    `json:"path,omitempty"`
	Command         []string  `json:"command,omitempty"`
	IntervalSeconds int       `json:"interval_seconds,omitzero"`
	TimeoutSeconds  int       `json:"timeout_seconds,omitzero"`
	GraceSeconds    int       `json:"grace_seconds,omitzero"`
}

// Restart is a systemd-style restart policy; empty means always.
type Restart string

const (
	RestartAlways    Restart = "always"
	RestartOnFailure Restart = "on-failure"
	RestartNo        Restart = "no"
)

// RestartPolicy bounds restarts; on-failure needs MaxRetries.
type RestartPolicy struct {
	Policy     Restart `json:"policy,omitempty"`
	MaxRetries int     `json:"max_retries,omitzero"`
}

// Validate checks the config in isolation.
func (c MachineConfig) Validate() error {
	if !tokenRE.MatchString(c.Role) || !digestRE.MatchString(c.Digest) {
		return fmt.Errorf("%w: config role or digest", ErrInvalid)
	}
	if c.Resources.CPU <= 0 || c.Resources.MemoryBytes <= 0 || c.Resources.DiskBytes <= 0 {
		return fmt.Errorf("%w: config resources must be positive", ErrInvalid)
	}
	if len(c.Args) > maxListed || len(c.Env) > maxListed {
		return fmt.Errorf("%w: too many arguments or environment variables", ErrInvalid)
	}
	for _, arg := range c.Args {
		if len(arg) > maxArgBytes {
			return fmt.Errorf("%w: argument too long", ErrInvalid)
		}
	}
	for key, value := range c.Env {
		if !envRE.MatchString(key) || len(value) > maxArgBytes {
			return fmt.Errorf("%w: environment variable %q", ErrInvalid, key)
		}
	}
	if len(c.Services) > maxListed || len(c.Checks) > maxListed {
		return fmt.Errorf("%w: too many services or checks", ErrInvalid)
	}
	var names []string
	var ports []int
	for _, service := range c.Services {
		if !tokenRE.MatchString(service.Name) || !validPort(service.Port) ||
			slices.Contains(names, service.Name) || slices.Contains(ports, service.Port) {
			return fmt.Errorf("%w: service %q", ErrInvalid, service.Name)
		}
		names, ports = append(names, service.Name), append(ports, service.Port)
	}
	names = nil
	for _, check := range c.Checks {
		if err := check.validate(); err != nil || slices.Contains(names, check.Name) {
			return fmt.Errorf("%w: check %q", ErrInvalid, check.Name)
		}
		names = append(names, check.Name)
	}
	switch c.Restart.Policy {
	case "", RestartAlways, RestartNo:
		if c.Restart.MaxRetries != 0 {
			return fmt.Errorf("%w: max retries need the on-failure policy", ErrInvalid)
		}
	case RestartOnFailure:
		if c.Restart.MaxRetries < 1 || c.Restart.MaxRetries > 100 {
			return fmt.Errorf("%w: max retries must be within 1..100", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: restart policy %q", ErrInvalid, c.Restart.Policy)
	}
	if err := c.MachineSpec.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

func (c Check) validate() error {
	if !tokenRE.MatchString(c.Name) ||
		c.IntervalSeconds < 0 || c.IntervalSeconds > 3600 || c.TimeoutSeconds < 0 || c.TimeoutSeconds > 300 ||
		c.GraceSeconds < 0 || c.GraceSeconds > 3600 {
		return ErrInvalid
	}
	switch c.Type {
	case CheckHTTP:
		if validPort(c.Port) && strings.HasPrefix(c.Path, "/") && len(c.Path) <= maxArgBytes && len(c.Command) == 0 {
			return nil
		}
	case CheckTCP:
		if validPort(c.Port) && c.Path == "" && len(c.Command) == 0 {
			return nil
		}
	case CheckExec:
		if c.Port == 0 && c.Path == "" && len(c.Command) > 0 && len(c.Command) <= maxListed &&
			!slices.ContainsFunc(c.Command, func(arg string) bool { return len(arg) > maxArgBytes }) {
			return nil
		}
	}
	return ErrInvalid
}

func validPort(port int) bool { return port > 0 && port <= 65535 }

// DesiredState is the state the orchestrator wants a machine in.
type DesiredState string

const (
	DesiredStarted   DesiredState = "started"
	DesiredStopped   DesiredState = "stopped"
	DesiredDestroyed DesiredState = "destroyed"
)

// State is a machine's observed state.
type State string

const (
	// StatePending is a machine not yet running on its host, or not yet
	// placed on one.
	StatePending  State = "pending"
	StateStarting State = "starting"
	StateStarted  State = "started"
	StateStopping State = "stopping"
	StateStopped  State = "stopped"
	StateFailed   State = "failed"
	// StateLost is a machine whose host is gone; it is replaced elsewhere.
	StateLost      State = "lost"
	StateDestroyed State = "destroyed"
)

var states = []State{StatePending, StateStarting, StateStarted, StateStopping, StateStopped, StateFailed,
	StateLost, StateDestroyed}

// Machine is one placed instance of an app: what the orchestrator wants.
// What it observes is the machine's Status.
type Machine struct {
	ID    string `json:"id"`
	App   string `json:"app"`
	AppID string `json:"app_id"`
	// Region is the store's own region.
	Region string `json:"region"`
	// Host is empty until the scheduler places the machine. FailureDomain is
	// the host's, in lower case as placement sees it.
	Host          string        `json:"host,omitempty"`
	FailureDomain string        `json:"failure_domain,omitempty"`
	Version       uint64        `json:"version"`
	Config        MachineConfig `json:"config"`
	Desired       DesiredState  `json:"desired"`
	// Revision is the record's KV revision: zero for a new machine.
	Revision uint64 `json:"-"`
}

// Validate checks the machine in isolation.
func (m Machine) Validate() error {
	if !entityid.Valid(m.ID) || !tokenRE.MatchString(m.App) || !entityid.Valid(m.AppID) ||
		!validRegion(m.Region) || m.Version == 0 {
		return fmt.Errorf("%w: machine identity or version", ErrInvalid)
	}
	if m.Host != "" && !tokenRE.MatchString(m.Host) || m.FailureDomain != "" && (m.Host == "" || !tokenRE.MatchString(m.FailureDomain)) {
		return fmt.Errorf("%w: machine %s host or failure domain", ErrInvalid, m.ID)
	}
	switch m.Desired {
	case DesiredStarted, DesiredStopped, DesiredDestroyed:
	default:
		return fmt.Errorf("%w: machine %s desired state %q", ErrInvalid, m.ID, m.Desired)
	}
	if err := m.Config.Validate(); err != nil {
		return fmt.Errorf("machine %s: %w", m.ID, err)
	}
	return nil
}

// Status is a machine's observed state, kept apart from the machine so
// that host reports and desired-state writes never contend.
type Status struct {
	ID        string    `json:"id"`
	App       string    `json:"app"`
	State     State     `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
	// Revision is the record's KV revision: zero for a new status.
	Revision uint64 `json:"-"`
}

// Validate checks the status in isolation.
func (s Status) Validate() error {
	if !entityid.Valid(s.ID) || !tokenRE.MatchString(s.App) || !slices.Contains(states, s.State) || s.UpdatedAt.IsZero() {
		return fmt.Errorf("%w: machine status", ErrInvalid)
	}
	return nil
}

// NewMachineID returns a random machine ID.
func NewMachineID() string { return newID() }

func newID() string { return entityid.New() }

func validRegion(region string) bool {
	_, ok := catalog.LookupName(region)
	return ok
}
