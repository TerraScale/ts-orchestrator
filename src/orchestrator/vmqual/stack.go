package vmqual

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

// Guest declares one launch host. Control is co-hosted on the first member of
// each Region and is intentionally part of the topology, not a seventh VM.
type Guest struct {
	ID        string
	Region    vmnet.RegionCode
	VCPU      int64
	MemoryMiB int64
	Control   bool
}

func LaunchGuests(memoryMiB int64) []Guest {
	if memoryMiB == 0 {
		memoryMiB = DefaultMemoryMiB
	}
	guests := make([]Guest, 0, 6)
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		for i := 1; i <= 2; i++ {
			guests = append(guests, Guest{ID: fmt.Sprintf("%s-member-%d", stringsLower(string(region)), i), Region: region, VCPU: 1, MemoryMiB: memoryMiB, Control: i == 1})
		}
	}
	return guests
}

// VM is the narrow lifecycle contract needed by the coordinator. Production
// orchestrator packages are not reachable through this test-only interface.
type VM interface {
	StartReady(context.Context) error
	Stop(context.Context) error
	Delete(context.Context) error
	Inspect(context.Context) (VMObservation, error)
}
type VMObservation struct {
	ID        string
	Region    vmnet.RegionCode
	Running   bool
	Ready     bool
	MemoryMiB int64
	RSSBytes  uint64
	IdleCPU   float64
}
type VMFactory interface {
	Create(context.Context, Guest) (VM, error)
}
type NetworkController interface {
	Apply(context.Context) error
	Cleanup(context.Context) error
}

type StackConfig struct {
	Guests      []Guest
	VMFactory   VMFactory
	Network     NetworkController
	JournalPath string
	StateRoot   string
	MaxRSSBytes int64
	MaxIdleCPU  float64
}

type Stack struct {
	config  StackConfig
	mu      sync.Mutex
	guests  []Guest
	vms     map[string]VM
	started bool
}

func NewStack(config StackConfig) (*Stack, error) {
	if config.VMFactory == nil {
		return nil, errors.New("vmqual: VM factory is required")
	}
	if config.Network == nil {
		return nil, errors.New("vmqual: network controller is required")
	}
	if len(config.Guests) == 0 {
		config.Guests = LaunchGuests(DefaultMemoryMiB)
	}
	if config.MaxRSSBytes == 0 {
		config.MaxRSSBytes = MaxIdleRSSBytes
	}
	if config.MaxIdleCPU == 0 {
		config.MaxIdleCPU = MaxIdleCPU
	}
	if len(config.Guests) != 6 {
		return nil, fmt.Errorf("vmqual: stack requires six guests, got %d", len(config.Guests))
	}
	seen := map[string]bool{}
	regions := map[vmnet.RegionCode]int{}
	controls := map[vmnet.RegionCode]int{}
	for _, guest := range config.Guests {
		if guest.ID == "" || seen[guest.ID] {
			return nil, fmt.Errorf("vmqual: duplicate or empty guest %q", guest.ID)
		}
		seen[guest.ID] = true
		if guest.VCPU != 1 || guest.MemoryMiB < 256 || guest.MemoryMiB > MaxGuestMemoryMiB {
			return nil, fmt.Errorf("vmqual: guest %s must use one vCPU and 256-512 MiB", guest.ID)
		}
		if guest.Control {
			controls[guest.Region]++
		}
		regions[guest.Region]++
	}
	for _, region := range []vmnet.RegionCode{vmnet.GRU, vmnet.SFO, vmnet.FRA} {
		if regions[region] != 2 {
			return nil, fmt.Errorf("vmqual: Region %s must have exactly two members", region)
		}
		if controls[region] != 1 {
			return nil, fmt.Errorf("vmqual: Region %s must have one co-hosted control replica", region)
		}
	}
	return &Stack{config: config, guests: append([]Guest(nil), config.Guests...), vms: map[string]VM{}}, nil
}

func (s *Stack) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("vmqual: nil stack")
	}
	if ctx == nil {
		return errors.New("vmqual: nil context")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return s.EnforceBudget(ctx)
	}
	s.mu.Unlock()
	if s.config.JournalPath != "" {
		networkJournal := vmnet.Journal{}
		if journaled, ok := s.config.Network.(interface{ Journal() vmnet.Journal }); ok {
			networkJournal = journaled.Journal()
		}
		if err := s.WriteJournal(s.config.JournalPath, networkJournal); err != nil {
			return fmt.Errorf("vmqual: write cleanup journal: %w", err)
		}
	}
	if err := s.config.Network.Apply(ctx); err != nil {
		return fmt.Errorf("vmqual: apply network: %w", err)
	}
	created := make([]string, 0, len(s.guests))
	cleanup := func() {
		_ = s.cleanupVMs(context.Background(), created)
		_ = s.config.Network.Cleanup(context.Background())
	}
	for _, guest := range s.guests {
		if err := ctx.Err(); err != nil {
			cleanup()
			return err
		}
		vm, err := s.config.VMFactory.Create(ctx, guest)
		if err != nil {
			cleanup()
			return fmt.Errorf("create %s: %w", guest.ID, err)
		}
		if vm == nil {
			cleanup()
			return fmt.Errorf("create %s: VM factory returned nil", guest.ID)
		}
		s.mu.Lock()
		s.vms[guest.ID] = vm
		s.mu.Unlock()
		created = append(created, guest.ID)
		if err := vm.StartReady(ctx); err != nil {
			cleanup()
			return fmt.Errorf("start %s: %w", guest.ID, err)
		}
	}
	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	if err := s.EnforceBudget(ctx); err != nil {
		cleanup()
		return err
	}
	return nil
}

func (s *Stack) EnforceBudget(ctx context.Context) error {
	s.mu.Lock()
	guests := append([]Guest(nil), s.guests...)
	s.mu.Unlock()
	var rss uint64
	var cpu float64
	var configuredMiB int64
	for _, guest := range guests {
		s.mu.Lock()
		vm := s.vms[guest.ID]
		s.mu.Unlock()
		if vm == nil {
			return fmt.Errorf("vmqual: %s was not created", guest.ID)
		}
		observation, err := vm.Inspect(ctx)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", guest.ID, err)
		}
		if !observation.Running || !observation.Ready {
			return fmt.Errorf("vmqual: %s is not ready", guest.ID)
		}
		if observation.ID != "" && observation.ID != guest.ID {
			return fmt.Errorf("vmqual: %s readiness identity mismatch: %s", guest.ID, observation.ID)
		}
		if observation.Region != "" && observation.Region != guest.Region {
			return fmt.Errorf("vmqual: %s readiness Region mismatch: %s", guest.ID, observation.Region)
		}
		if observation.MemoryMiB != 0 && observation.MemoryMiB != guest.MemoryMiB {
			return fmt.Errorf("vmqual: %s readiness memory mismatch: %d MiB", guest.ID, observation.MemoryMiB)
		}
		rss += observation.RSSBytes
		cpu += observation.IdleCPU
		configuredMiB += guest.MemoryMiB
	}
	if configuredMiB*1024*1024 > s.config.MaxRSSBytes {
		return fmt.Errorf("vmqual: configured memory budget exceeded: %d MiB", configuredMiB)
	}
	if rss > uint64(s.config.MaxRSSBytes) {
		return fmt.Errorf("vmqual: idle RSS budget exceeded: %d > %d", rss, s.config.MaxRSSBytes)
	}
	if cpu > s.config.MaxIdleCPU {
		return fmt.Errorf("vmqual: idle CPU budget exceeded: %.3f > %.3f", cpu, s.config.MaxIdleCPU)
	}
	return nil
}

func (s *Stack) cleanupVMs(ctx context.Context, ids []string) error {
	var first error
	for i := len(ids) - 1; i >= 0; i-- {
		s.mu.Lock()
		vm := s.vms[ids[i]]
		delete(s.vms, ids[i])
		s.mu.Unlock()
		if vm == nil {
			continue
		}
		if err := vm.Stop(ctx); err != nil && first == nil {
			first = err
		}
		if err := vm.Delete(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (s *Stack) Cleanup(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	ids := make([]string, 0, len(s.vms))
	for id := range s.vms {
		ids = append(ids, id)
	}
	s.started = false
	s.mu.Unlock()
	sort.Strings(ids)
	cleanCtx := context.WithoutCancel(ctx)
	vmErr := s.cleanupVMs(cleanCtx, ids)
	netErr := s.config.Network.Cleanup(cleanCtx)
	return errors.Join(vmErr, netErr)
}

func (s *Stack) Guests() []Guest {
	if s == nil {
		return nil
	}
	return append([]Guest(nil), s.guests...)
}

// Journal is written before stack mutation. VM paths are exact ownership
// records; cleanup never searches for arbitrary Firecracker processes.
type Journal struct {
	Version   int           `json:"version"`
	Marker    string        `json:"marker"`
	CreatedAt time.Time     `json:"createdAt"`
	StateRoot string        `json:"stateRoot"`
	VMs       []JournalVM   `json:"vms"`
	Network   vmnet.Journal `json:"network"`
}
type JournalVM struct {
	ID       string `json:"id"`
	Region   string `json:"region"`
	StateDir string `json:"stateDir"`
}

func (s *Stack) WriteJournal(path string, network vmnet.Journal) error {
	if s == nil || path == "" || !filepath.IsAbs(path) {
		return errors.New("vmqual: journal path must be absolute")
	}
	j := Journal{Version: 1, Marker: OwnershipMarker, CreatedAt: time.Now().UTC(), StateRoot: s.config.StateRoot, Network: network}
	for _, guest := range s.guests {
		j.VMs = append(j.VMs, JournalVM{ID: guest.ID, Region: string(guest.Region), StateDir: filepath.Join(s.config.StateRoot, guest.ID)})
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
func stringsLower(v string) string {
	b := []byte(v)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
